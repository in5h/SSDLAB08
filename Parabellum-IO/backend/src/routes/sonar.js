/**
 * sonar.js — Express router for SonarQube scan endpoints
 *
 * POST /api/sonar/scan/:projectId           — scan only
 * POST /api/sonar/scan-and-map/:projectId   — full pipeline (scan + GRC + report)
 * GET  /api/sonar/status/:projectKey        — CE task status
 * GET  /api/sonar/issues/:projectKey        — paginated issues
 * GET  /api/sonar/quality-gate/:projectKey  — quality gate result
 * GET  /api/sonar/reports                   — list saved reports
 * GET  /api/sonar/reports/:filename         — download a saved report
 */

import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
    createSonarProject,
    runSonarScan,
    getScanStatus,
    waitForSonarQubeProcessing,
    getIssues,
    getQualityGate,
    formatIssuesAsText,
} from "../services/sonarService.js";
import { generateScanReport } from "../services/scanReportService.js";
import { mapFindingsToGRC } from "../services/grcMappingService.js";
import { generateRiskReport } from "../services/riskReportService.js";
import { getProjectById, getOwnedProjectByKey, db } from "./projects.js";
import { recordSingleToolRun } from "../services/pipelineService.js";
import { adviseIssues } from "../services/findingService.js";
import { buildFixPlan } from "../services/remediationService.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, "..", "uploads", "reports");
fs.mkdirSync(REPORTS_DIR, { recursive: true });

const router = express.Router();

/** Derive a safe SonarQube project key from the owner + project name (owner prefix keeps users' projects apart). */
function toProjectKey(name, userId) {
    return `u${userId}_${name}`
        .replace(/[^a-zA-Z0-9_\-:.]/g, "_")
        .replace(/_+/g, "_")
        .substring(0, 200)
        .toLowerCase();
}

// ──────────────────────────────────────────────────────────────────
// POST /api/sonar/scan/:projectId
// Deep scan only — returns full report JSON + saves files to disk
// ──────────────────────────────────────────────────────────────────
router.post("/scan/:projectId", async (req, res) => {
    try {
        const project = getProjectById(req.params.projectId, req.user.userId);
        if (!project) return res.status(404).json({ error: "Project not found." });
        if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

        const projectKey = toProjectKey(project.name, req.user.userId);
        const projectName = project.name;

        // 1. Create project in SonarQube (idempotent)
        await createSonarProject(projectKey, projectName);

        // 2. Deep scan (auto-compile Java → scanner)
        const scanStarted = new Date();
        const { compileInfo } = await runSonarScan(projectKey, projectName, project.local_path);

        // 2.5 Wait for SonarQube backend to process the scan so issues are available
        await waitForSonarQubeProcessing(projectKey, 90, 2000, scanStarted);

        // 3. Generate full JSON + YAML report
        const { reportPath, yamlPath, report } = await generateScanReport(
            projectKey, projectName, compileInfo
        );

        // 4. Tag project in DB
        db.prepare(
            "UPDATE projects SET sonar_key = ? WHERE id = ?"
        ).run(projectKey, project.id);
        
        db.prepare(
            `INSERT INTO scan_results (project_id, quality_gate, summary, measures, report_path, yaml_path)
             VALUES (?, ?, ?, ?, ?, ?)`
        ).run(
            project.id,
            JSON.stringify(report.qualityGate || {}),
            JSON.stringify(report.summary || {}),
            JSON.stringify(report.measures || {}),
            reportPath,
            yamlPath
        );

        // Save findings so they are tracked across runs and appear in the final report
        recordSingleToolRun({ ...project, sonar_key: projectKey }, req.user.userId, "SonarQube",
            { issues: report.issues || [], engine: "native" });

        res.json({
            projectKey,
            projectName,
            qualityGate: report.qualityGate,
            summary: report.summary,
            measures: report.measures,
            compilation: report.compilation,
            // Every issue (not only the first page), with rule guidance, evidence and a recommended fix
            issues: adviseIssues({ ...project, sonar_key: projectKey }, "SonarQube", { issues: report.issues || [], engine: "native" }, buildFixPlan),
            reportFiles: {
                json: path.basename(reportPath),
                yaml: path.basename(yamlPath),
            },
            message: `Deep scan complete. ${report.summary.total} issues found.`,
        });

    } catch (err) {
        console.error("❌ Sonar scan error:", err.message);
        res.status(500).json({ error: err.message || "Sonar scan failed" });
    }
});

// ──────────────────────────────────────────────────────────────────
// POST /api/sonar/scan-and-map/:projectId
// Full pipeline: deep scan → report → GRC map → risk report
// ──────────────────────────────────────────────────────────────────
router.post("/scan-and-map/:projectId", async (req, res) => {
    try {
        const project = getProjectById(req.params.projectId, req.user.userId);
        if (!project) return res.status(404).json({ error: "Project not found." });
        if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

        const projectKey = toProjectKey(project.name, req.user.userId);
        const projectName = project.name;

        console.log(`\n🚀 Full pipeline starting for: ${projectName}`);

        // Step 1: Create SonarQube project
        await createSonarProject(projectKey, projectName);

        // Step 2: Deep scan (auto-compile Java → scanner)
        console.log("🔍 Running deep SonarQube scan...");
        const scanStarted = new Date();
        const { compileInfo } = await runSonarScan(projectKey, projectName, project.local_path);

        // Step 2.5: Wait for SonarQube backend processing
        await waitForSonarQubeProcessing(projectKey, 90, 2000, scanStarted);

        // Step 3: Generate full scan report (JSON + YAML)
        console.log("📊 Generating full scan report...");
        const { reportPath, yamlPath, report } = await generateScanReport(
            projectKey, projectName, compileInfo
        );

        // Step 4: Format issues for GRC mapping
        const findingsText = formatIssuesAsText(report.issues);

        // Step 5: GRC mapping via Gemini
        console.log("🗺️  Running GRC mapping...");
        const mapping = await mapFindingsToGRC("SonarQube", findingsText);

        // Step 6: Risk report via Gemini
        console.log("📄 Generating risk report...");
        const riskReport = await generateRiskReport(projectName, mapping);

        // Tag project and create scan result
        db.prepare(
            "UPDATE projects SET sonar_key = ? WHERE id = ?"
        ).run(projectKey, project.id);
        
        db.prepare(
            `INSERT INTO scan_results (project_id, quality_gate, summary, measures, report_path, yaml_path)
             VALUES (?, ?, ?, ?, ?, ?)`
        ).run(
            project.id,
            JSON.stringify(report.qualityGate || {}),
            JSON.stringify(report.summary || {}),
            JSON.stringify(report.measures || {}),
            reportPath,
            yamlPath
        );

        // Save findings so they are tracked across runs and appear in the final report
        recordSingleToolRun({ ...project, sonar_key: projectKey }, req.user.userId, "SonarQube",
            { issues: report.issues || [], engine: "native" });

        res.json({
            projectId: project.id,
            projectKey,
            projectName,
            compilation: report.compilation,
            qualityGate: report.qualityGate,
            measures: report.measures,
            summary: report.summary,
            reportFiles: {
                json: path.basename(reportPath),
                yaml: path.basename(yamlPath),
            },
            mapping,
            riskReport,
        });

    } catch (err) {
        console.error("❌ Full pipeline error:", err.message);
        res.status(500).json({ error: err.message || "Full pipeline failed" });
    }
});

/** 404 unless the SonarQube key belongs to one of the caller's projects. */
function requireOwnedKey(req, res, next) {
    if (!getOwnedProjectByKey(req.params.projectKey, req.user.userId)) {
        return res.status(404).json({ error: "Project not found." });
    }
    next();
}

/** Report file names that belong to the caller's scans. */
function ownedReportFiles(userId) {
    const rows = db.prepare(`
        SELECT sr.report_path, sr.yaml_path FROM scan_results sr
        JOIN projects p ON p.id = sr.project_id WHERE p.user_id = ?
    `).all(userId);
    const names = new Set();
    for (const r of rows) {
        if (r.report_path) names.add(path.basename(r.report_path));
        if (r.yaml_path) names.add(path.basename(r.yaml_path));
    }
    return names;
}

// ──────────────────────────────────────────────────────────────────
// GET /api/sonar/status/:projectKey
// ──────────────────────────────────────────────────────────────────
router.get("/status/:projectKey", requireOwnedKey, async (req, res) => {
    try {
        res.json(await getScanStatus(req.params.projectKey));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/sonar/issues/:projectKey
// ──────────────────────────────────────────────────────────────────
router.get("/issues/:projectKey", requireOwnedKey, async (req, res) => {
    try {
        const { page = 1, pageSize = 100 } = req.query;
        res.json(await getIssues(req.params.projectKey, {
            page: Number(page), pageSize: Number(pageSize),
        }));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/sonar/quality-gate/:projectKey
// ──────────────────────────────────────────────────────────────────
router.get("/quality-gate/:projectKey", requireOwnedKey, async (req, res) => {
    try {
        res.json(await getQualityGate(req.params.projectKey));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/sonar/reports — list all saved scan reports
// ──────────────────────────────────────────────────────────────────
router.get("/reports", (req, res) => {
    try {
        const mine = ownedReportFiles(req.user.userId);
        const files = fs.readdirSync(REPORTS_DIR)
            .filter(f => (f.endsWith(".json") || f.endsWith(".yaml")) && mine.has(f))
            .map(f => {
                const stat = fs.statSync(path.join(REPORTS_DIR, f));
                return { filename: f, size: stat.size, createdAt: stat.birthtime };
            })
            .sort((a, b) => b.createdAt - a.createdAt);
        res.json({ total: files.length, reports: files });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ──────────────────────────────────────────────────────────────────
// GET /api/sonar/reports/:filename — download a specific report
// ──────────────────────────────────────────────────────────────────
router.get("/reports/:filename", (req, res) => {
    const filename = path.basename(req.params.filename); // safety: strip path traversal
    const filePath = path.join(REPORTS_DIR, filename);
    if (!ownedReportFiles(req.user.userId).has(filename) || !fs.existsSync(filePath)) {
        return res.status(404).json({ error: `Report not found: ${filename}` });
    }
    const contentType = filename.endsWith(".yaml")
        ? "application/yaml"
        : "application/json";
    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    fs.createReadStream(filePath).pipe(res);
});

export default router;
