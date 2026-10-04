/**
 * tools.js — Express router for unified security tool endpoints
 *
 * GET  /api/tools/status                   — check all 6 security tool statuses
 * POST /api/tools/semgrep/scan/:projectId  — run Semgrep SAST scan
 * POST /api/tools/snyk/scan/:projectId     — run Snyk SCA scan
 * POST /api/tools/trivy/scan/:projectId    — run Trivy Container scan
 * POST /api/tools/zap/scan/:projectId      — run OWASP ZAP DAST scan
 * POST /api/tools/anchore/scan/:projectId  — run Anchore Container Policy scan
 */

import express from "express";
import { getProjectById } from "./projects.js";
import { checkSemgrepAvailability, runSemgrepScan } from "../services/semgrepService.js";
import { checkSnykAvailability, runSnykScan } from "../services/snykService.js";
import { checkTrivyAvailability, runTrivyScan } from "../services/trivyService.js";
import { checkZapAvailability, runZapScan } from "../services/zapService.js";
import { checkAnchoreAvailability, runAnchoreScan } from "../services/anchoreService.js";
import { checkSonarAvailability } from "../services/sonarService.js";
import { recordSingleToolRun } from "../services/pipelineService.js";
import { adviseIssues } from "../services/findingService.js";
import { buildFixPlan } from "../services/remediationService.js";

/** Add CWE, code evidence, risk and a recommended fix to every result row. */
const withAdvice = (project, tool, result) => ({ ...result, issues: adviseIssues(project, tool, result, buildFixPlan) });

const router = express.Router();

// ── GET /api/tools/status ─────────────────────────────────────────
// Returns availability / version info for all 6 security tools
router.get("/status", async (req, res) => {
  try {
    const [sonarqube, semgrep, snyk, trivy, zap, anchore] = await Promise.all([
      checkSonarAvailability(),
      checkSemgrepAvailability(),
      checkSnykAvailability(),
      checkTrivyAvailability(),
      checkZapAvailability(),
      checkAnchoreAvailability(),
    ]);

    res.json({
      sonarqube,
      semgrep,
      snyk,
      trivy,
      zap,
      anchore,
    });
  } catch (err) {
    console.error("❌ Tools status error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/tools/semgrep/scan/:projectId ───────────────────────
router.post("/semgrep/scan/:projectId", async (req, res) => {
  try {
    const project = getProjectById(req.params.projectId, req.user.userId);
    if (!project) return res.status(404).json({ error: "Project not found." });
    if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

    console.log(`\n🔎 Semgrep scan starting for: ${project.name}`);
    const result = await runSemgrepScan(project.local_path);
    // Save findings so they are tracked across runs and appear in the final report
    const tracked = recordSingleToolRun(project, req.user.userId, "Semgrep", result);
    res.json({ projectId: project.id, projectName: project.name, ...withAdvice(project, "Semgrep", result), tracking: tracked });
  } catch (err) {
    console.error("❌ Semgrep scan error:", err.message);
    res.status(500).json({ error: err.message || "Semgrep scan failed" });
  }
});

// ── POST /api/tools/snyk/scan/:projectId ──────────────────────────
router.post("/snyk/scan/:projectId", async (req, res) => {
  try {
    const project = getProjectById(req.params.projectId, req.user.userId);
    if (!project) return res.status(404).json({ error: "Project not found." });
    if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

    console.log(`\n📦 Snyk scan starting for: ${project.name}`);
    const result = await runSnykScan(project.local_path, { severityThreshold: req.body.severityThreshold || null });
    // Save findings so they are tracked across runs and appear in the final report
    const tracked = recordSingleToolRun(project, req.user.userId, "Snyk", result);
    res.json({ projectId: project.id, projectName: project.name, ...withAdvice(project, "Snyk", result), tracking: tracked });
  } catch (err) {
    console.error("❌ Snyk scan error:", err.message);
    res.status(500).json({ error: err.message || "Snyk scan failed" });
  }
});

// ── POST /api/tools/trivy/scan/:projectId ─────────────────────────
router.post("/trivy/scan/:projectId", async (req, res) => {
  try {
    const project = getProjectById(req.params.projectId, req.user.userId);
    if (!project) return res.status(404).json({ error: "Project not found." });
    if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

    console.log(`\n🐳 Trivy scan starting for: ${project.name}`);
    const result = await runTrivyScan(project.local_path);
    // Save findings so they are tracked across runs and appear in the final report
    const tracked = recordSingleToolRun(project, req.user.userId, "Trivy", result);
    res.json({ projectId: project.id, projectName: project.name, ...withAdvice(project, "Trivy", result), tracking: tracked });
  } catch (err) {
    console.error("❌ Trivy scan error:", err.message);
    res.status(500).json({ error: err.message || "Trivy scan failed" });
  }
});

// ── POST /api/tools/zap/scan/:projectId ───────────────────────────
router.post("/zap/scan/:projectId", async (req, res) => {
  try {
    const project = getProjectById(req.params.projectId, req.user.userId);
    if (!project) return res.status(404).json({ error: "Project not found." });

    console.log(`\n🌐 OWASP ZAP scan starting for: ${project.name}`);
    const result = await runZapScan(project.local_path || "", {
      targetUrl: req.body.targetUrl,
      active: req.body.active === true,
    });
    // Save findings so they are tracked across runs and appear in the final report
    const tracked = recordSingleToolRun(project, req.user.userId, "OWASP ZAP", result);
    res.json({ projectId: project.id, projectName: project.name, ...withAdvice(project, "OWASP ZAP", result), tracking: tracked });
  } catch (err) {
    console.error("❌ OWASP ZAP scan error:", err.message);
    res.status(err.status || 500).json({ error: err.message || "OWASP ZAP scan failed" });
  }
});

// ── POST /api/tools/anchore/scan/:projectId ───────────────────────
router.post("/anchore/scan/:projectId", async (req, res) => {
  try {
    const project = getProjectById(req.params.projectId, req.user.userId);
    if (!project) return res.status(404).json({ error: "Project not found." });
    if (!project.local_path) return res.status(422).json({ error: "Project has no local source path." });

    console.log(`\n🛡️ Anchore scan starting for: ${project.name}`);
    const result = await runAnchoreScan(project.local_path);
    // Save findings so they are tracked across runs and appear in the final report
    const tracked = recordSingleToolRun(project, req.user.userId, "Anchore", result);
    res.json({ projectId: project.id, projectName: project.name, ...withAdvice(project, "Anchore", result), tracking: tracked });
  } catch (err) {
    console.error("❌ Anchore scan error:", err.message);
    res.status(500).json({ error: err.message || "Anchore scan failed" });
  }
});

export default router;
