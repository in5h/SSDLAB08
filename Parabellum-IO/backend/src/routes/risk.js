/**
 * risk.js — /api/risk routes
 * CWE-mapped risk analysis of the open findings from ALL security tools
 * (falls back to SonarQube issues when the project has no stored tool results).
 */
import express from "express";
import db from "../db/database.js";
import { buildCWEFindings, buildRiskSummary } from "../services/cweRiskService.js";
import { resolveThreatMapping, buildHeatmaps } from "../services/threatMappings.js";
import { scanProject } from "../services/policyEngine.js";
import { getOwnedProjectByKey, getProjectById } from "./projects.js";
import { loadProjectIssues, analysableProjects } from "../services/projectIssues.js";
import { askLLM, isGeminiConfigured } from "../services/geminiClient.js";

const router = express.Router();

// ── GET /api/risk/projects ─────────────────────────────────────────────────
// Returns all user projects with a needsScan flag
router.get("/projects", (req, res) => {
  res.json(analysableProjects(req.user.userId));
});

// ── POST /api/risk/analyze ─────────────────────────────────────────────────
// Body: { projectKey, projectId }
router.post("/analyze", async (req, res) => {
  const { projectKey, projectId: bodyProjectId } = req.body;
  if (!projectKey && !bodyProjectId) {
    return res.status(400).json({ error: "projectId (or projectKey) is required" });
  }

  // Only allow analysis of the caller's own projects
  const ownedProject = bodyProjectId ? getProjectById(bodyProjectId, req.user.userId) : getOwnedProjectByKey(projectKey, req.user.userId);
  if (!ownedProject) return res.status(404).json({ error: "Project not found." });
  const projectId = ownedProject.id;

  console.log(`\n🎯 Risk analysis for: ${ownedProject.name}`);

  try {
    // 1. Open findings from all tools (or SonarQube issues if nothing is stored yet)
    let issueList = [];
    let sources = { source: "none", tools: [] };
    try {
      const loaded = await loadProjectIssues(ownedProject);
      issueList = loaded.issues;
      sources = { source: loaded.source, tools: loaded.tools, toolFindings: issueList.length };
      console.log(`   📋 ${issueList.length} open issues from ${loaded.tools.join(", ") || "no tools"}`);
    } catch (err) {
      const msg = err.message || "";
      if (err.response?.status === 404 || msg.includes("404") || msg.includes("not found")) {
        return res.status(422).json({
          notYetScanned: true,
          error: "This project has no scan results yet. Run the Pipeline (or any scan on Security Scans) first.",
        });
      }
      throw err;
    }

    // 1b. Fetch local config/policy violations
    if (projectId) {
      try {
        const { violations } = ownedProject.local_path ? scanProject(ownedProject.local_path) : { violations: [] };

        if (violations && violations.length > 0) {
          console.log(`   🛠️ Policy Engine: Found ${violations.length} config/infra violations`);
          for (const v of violations) {
            issueList.push({
              key: `config-${v.policyId}-${Math.random()}`,
              type: "CONFIG",
              severity: v.severity.toUpperCase(),
              rule: v.policyId,
              message: `[${v.policyId}] ${v.message}`,
              component: v.file,
              line: null,
              status: "OPEN"
            });
          }
        }
      } catch (err) {
        console.warn("   ⚠ Policy scanning failed in risk analysis:", err.message);
      }
    }

    sources.policyChecks = issueList.length - (sources.toolFindings || 0);

    if (issueList.length === 0) {
      return res.json({
        cweFindings: [],
        riskSummary: buildRiskSummary([], 0),
        projectKey: ownedProject.sonar_key || ownedProject.name, ...sources,
        scannedAt: new Date().toISOString(),
      });
    }

    // 2. Map issues → CWE findings
    const cweFindings = buildCWEFindings(issueList);
    const riskSummary = buildRiskSummary(cweFindings, issueList.length);

    // 3. Enrich each finding with MITRE / OWASP / CAPEC threat intel
    for (const f of cweFindings) {
      f.threatMapping = resolveThreatMapping(f.cwe_id);
    }

    // 4. Build heatmap aggregations
    const heatmaps = buildHeatmaps(cweFindings);

    console.log(`   ✅ Mapped to ${cweFindings.length} unique CWEs`);
    console.log(`   🔴 Critical: ${riskSummary.critical_cwes}  🟠 High: ${riskSummary.high_cwes}`);
    console.log(`   🗺️  MITRE: ${heatmaps.mitre.length}  OWASP: ${heatmaps.owasp.length}  CAPEC: ${heatmaps.capec.length}`);

    // 5. Optionally save to scan_results if projectId provided
    if (projectId) {
      try {
        const existing = db.prepare(
          "SELECT id FROM scan_results WHERE project_id = ? ORDER BY scanned_at DESC LIMIT 1"
        ).get(projectId);

        if (existing) {
          db.prepare(
            "UPDATE scan_results SET summary = ? WHERE id = ?"
          ).run(
            JSON.stringify({ ...JSON.parse(existing.summary || "{}"), riskSummary }),
            existing.id
          );
        }
      } catch (dbErr) { console.debug("Non-fatal risk DB update:", dbErr.message); }
    }

    return res.json({
      cweFindings,
      riskSummary,
      heatmaps,
      projectKey: ownedProject.sonar_key || ownedProject.name,
      ...sources,
      scannedAt: new Date().toISOString(),
    });

  } catch (err) {
    console.error("❌ Risk analysis error:", err.message);
    return res.status(500).json({ error: err.message || "Risk analysis failed" });
  }
});

// ── POST /api/risk/ai-advice ───────────────────────────────────────────────
// Body: { cweId, name, severity, cvss, examples: [{ message, component, line }] }
// Asks Gemini for plain-language remediation advice for one CWE finding.
router.post("/ai-advice", async (req, res) => {
  const { cweId, name, severity, cvss, examples = [] } = req.body || {};
  if (!cweId) return res.status(400).json({ error: "cweId is required" });
  if (!isGeminiConfigured()) {
    return res.status(503).json({ error: "Gemini is not configured. Set GEMINI_API_KEY in backend/.env." });
  }

  const sample = examples.slice(0, 5).map(e =>
    `- ${String(e.message || "").slice(0, 300)} (${e.component || "unknown file"}${e.line ? `:${e.line}` : ""})`
  ).join("\n");

  const prompt = `You are an application security engineer helping a developer fix a finding.
Weakness: ${cweId} ${name || ""}
Severity: ${severity || "unknown"}${cvss ? `, CVSS ${cvss}` : ""}
Example occurrences from the scanner:
${sample || "- (none provided)"}

Reply in plain English with these sections:
1. What the problem is (2 sentences, no jargon).
2. Business impact (1-2 sentences).
3. How to fix it (numbered steps, include a short code example if useful).
4. How to verify the fix.
Keep it under 250 words.`;

  try {
    const advice = await askLLM(prompt);
    res.json({ cweId, advice, model: "gemini" });
  } catch (err) {
    console.error("❌ Gemini advice error:", err.message);
    res.status(502).json({ error: "Gemini request failed: " + err.message });
  }
});

export default router;
