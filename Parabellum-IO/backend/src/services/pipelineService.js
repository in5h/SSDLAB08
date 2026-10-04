/**
 * pipelineService.js — One-click security pipeline per project.
 *
 * Stages: SonarQube → Semgrep → Snyk → Trivy → OWASP ZAP → Anchore → Correlate & map.
 * Every run is stored (pipeline_runs) with per-stage status, and every finding is
 * tracked across runs (findings + finding_events), so a rescan after a fix shows
 * exactly what was fixed, what is still open and what is new.
 */
import path from "node:path";
import db from "../db/database.js";
import {
  createSonarProject, runSonarScan, waitForSonarQubeProcessing, checkSonarAvailability,
} from "./sonarService.js";
import { generateScanReport } from "./scanReportService.js";
import { checkSemgrepAvailability, runSemgrepScan } from "./semgrepService.js";
import { checkSnykAvailability, runSnykScan } from "./snykService.js";
import { checkTrivyAvailability, runTrivyScan } from "./trivyService.js";
import { checkZapAvailability, runZapScan } from "./zapService.js";
import { checkAnchoreAvailability, runAnchoreScan } from "./anchoreService.js";
import { ingestToolResult, listFindings } from "./findingService.js";
import { buildFixPlan } from "./remediationService.js";
import { mapFinding, recommend } from "./ragRecommendService.js";
import { isGeminiConfigured } from "./geminiClient.js";

export const TOOL_ORDER = ["SonarQube", "Semgrep", "Snyk", "Trivy", "OWASP ZAP", "Anchore"];

// Mark runs that were cut off by a server restart
db.prepare("UPDATE pipeline_runs SET status = 'interrupted', finished_at = datetime('now') WHERE status = 'running'").run();

function toSonarKey(name, userId) {
  return `u${userId}_${name}`.replace(/[^a-zA-Z0-9_\-:.]/g, "_").replace(/_+/g, "_").substring(0, 200).toLowerCase();
}

/** SonarQube stage: same steps as the SonarQube tab, returns issues with clean file paths. */
async function sonarStage(project, userId) {
  const key = toSonarKey(project.name, userId);
  await createSonarProject(key, project.name);
  const scanStarted = new Date();
  const { compileInfo } = await runSonarScan(key, project.name, project.local_path);
  await waitForSonarQubeProcessing(key, 90, 2000, scanStarted);
  const { reportPath, yamlPath, report } = await generateScanReport(key, project.name, compileInfo);
  db.prepare("UPDATE projects SET sonar_key = ? WHERE id = ?").run(key, project.id);
  db.prepare(`INSERT INTO scan_results (project_id, quality_gate, summary, measures, report_path, yaml_path)
              VALUES (?, ?, ?, ?, ?, ?)`).run(project.id, JSON.stringify(report.qualityGate || {}),
    JSON.stringify(report.summary || {}), JSON.stringify(report.measures || {}), reportPath, yamlPath);
  project.sonar_key = key;
  return { issues: report.issues || [], engine: "native", extra: { qualityGate: report.qualityGate?.status, reportFile: path.basename(reportPath) } };
}

const STAGES = {
  "SonarQube": {
    check: async () => checkSonarAvailability(),
    run: (project, opts) => sonarStage(project, opts.userId),
  },
  "Semgrep": { check: checkSemgrepAvailability, run: p => runSemgrepScan(p.local_path) },
  "Snyk": { check: checkSnykAvailability, run: p => runSnykScan(p.local_path) },
  "Trivy": { check: checkTrivyAvailability, run: p => runTrivyScan(p.local_path) },
  "OWASP ZAP": {
    check: checkZapAvailability,
    run: (p, opts) => runZapScan(p.local_path, { targetUrl: opts.targetUrl || p.target_url, active: opts.active }),
  },
  "Anchore": { check: checkAnchoreAvailability, run: p => runAnchoreScan(p.local_path) },
};

function saveRun(runId, fields) {
  const sets = Object.keys(fields).map(k => `${k} = @${k}`).join(", ");
  db.prepare(`UPDATE pipeline_runs SET ${sets} WHERE id = @id`).run({ ...fields, id: runId });
}

/**
 * Start a pipeline run. Returns the run id immediately; stages run in the background.
 * @param {object} project — projects row (owned by the user)
 * @param {object} opts — { userId, tools?: string[], targetUrl?, active?, trigger? }
 */
export function startPipeline(project, opts) {
  if (!project.local_path) throw Object.assign(new Error("Project has no local source path."), { status: 422 });
  const busy = db.prepare("SELECT id FROM pipeline_runs WHERE project_id = ? AND status = 'running'").get(project.id);
  if (busy) throw Object.assign(new Error(`Pipeline run #${busy.id} is still running for this project.`), { status: 409 });

  const tools = (opts.tools?.length ? opts.tools : TOOL_ORDER).filter(t => TOOL_ORDER.includes(t));
  const stages = [...tools.map(t => ({ name: t, status: "pending" })), { name: "Correlate & map", status: "pending" }];
  const runId = db.prepare(`INSERT INTO pipeline_runs (project_id, user_id, trigger, tools, target_url, status, stages)
                            VALUES (?, ?, ?, ?, ?, 'running', ?)`)
    .run(project.id, opts.userId, opts.trigger || "pipeline", JSON.stringify(tools), opts.targetUrl || project.target_url || null,
      JSON.stringify(stages)).lastInsertRowid;

  executePipeline(runId, project, tools, stages, opts).catch(err => {
    console.error(`❌ Pipeline #${runId} crashed:`, err);
    saveRun(runId, { status: "failed", finished_at: new Date().toISOString() });
  });
  return runId;
}

async function executePipeline(runId, project, tools, stages, opts) {
  console.log(`\n🚦 Pipeline #${runId} started for ${project.name}: ${tools.join(", ")}`);
  const totals = { new: 0, stillOpen: 0, fixed: 0, reopened: 0, suppressed: 0 };
  const setStage = (name, patch) => {
    Object.assign(stages.find(s => s.name === name), patch);
    saveRun(runId, { stages: JSON.stringify(stages) });
  };

  for (const tool of tools) {
    const stage = STAGES[tool];
    const started = Date.now();
    setStage(tool, { status: "running", startedAt: new Date().toISOString() });
    try {
      const avail = await stage.check();
      if (!avail.available && !avail.builtInFallback) {
        setStage(tool, { status: "skipped", message: avail.error || `${tool} is not installed/connected.` });
        continue;
      }
      const result = await stage.run(project, opts);
      const counts = ingestToolResult(project, runId, tool, result);
      for (const k of Object.keys(totals)) totals[k] += counts[k];
      setStage(tool, {
        status: "done",
        engine: result.engine || "native",
        findings: (result.issues || []).length,
        counts,
        warning: result.warning,
        extra: result.extra,
        seconds: Math.round((Date.now() - started) / 1000),
      });
    } catch (err) {
      setStage(tool, { status: "failed", message: err.message.slice(0, 500), seconds: Math.round((Date.now() - started) / 1000) });
    }
  }

  // Correlate, map to frameworks and write RAG recommendations for open findings
  setStage("Correlate & map", { status: "running" });
  const started = Date.now();
  try {
    const mapped = await refreshMappings(project.id, { onlyMissing: false });
    setStage("Correlate & map", { status: "done", findings: mapped, seconds: Math.round((Date.now() - started) / 1000) });
  } catch (err) {
    setStage("Correlate & map", { status: "failed", message: err.message });
  }

  const findings = listFindings(project.id);
  const open = findings.filter(f => ["Open", "In Progress"].includes(f.status) && f.category === "Security" && !f.duplicateOf);
  const bySeverity = {};
  for (const f of open) bySeverity[f.risk] = (bySeverity[f.risk] || 0) + 1;
  const gateFail = open.some(f => ["Critical", "High"].includes(f.risk) && f.confidence !== "Low");
  const failedStages = stages.filter(s => s.status === "failed").length;
  saveRun(runId, {
    status: failedStages === stages.length - 1 ? "failed" : "completed",
    finished_at: new Date().toISOString(),
    summary: JSON.stringify({ ...totals, open: open.length, byRisk: bySeverity, gate: gateFail ? "FAIL" : "PASS", failedStages }),
  });
  console.log(`✅ Pipeline #${runId} finished: ${JSON.stringify(totals)} gate=${gateFail ? "FAIL" : "PASS"}`);
}

/**
 * Compute framework mappings + RAG recommendation for findings (cached on each row).
 * Gemini (if configured) is used for open Critical/High findings; others use the template.
 */
export async function refreshMappings(projectId, { onlyMissing = true } = {}) {
  const findings = listFindings(projectId).filter(f => f.category === "Security"
    && !["False Positive"].includes(f.status) && (!onlyMissing || !f.mappings));
  let llmBudget = isGeminiConfigured() ? 25 : 0;
  for (const f of findings) {
    const mapping = await mapFinding(f);
    const plan = buildFixPlan(f, f.risk);
    const useLLM = llmBudget > 0 && ["Critical", "High"].includes(f.risk) && ["Open", "In Progress"].includes(f.status);
    if (useLLM) llmBudget--;
    const rec = await recommend(f, mapping, plan, { useLLM });
    db.prepare("UPDATE findings SET mappings = ?, recommendation = ?, rec_source = ? WHERE id = ?")
      .run(JSON.stringify(mapping), rec.text, rec.source, f.id);
  }
  return findings.length;
}

/** Record a single-tool scan from the Security Scans page as a one-stage run. */
export function recordSingleToolRun(project, userId, tool, result) {
  const stages = [{ name: tool, status: "done", engine: result.engine || "native", findings: (result.issues || []).length }];
  const runId = db.prepare(`INSERT INTO pipeline_runs (project_id, user_id, trigger, tools, status, stages, finished_at)
                            VALUES (?, ?, 'single', ?, 'completed', ?, datetime('now'))`)
    .run(project.id, userId, JSON.stringify([tool]), JSON.stringify(stages)).lastInsertRowid;
  const counts = ingestToolResult(project, runId, tool, result);
  stages[0].counts = counts;
  saveRun(runId, { stages: JSON.stringify(stages), summary: JSON.stringify(counts) });
  return { runId, counts };
}

export function listRuns(projectId) {
  return db.prepare("SELECT * FROM pipeline_runs WHERE project_id = ? ORDER BY id DESC LIMIT 50").all(projectId)
    .map(r => ({ ...r, tools: JSON.parse(r.tools || "[]"), stages: JSON.parse(r.stages || "[]"), summary: r.summary ? JSON.parse(r.summary) : null }));
}

export function getRun(runId) {
  const r = db.prepare("SELECT * FROM pipeline_runs WHERE id = ?").get(runId);
  if (!r) return null;
  return { ...r, tools: JSON.parse(r.tools || "[]"), stages: JSON.parse(r.stages || "[]"), summary: r.summary ? JSON.parse(r.summary) : null };
}
