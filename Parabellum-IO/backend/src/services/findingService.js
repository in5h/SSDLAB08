/**
 * findingService.js — Unified findings across all tools.
 *
 *  normalize   : every tool's output → one finding format (severity, CWE, file/line, package, URL)
 *  ingestRun   : store a scan run; track lifecycle New → Open → Fixed / Reopened
 *                (fix verification: a finding that the same tool no longer reports is marked Fixed)
 *  evidence    : code snippet around the reported line / manifest line / ZAP evidence
 *  confidence  : true-positive confidence from tool type, cross-tool corroboration, file location
 *                and analyst triage (False Positive / Accepted Risk are remembered across rescans)
 *  risk        : severity × asset/business context (internet-facing, environment, criticality, data)
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import db from "../db/database.js";
import { mapIssueToCWE, getCWE } from "./cweRiskService.js";
import { dueDateFor } from "./remediationService.js";

export const STATUSES = ["Open", "In Progress", "Fixed", "Verified Fixed", "Accepted Risk", "False Positive"];
const SUPPRESSED = ["Accepted Risk", "False Positive"];
const OPEN_LIKE = ["Open", "In Progress"];

const SEV = {
  BLOCKER: "Critical", CRITICAL: "Critical", HIGH: "High", MAJOR: "High",
  MEDIUM: "Medium", MINOR: "Medium", LOW: "Low", INFO: "Low", INFORMATIONAL: "Low",
  Critical: "Critical", High: "High", Medium: "Medium", Low: "Low",
};
const SEV_SCORE = { Critical: 9, High: 7, Medium: 5, Low: 3, Info: 1 };

// ── Normalisation ──────────────────────────────────────────────────
function shortTitle(message) {
  const m = String(message).replace(/\s*\(\d+ URLs\)$/, "").trim();
  const first = m.split(/(?<=[.!?])\s+(?=[A-Z])/)[0];
  return (first.length > 140 ? `${first.slice(0, 137)}…` : first).replace(/\.$/, "");
}

function firstCwe(list) {
  const raw = Array.isArray(list) ? list[0] : list;
  const m = String(raw || "").match(/CWE-\d+/i);
  return m ? m[0].toUpperCase() : null;
}

function cleanFile(component, sonarKey) {
  if (!component) return null;
  let c = String(component);
  if (sonarKey && c.startsWith(`${sonarKey}:`)) c = c.slice(sonarKey.length + 1);
  else if (/^[^/\\]+:[^/\\]/.test(c) && !/^[a-z]:\\/i.test(c) && !c.startsWith("http")) c = c.slice(c.indexOf(":") + 1);
  return c.replace(/\\/g, "/");
}

/**
 * Convert one tool result into unified findings.
 * @param {string} tool — SonarQube | Semgrep | Snyk | Trivy | OWASP ZAP | Anchore
 * @param {object} result — the tool service result ({ issues, engine })
 */
export function normalize(tool, result, { sonarKey } = {}) {
  const builtIn = result.engine === "built-in";
  const toolKey = builtIn ? `${tool} (built-in)` : tool;
  const list = (result.issues || []).map(i => {
    const pkg = i.pkgName || i.packageName || null;
    const isUrl = tool === "OWASP ZAP" && /^https?:/.test(i.component || "");
    const f = {
      tool: toolKey,
      engine: builtIn ? "built-in" : "native",
      rule: i.rule || i.key || "unknown",
      // Short display title: first sentence of the message
      title: shortTitle(i.message || i.rule || ""),
      titleKey: (i.message || "").split(" — ")[0].replace(/\s*\(\d+ URLs\)$/, "").slice(0, 200),
      message: i.message || "",
      severity: SEV[i.severity] || SEV[String(i.severity || "").toUpperCase()] || "Medium",
      type: i.type || (pkg ? "VULNERABILITY" : "SECURITY_HOTSPOT"),
      cwe: firstCwe(i.cwe),
      file: isUrl ? null : (pkg ? cleanFile(i.target || i.component) : cleanFile(i.component, sonarKey)),
      line: Number.isFinite(i.line) ? i.line : null,
      package_name: pkg,
      installed_version: i.installedVersion || i.packageVersion || null,
      fixed_version: i.fixedVersion || (Array.isArray(i.fixedIn) ? i.fixedIn.join(", ") : null) || null,
      url: isUrl ? i.component : null,
      raw: i,
    };
    if (!f.cwe) f.cwe = pkg ? "CWE-1104" : mapIssueToCWE({ message: `${f.message} ${f.rule}`, rule: f.rule, type: f.type }).id;
    // Fingerprint ignores line numbers so a finding keeps its identity when code moves
    const norm = f.titleKey.toLowerCase().replace(/\d+/g, "#");
    delete f.titleKey;
    f.baseKey = [toolKey, f.rule, f.file || "", f.url ? new URL(f.url).pathname : "", pkg || "", f.installed_version || "", norm].join("|");
    return f;
  });
  // The same rule can fire several times in one file: number the occurrences (in line order)
  const seen = {};
  for (const f of [...list].sort((a, b) => (a.line || 0) - (b.line || 0))) {
    const n = (seen[f.baseKey] = (seen[f.baseKey] || 0) + 1);
    f.fingerprint = crypto.createHash("sha1").update(`${f.baseKey}|${n}`).digest("hex");
    delete f.baseKey;
  }
  return list;
}

// ── Evidence ───────────────────────────────────────────────────────
/** Code lines around the finding (">" marks the reported line). */
export function collectEvidence(project, f) {
  if (f.url) {
    const urls = f.raw?.affectedUrls?.length ? f.raw.affectedUrls : [f.url];
    return `Affected URL(s):\n${urls.slice(0, 5).join("\n")}${f.raw?.evidence ? `\nEvidence: ${f.raw.evidence}` : ""}`;
  }
  if (!project?.local_path || !f.file) return null;
  const root = path.resolve(project.local_path);
  const full = path.resolve(root, f.file);
  if (!full.startsWith(root) || !fs.existsSync(full) || fs.statSync(full).size > 2_000_000) return null;
  const lines = fs.readFileSync(full, "utf8").split("\n");

  let target = f.line;
  if (!target && f.package_name) {
    const idx = lines.findIndex(l => l.includes(`"${f.package_name}"`) || l.includes(`${f.package_name}==`) || l.includes(`<artifactId>${f.package_name}<`));
    target = idx >= 0 ? idx + 1 : null;
  }
  if (!target) return null;
  const from = Math.max(1, target - 3), to = Math.min(lines.length, target + 3);
  const out = [];
  for (let n = from; n <= to; n++) {
    out.push(`${n === target ? ">" : " "} ${String(n).padStart(4)} | ${lines[n - 1].slice(0, 160)}`);
  }
  return `${f.file}:${target}\n${out.join("\n")}`;
}

// ── Risk (business context) ────────────────────────────────────────
/**
 * Risk score (0–10) = base × likelihood × business impact × confidence
 *  base       : tool severity, averaged with the weakness' typical CVSS (code/config findings)
 *  likelihood : internet-facing (1.0 / 0.85) × environment (Production 1.0 … Development 0.8)
 *  impact     : business criticality (Critical 1.0 … Low 0.75) + data classification bonus
 */
export function riskFor(f, project, confidence = "Medium") {
  const sev = SEV_SCORE[f.severity] ?? 5;
  const kb = !f.package_name ? getCWE(f.cwe) : null;
  const base = kb && f.cwe !== "CWE-693" ? (sev + kb.cvss) / 2 : sev;
  const likelihood = (project?.internet_facing ? 1.0 : 0.85) *
    ({ Production: 1.0, Staging: 0.9, Test: 0.8, Development: 0.8 }[project?.environment] ?? 0.9);
  const impact = Math.min(1, ({ Critical: 1.0, High: 0.95, Medium: 0.85, Low: 0.75 }[project?.business_criticality] ?? 0.85) +
    ({ Restricted: 0.05, Confidential: 0.03 }[project?.data_classification] ?? 0));
  const conf = { High: 1, Medium: 0.9, Low: 0.75 }[confidence] ?? 0.9;
  const score = Math.round(base * likelihood * impact * conf * 10) / 10;
  const rating = score >= 8.5 ? "Critical" : score >= 6.5 ? "High" : score >= 4 ? "Medium" : score >= 2 ? "Low" : "Info";
  return { score, rating };
}

// Remove real HTML markup (ZAP / Snyk descriptions) but keep code such as "<!DOCTYPE>" or "<html>" written in the text
const stripTags = t => String(t).replace(/<\/?(p|br|code|pre|ul|ol|li|h\d|strong|em|a|b|i|span|div)\b[^>]*>/gi, "");

/** The scanner's own fix advice (SonarQube rule "how to fix", Trivy resolution, ZAP solution …), if any. */
function parseRaw(raw) {
  try { return typeof raw === "string" ? JSON.parse(raw) : raw || {}; } catch { return {}; }
}
function toolGuidance(raw) {
  const r = parseRaw(raw);
  const g = r.solution || r.resolution || r.remediation || null;
  return g ? stripTags(g).trim().slice(0, 1500) : null;
}
/** Extra details from the raw tool output that help the user (description, autofix code, references). */
function toolExtras(raw) {
  const r = parseRaw(raw);
  return {
    toolFix: r.fix ? String(r.fix).slice(0, 800) : null,
    description: r.description ? stripTags(r.description).trim().slice(0, 1500) : null,
    references: Array.isArray(r.references) ? r.references.slice(0, 5) : [],
    ruleName: r.ruleName || null,
    cve: r.cve || r.vulnerabilityId || null,
    owasp: r.owasp || null,
  };
}

// ── Run ingestion & lifecycle ──────────────────────────────────────
function event(findingId, runId, ev, detail = null, actor = "pipeline") {
  db.prepare("INSERT INTO finding_events (finding_id, run_id, event, detail, actor) VALUES (?, ?, ?, ?, ?)")
    .run(findingId, runId, ev, detail, actor);
}

/**
 * Store the findings of one tool in a run and update the lifecycle of that tool's
 * earlier findings. Only findings from `tool` are considered for "Fixed", so a run
 * that skips a tool never closes that tool's findings.
 * @returns {{ new: number, stillOpen: number, fixed: number, reopened: number, suppressed: number }}
 */
export function ingestToolResult(project, runId, tool, result) {
  const items = normalize(tool, result, { sonarKey: project.sonar_key });
  const toolKey = result.engine === "built-in" ? `${tool} (built-in)` : tool;
  const counts = { new: 0, stillOpen: 0, fixed: 0, reopened: 0, suppressed: 0 };
  const seen = new Set();

  const tx = db.transaction(() => {
    for (const f of items) {
      if (seen.has(f.fingerprint)) continue;
      seen.add(f.fingerprint);
      const evidence = collectEvidence(project, f);
      const existing = db.prepare("SELECT * FROM findings WHERE project_id = ? AND fingerprint = ?").get(project.id, f.fingerprint);

      if (!existing) {
        const r = db.prepare(`
          INSERT INTO findings (project_id, fingerprint, tool, engine, rule, title, message, severity, type, cwe, file, line,
            package_name, installed_version, fixed_version, url, evidence, raw, status, owner, due_date, first_seen_run, last_seen_run)
          VALUES (@project_id, @fingerprint, @tool, @engine, @rule, @title, @message, @severity, @type, @cwe, @file, @line,
            @package_name, @installed_version, @fixed_version, @url, @evidence, @raw, 'Open', @owner, @due_date, @run, @run)
        `).run({
          ...f, project_id: project.id, evidence, raw: JSON.stringify(f.raw).slice(0, 20000),
          // due_date stays empty: it follows the SLA of the final risk rating until someone sets one by hand
          owner: project.business_owner || null, due_date: null, run: runId,
        });
        event(r.lastInsertRowid, runId, "New", `Detected by ${toolKey}`);
        counts.new++;
        continue;
      }

      db.prepare(`UPDATE findings SET last_seen_run = ?, line = ?, severity = ?, title = ?, message = ?, evidence = COALESCE(?, evidence),
                  raw = ?, updated_at = datetime('now') WHERE id = ?`)
        .run(runId, f.line, f.severity, f.title, f.message, evidence, JSON.stringify(f.raw).slice(0, 20000), existing.id);

      if (SUPPRESSED.includes(existing.status)) {
        counts.suppressed++;
      } else if (["Fixed", "Verified Fixed"].includes(existing.status)) {
        db.prepare("UPDATE findings SET status = 'Open', fixed_run = NULL, fixed_at = NULL WHERE id = ?").run(existing.id);
        event(existing.id, runId, "Reopened", `${toolKey} reported it again after it was marked ${existing.status}`);
        counts.reopened++;
      } else {
        counts.stillOpen++;
      }
    }

    // Fix verification: open findings from this tool that were not reported in this run
    const gone = db.prepare(`
      SELECT id, status FROM findings WHERE project_id = ? AND tool = ? AND (last_seen_run IS NULL OR last_seen_run != ?)
      AND status IN ('Open', 'In Progress', 'Fixed')
    `).all(project.id, toolKey, runId);
    for (const g of gone) {
      db.prepare("UPDATE findings SET status = 'Verified Fixed', fixed_run = ?, fixed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?")
        .run(runId, g.id);
      event(g.id, runId, "Verified Fixed", `Not reported by ${toolKey} in rescan (run #${runId})`);
      counts.fixed++;
    }
  });
  tx();
  return counts;
}

// ── Correlation & confidence ───────────────────────────────────────
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|examples?|fixtures?|mocks?|docs?|vendor|third_party)(\/|$)|\.(test|spec)\.[jt]sx?$/i;
const BASE_CONF = { "SonarQube": 0.6, "Semgrep": 0.6, "Snyk": 0.85, "Trivy": 0.85, "Anchore": 0.85, "OWASP ZAP": 0.75 };

function isQuality(f) {
  return ["BUG", "CODE_SMELL"].includes(f.type) && (!f.cwe || f.cwe === "CWE-693") && !f.package_name && !f.url;
}

/**
 * Add correlation, confidence, category and risk to stored findings.
 * Findings from different tools about the same weakness at the same place
 * (same file + CWE within ±3 lines, or same package+version) corroborate each other.
 */
// Tools label the same weakness with sibling CWE ids — compare by family
const CWE_FAMILY = {
  "CWE-95": "CWE-94", "CWE-96": "CWE-94", "CWE-913": "CWE-94",
  "CWE-564": "CWE-89", "CWE-943": "CWE-89",
  "CWE-80": "CWE-79", "CWE-83": "CWE-79", "CWE-116": "CWE-79",
  "CWE-259": "CWE-798", "CWE-321": "CWE-798", "CWE-312": "CWE-798", "CWE-540": "CWE-798",
  "CWE-269": "CWE-250", "CWE-732": "CWE-250",
};
const family = cwe => CWE_FAMILY[cwe] || cwe;

export function enrich(rows, project) {
  const groups = new Map();
  const keyOf = f => f.package_name
    ? `pkg|${f.package_name}|${f.installed_version}`
    : f.url ? `url|${family(f.cwe)}|${new URL(f.url).pathname}` : `code|${f.file}|${family(f.cwe)}|${Math.floor((f.line || 0) / 4)}`;
  for (const f of rows) {
    const k = keyOf(f);
    if (!groups.has(k)) groups.set(k, new Set());
    groups.get(k).add(f.tool.replace(" (built-in)", ""));
  }

  // Cross-tool duplicates: the same weakness at the same place reported by several tools is kept once.
  // The finding from the most reliable tool is the primary; the others point to it (duplicateOf).
  const primaryOf = new Map();
  const rank = f => (f.engine === "built-in" ? 0.4 : (BASE_CONF[f.tool.replace(" (built-in)", "")] ?? 0.6));
  const openGroups = new Map();
  for (const f of rows) {
    if (!OPEN_LIKE.includes(f.status)) continue;
    const k = keyOf(f);
    if (!openGroups.has(k)) openGroups.set(k, []);
    openGroups.get(k).push(f);
  }
  for (const list of openGroups.values()) {
    if (new Set(list.map(f => f.tool.replace(" (built-in)", ""))).size < 2) continue;
    const best = [...list].sort((a, b) => rank(b) - rank(a) || a.id - b.id)[0];
    for (const f of list) if (f.tool !== best.tool) primaryOf.set(f.id, best.id);
  }

  return rows.map(f => {
    const baseTool = f.tool.replace(" (built-in)", "");
    const tools = [...(groups.get(keyOf(f)) || [])];
    const corroborated = tools.filter(t => t !== baseTool);
    let score = f.engine === "built-in" ? 0.4 : (BASE_CONF[baseTool] ?? 0.6);
    const reasons = [f.engine === "built-in" ? "built-in heuristic check" : `${baseTool} native result`];
    if (corroborated.length) { score += 0.25; reasons.push(`confirmed by ${corroborated.join(", ")}`); }
    if (f.raw && /"confidence":"HIGH"/i.test(f.raw)) { score += 0.1; reasons.push("tool reports HIGH confidence"); }
    if (f.file && TEST_PATH.test(f.file)) { score -= 0.25; reasons.push("test/example/vendor path"); }
    if (isQuality(f)) { score -= 0.2; reasons.push("code-quality rule, not a security weakness"); }
    if (f.status === "False Positive") { score = 0; reasons.push("marked False Positive by analyst"); }
    const confidence = score >= 0.75 ? "High" : score >= 0.5 ? "Medium" : "Low";
    const risk = riskFor(f, project, confidence);
    const kb = getCWE(f.cwe) || mapIssueToCWE({ message: f.message, rule: f.rule, type: f.type });
    return {
      ...f,
      toolGuidance: toolGuidance(f.raw),
      ...toolExtras(f.raw),
      raw: undefined,
      mappings: f.mappings ? JSON.parse(f.mappings) : null,
      category: isQuality(f) ? "Code Quality" : "Security",
      cweName: kb?.name || null,
      corroboratedBy: corroborated,
      duplicateOf: primaryOf.get(f.id) || null,
      confidence, confidenceScore: Math.round(Math.max(0, Math.min(1, score)) * 100) / 100,
      confidenceReasons: reasons,
      likelyFalsePositive: confidence === "Low" && f.status !== "False Positive",
      risk: risk.rating, riskScore: risk.score,
      due_date: f.due_date || dueDateFor(risk.rating, `${String(f.created_at).replace(" ", "T")}Z`),
      dueDateSource: f.due_date ? "manual" : "SLA",
    };
  });
}

export function listFindings(projectId, { includeClosed = true } = {}) {
  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId);
  const rows = db.prepare(`SELECT * FROM findings WHERE project_id = ? ${includeClosed ? "" : "AND status IN ('Open','In Progress')"}
    ORDER BY id`).all(projectId);
  return enrich(rows, project);
}

/** Analyst update: status / owner / due date / note (with audit event). */
export function updateFinding(projectId, findingId, changes, actor) {
  const f = db.prepare("SELECT * FROM findings WHERE id = ? AND project_id = ?").get(findingId, projectId);
  if (!f) return null;
  const allowed = {};
  if (changes.status !== undefined) {
    if (!STATUSES.includes(changes.status)) throw Object.assign(new Error(`Status must be one of: ${STATUSES.join(", ")}`), { status: 400 });
    allowed.status = changes.status;
  }
  if (changes.owner !== undefined) allowed.owner = String(changes.owner).slice(0, 120);
  if (changes.due_date !== undefined) {
    if (changes.due_date && !/^\d{4}-\d{2}-\d{2}$/.test(changes.due_date)) throw Object.assign(new Error("due_date must be YYYY-MM-DD"), { status: 400 });
    allowed.due_date = changes.due_date || null;
  }
  if (changes.triage_note !== undefined) allowed.triage_note = String(changes.triage_note).slice(0, 1000);
  if (!Object.keys(allowed).length) return f;

  const sets = Object.keys(allowed).map(k => `${k} = @${k}`).join(", ");
  db.prepare(`UPDATE findings SET ${sets}, updated_at = datetime('now') WHERE id = @id`).run({ ...allowed, id: f.id });
  const detail = Object.entries(allowed).map(([k, v]) => `${k}: ${f[k] ?? "—"} → ${v ?? "—"}`).join("; ");
  event(f.id, null, allowed.status ? `Status: ${allowed.status}` : "Updated", detail, actor);
  return db.prepare("SELECT * FROM findings WHERE id = ?").get(f.id);
}

export function findingHistory(findingId) {
  return db.prepare("SELECT run_id, event, detail, actor, at FROM finding_events WHERE finding_id = ? ORDER BY id").all(findingId);
}

/**
 * Fix advice for the raw results of one scan (Security Scans page), so every row
 * can show the weakness, evidence and a recommended fix even before triage.
 */
export function adviseIssues(project, tool, result, buildFixPlan) {
  const items = normalize(tool, result, { sonarKey: project?.sonar_key });
  return (result.issues || []).map((iss, i) => {
    const f = items[i];
    if (!f) return iss;
    const kb = getCWE(f.cwe) || mapIssueToCWE({ message: f.message, rule: f.rule, type: f.type });
    const risk = riskFor(f, project, "Medium");
    const enriched = { ...f, cweName: kb?.name || null, toolGuidance: toolGuidance(f.raw), ...toolExtras(f.raw) };
    return {
      ...iss,
      cwe: iss.cwe || f.cwe, cweName: kb?.name || null,
      evidence: iss.evidence || collectEvidence(project, f),
      risk: risk.rating, riskScore: risk.score,
      fixPlan: buildFixPlan(enriched, risk.rating),
    };
  });
}

export { OPEN_LIKE, SUPPRESSED };
