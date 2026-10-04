/**
 * reportService.js — Builds the final security & compliance report for a project
 * from the unified findings of all tools (not only SonarQube / NIST CSF).
 */
import db from "../db/database.js";
import { listFindings, findingHistory } from "./findingService.js";
import { buildFixPlan } from "./remediationService.js";
import { FRAMEWORKS, ragOnline } from "./ragRecommendService.js";
import { refreshMappings, listRuns, TOOL_ORDER } from "./pipelineService.js";
import { isGeminiConfigured } from "./geminiClient.js";

const RISK_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const OPEN = ["Open", "In Progress"];

// Which weakness families each tool type can find — used for the coverage / false-negative view
const CATEGORY_OF = f => {
  if (f.package_name) return "Vulnerable dependencies";
  if (f.url) return "Running web app (headers, cookies, CSRF)";
  if (["CWE-798", "CWE-200"].includes(f.cwe) && /secret|password|key|token|\.env/i.test(`${f.message} ${f.file}`)) return "Secrets";
  if (["CWE-250", "CWE-829"].includes(f.cwe) || /docker/i.test(f.file || "")) return "Container / IaC configuration";
  if (["CWE-89", "CWE-94", "CWE-79", "CWE-22", "CWE-611", "CWE-918"].includes(f.cwe)) return "Injection & XSS";
  return "Other code weaknesses";
};
const EXPECTED_TOOLS = {
  "Vulnerable dependencies": ["Snyk", "Trivy", "Anchore"],
  "Running web app (headers, cookies, CSRF)": ["OWASP ZAP"],
  "Secrets": ["Semgrep", "Trivy", "SonarQube"],
  "Container / IaC configuration": ["Trivy", "Anchore", "Semgrep", "SonarQube"],
  "Injection & XSS": ["SonarQube", "Semgrep"],
  "Other code weaknesses": ["SonarQube", "Semgrep"],
};

function businessImpact(f, project) {
  const exposure = project.internet_facing ? "an internet-facing" : "an internal";
  const data = project.data_classification || "Internal";
  return `${f.cweName || f.title} in ${exposure} ${String(project.asset_type || "application").toLowerCase()} ` +
    `(${project.environment || "Development"}, ${data} data, business criticality ${project.business_criticality || "Medium"}). ` +
    `Business owner: ${project.business_owner || "not assigned"}.`;
}

export async function buildReport(projectId, user) {
  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(projectId);
  await refreshMappings(projectId, { onlyMissing: true });
  const all = listFindings(projectId);
  const runs = listRuns(projectId);
  const pipelineRuns = runs.filter(r => r.trigger !== "single");
  const latest = runs[0] || null;
  const previous = runs[1] || null;

  const security = all.filter(f => f.category === "Security");
  // Cross-tool duplicates are merged into their primary finding ("also found by …")
  const duplicates = security.filter(f => OPEN.includes(f.status) && f.duplicateOf);
  const open = security.filter(f => OPEN.includes(f.status) && !f.duplicateOf)
    .sort((a, b) => b.riskScore - a.riskScore || RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk));
  const byRisk = Object.fromEntries(RISK_ORDER.map(r => [r, open.filter(f => f.risk === r).length]));

  // ── per-finding details (same layout for every section of the report) ──
  const today = new Date().toISOString().slice(0, 10);
  const detail = (f, ref) => {
    const plan = buildFixPlan(f, f.risk);
    return {
      ref,
      id: f.id, title: f.title, message: f.message, category: f.category, tool: f.tool, engine: f.engine,
      corroboratedBy: f.corroboratedBy, rule: f.rule, ruleName: f.ruleName, cwe: f.cwe, cweName: f.cweName,
      severity: f.severity, risk: f.risk, riskScore: f.riskScore,
      confidence: f.confidence, confidenceReasons: f.confidenceReasons,
      location: f.url || (f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.package_name ? `${f.package_name}@${f.installed_version}` : "—"),
      package: f.package_name ? { name: f.package_name, installed: f.installed_version, fixed: f.fixed_version } : null,
      description: f.description, references: f.references,
      evidence: f.evidence,
      businessImpact: businessImpact(f, project),
      mappings: f.mappings,
      recommendation: f.recommendation, recommendationSource: f.rec_source,
      fixPlan: plan,
      owner: f.owner || project.business_owner || "Unassigned",
      status: f.status, dueDate: f.due_date, note: f.triage_note || null,
      overdue: OPEN.includes(f.status) && f.due_date ? f.due_date < today : false,
      firstSeenRun: f.first_seen_run, lastSeenRun: f.last_seen_run, fixedRun: f.fixed_run, fixedAt: f.fixed_at,
      history: findingHistory(f.id),
    };
  };
  const byRiskScore = (a, b) => b.riskScore - a.riskScore || RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk);
  const details = open.map((f, i) => detail(f, `F-${String(i + 1).padStart(3, "0")}`));
  const codeQuality = all.filter(f => f.category === "Code Quality" && OPEN.includes(f.status)).sort(byRiskScore)
    .map((f, i) => detail(f, `Q-${String(i + 1).padStart(3, "0")}`));
  const refById = new Map(details.map(d => [d.id, d.ref]));
  const duplicateDetails = duplicates.map((f, i) => ({ ...detail(f, `D-${String(i + 1).padStart(3, "0")}`), duplicateOfRef: refById.get(f.duplicateOf) || null }));
  const awaitingVerification = all.filter(f => f.status === "Fixed").sort(byRiskScore)
    .map((f, i) => detail(f, `W-${String(i + 1).padStart(3, "0")}`));
  const fixedDetails = all.filter(f => f.status === "Verified Fixed")
    .sort((a, b) => (b.fixed_run || 0) - (a.fixed_run || 0) || byRiskScore(a, b))
    .map((f, i) => detail(f, `V-${String(i + 1).padStart(3, "0")}`));
  const suppressedDetails = all.filter(f => ["False Positive", "Accepted Risk"].includes(f.status)).sort(byRiskScore)
    .map((f, i) => detail(f, `S-${String(i + 1).padStart(3, "0")}`));
  const shortFix = d => d.fixPlan.toolAdvice
    ? d.fixPlan.toolAdvice.split("\n").filter(Boolean)[0].slice(0, 220)
    : (d.fixPlan.steps.find(st => !/^(Locate|Open) /.test(st)) || d.fixPlan.steps[0]);
  // Complete register: every finding the tools reported, whatever its status
  const register = [...details, ...duplicateDetails, ...codeQuality, ...awaitingVerification, ...fixedDetails, ...suppressedDetails].map(d => ({
    ref: d.ref, title: d.title, category: d.category, tool: d.tool, location: d.location, risk: d.risk,
    status: d.duplicateOfRef ? `${d.status} (merged into ${d.duplicateOfRef})` : d.status, owner: d.owner, dueDate: d.dueDate, fix: shortFix(d),
  }));

  // ── compliance per framework (controls affected by open findings) ──
  const compliance = Object.entries(FRAMEWORKS).map(([key, meta]) => {
    const controls = new Map();
    for (const d of details) {
      for (const c of d.mappings?.frameworks?.[key]?.controls || []) {
        if (!controls.has(c.id)) controls.set(c.id, { id: c.id, title: c.title, group: c.group, findings: [], worst: "Info" });
        const e = controls.get(c.id);
        e.findings.push(d.ref);
        if (RISK_ORDER.indexOf(d.risk) < RISK_ORDER.indexOf(e.worst)) e.worst = d.risk;
      }
    }
    return { key, label: meta.label, controlsAffected: controls.size,
      controls: [...controls.values()].sort((a, b) => RISK_ORDER.indexOf(a.worst) - RISK_ORDER.indexOf(b.worst) || b.findings.length - a.findings.length) };
  });
  const owaspTop10 = new Map();
  for (const d of details) for (const o of d.mappings?.owaspTop10 || []) {
    if (!owaspTop10.has(o.id)) owaspTop10.set(o.id, { ...o, findings: [] });
    owaspTop10.get(o.id).findings.push(d.ref);
  }

  // ── accuracy: true positives / false positives / false negatives ──
  const triagedFP = security.filter(f => f.status === "False Positive");
  const accepted = security.filter(f => f.status === "Accepted Risk");
  const confidence = { High: 0, Medium: 0, Low: 0 };
  for (const f of open) confidence[f.confidence]++;
  const toolsRun = [...new Set(security.map(f => f.tool.replace(" (built-in)", "")))];
  const nativeTools = new Set(security.filter(f => f.engine !== "built-in").map(f => f.tool));
  const lastPipelineTools = pipelineRuns[0]?.stages?.filter(s => s.status === "done") || [];
  const ranNative = new Set(lastPipelineTools.filter(s => s.engine !== "built-in").map(s => s.name));
  for (const t of nativeTools) ranNative.add(t);
  const coverage = Object.entries(EXPECTED_TOOLS).map(([cat, tools]) => {
    const found = open.filter(f => CATEGORY_OF(f) === cat);
    const byTool = {};
    for (const f of found) { const t = f.tool.replace(" (built-in)", ""); byTool[t] = (byTool[t] || 0) + 1; }
    const covering = tools.filter(t => ranNative.has(t));
    return { category: cat, findings: found.length, byTool, expectedTools: tools, coveredBy: covering,
      gap: covering.length === 0 ? `No native ${tools.join("/")} scan ran — issues of this type may be missed (false negatives).` : null };
  });
  const uniqueToTool = {};
  for (const f of open) if (!f.corroboratedBy.length) {
    const t = f.tool.replace(" (built-in)", "");
    uniqueToTool[t] = (uniqueToTool[t] || 0) + 1;
  }

  // ── fix verification (latest run vs earlier) ──
  const verifiedFixed = security.filter(f => ["Verified Fixed"].includes(f.status));
  const fixVerification = {
    latestRun: latest ? { id: latest.id, trigger: latest.trigger, status: latest.status, startedAt: latest.started_at, finishedAt: latest.finished_at, summary: latest.summary, stages: latest.stages } : null,
    previousRun: previous ? { id: previous.id, startedAt: previous.started_at, summary: previous.summary } : null,
    fixedInLatest: latest ? verifiedFixed.filter(f => f.fixed_run === latest.id).map(f => ({ title: f.title, tool: f.tool, location: f.file || f.url || f.package_name, fixedAt: f.fixed_at })) : [],
    newInLatest: latest ? open.filter(f => f.first_seen_run === latest.id).length : 0,
    verifiedFixedTotal: verifiedFixed.map(f => ({ title: f.title, tool: f.tool, location: f.file || f.url || f.package_name, run: f.fixed_run, fixedAt: f.fixed_at })),
    runs: runs.slice(0, 15).map(r => ({ id: r.id, trigger: r.trigger, status: r.status, startedAt: r.started_at, tools: r.tools, summary: r.summary })),
  };

  const gate = open.some(f => ["Critical", "High"].includes(f.risk) && f.confidence !== "Low") ? "FAIL" : "PASS";
  const ragUp = await ragOnline();

  return {
    meta: {
      reportId: `PB-${project.id}-${Date.now().toString(36).toUpperCase()}`,
      generatedAt: new Date().toISOString(),
      generatedBy: user?.name || user?.email || "Parabellum IO",
      recommendationEngine: `${ragUp ? "RAG service (embeddings + ChromaDB)" : "Built-in BM25 retriever"} + ${isGeminiConfigured() ? "Gemini generation" : "template generation (set GEMINI_API_KEY for AI-written advice)"}`,
    },
    asset: {
      project: project.name, assetName: project.asset_name || project.name, assetType: project.asset_type,
      environment: project.environment, dataClassification: project.data_classification,
      businessOwner: project.business_owner || "Not assigned", businessCriticality: project.business_criticality,
      internetFacing: !!project.internet_facing, description: project.description || "", targetUrl: project.target_url || null,
    },
    executive: {
      gate,
      openSecurityFindings: open.length,
      byRisk,
      overdue: details.filter(d => d.overdue).length,
      verifiedFixed: verifiedFixed.length,
      falsePositives: triagedFP.length,
      acceptedRisks: accepted.length,
      codeQualityIssues: codeQuality.length,
      awaitingVerification: awaitingVerification.length,
      totalFindings: register.length,
      frameworksAffected: compliance.map(c => ({ label: c.label, controlsAffected: c.controlsAffected })),
      topRisks: details.slice(0, 5).map(d => ({ ref: d.ref, title: d.title, risk: d.risk, location: d.location, owner: d.owner, due: d.dueDate })),
      toolsUsed: toolsRun,
    },
    methodology: {
      tools: TOOL_ORDER,
      riskFormula: "Risk score (0–10) = base (tool severity averaged with the weakness' typical CVSS) × likelihood (internet exposure × environment) × business impact (criticality + data classification) × confidence; ≥8.5 Critical, ≥6.5 High, ≥4 Medium, ≥2 Low.",
      confidenceModel: "Base confidence by tool type (dependency/DAST scanners higher, built-in heuristics lower) +0.25 when another tool reports the same weakness at the same place, −0.25 for test/example/vendor paths, −0.2 for code-quality rules; analyst 'False Positive' decisions are remembered across rescans.",
      sla: "Fix within: Critical 7 days, High 30, Medium 90, Low 180.",
    },
    accuracy: { confidence, corroborated: open.filter(f => f.corroboratedBy.length).length,
      mergedDuplicates: duplicateDetails.map(d => ({ ref: d.ref, title: d.title, tool: d.tool, location: d.location, mergedInto: d.duplicateOfRef })),
      likelyFalsePositives: open.filter(f => f.likelyFalsePositive).length,
      triagedFalsePositives: triagedFP.map(f => ({ title: f.title, tool: f.tool, note: f.triage_note })),
      uniqueToTool, coverage },
    findings: details,
    codeQuality,
    awaitingVerification,
    fixedFindings: fixedDetails,
    suppressedFindings: suppressedDetails,
    register,
    compliance, owaspTop10: [...owaspTop10.values()],
    remediationPlan: [...details, ...codeQuality, ...awaitingVerification].map(d => ({ ref: d.ref, title: d.title, category: d.category, risk: d.risk, priority: d.fixPlan.priority,
      owner: d.owner, dueDate: d.dueDate, effort: d.fixPlan.effort, status: d.status, overdue: d.overdue, fix: shortFix(d) })),
    fixVerification,
    acceptedRisks: accepted.map(f => ({ title: f.title, tool: f.tool, owner: f.owner, note: f.triage_note })),
  };
}
