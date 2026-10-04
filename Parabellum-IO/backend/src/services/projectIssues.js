/**
 * projectIssues.js — One list of open issues per project for Risk Analysis and
 * Compliance Mapping, built from the unified findings of ALL tools
 * (SonarQube, Semgrep, Snyk, Trivy, OWASP ZAP, Anchore). Falls back to the
 * project's SonarQube issues only when no tool results are stored yet.
 */
import db from "../db/database.js";
import { listFindings } from "./findingService.js";
import { refreshMappings } from "./pipelineService.js";
import { getIssues } from "./sonarService.js";
import { FRAMEWORKS } from "./ragRecommendService.js";

// Context-aware risk rating → SonarQube-style severity used by the risk/compliance scoring
const SONAR_SEV = { Critical: "CRITICAL", High: "MAJOR", Medium: "MINOR", Low: "INFO", Info: "INFO" };

export function findingCount(projectId) {
  return db.prepare("SELECT COUNT(*) n FROM findings WHERE project_id = ? AND status IN ('Open','In Progress')").get(projectId).n;
}

/**
 * @returns {Promise<{ issues: object[], source: string, tools: string[] }>}
 *   issues — Sonar-shaped issues (key, type, severity, rule, message, component, line)
 *            plus tool, cwe, risk and the framework mappings of the finding
 */
export async function loadProjectIssues(project) {
  if (findingCount(project.id) > 0) {
    await refreshMappings(project.id, { onlyMissing: true });
    // Cross-tool duplicates are counted once (they are merged into their primary finding)
    const open = listFindings(project.id).filter(f => ["Open", "In Progress"].includes(f.status) && !f.duplicateOf);
    const issues = open.map(f => ({
      key: `F${f.id}`,
      findingId: f.id,
      type: f.package_name ? "VULNERABILITY" : f.url ? "VULNERABILITY" : f.type,
      severity: SONAR_SEV[f.risk] || "MINOR",
      rule: f.rule,
      message: `[${f.tool}] ${f.message || f.title}`,
      component: f.url || f.file || (f.package_name ? `${f.package_name}@${f.installed_version}` : ""),
      line: f.line,
      tool: f.tool,
      cwe: f.cwe,
      category: f.category,
      risk: f.risk, riskScore: f.riskScore, confidence: f.confidence,
      mappings: f.mappings,
    }));
    return { issues, source: "all-tools", tools: [...new Set(open.map(f => f.tool))] };
  }
  if (project.sonar_key) {
    const data = await getIssues(project.sonar_key, { pageSize: 500 });
    return { issues: data.issues || [], source: "sonarqube", tools: ["SonarQube"] };
  }
  return { issues: [], source: "none", tools: [] };
}

/** Framework control ids for one unified issue, in the grcMappingService shape (all 6 frameworks). */
export function grcFromMappings(mappings) {
  if (!mappings?.frameworks) return null;
  const out = {};
  for (const [fw, meta] of Object.entries(FRAMEWORKS)) {
    out[meta.grcKey] = (mappings.frameworks[fw]?.controls || []).map(c => c.id);
  }
  return out;
}

/** Projects the user can analyse: any project with tool results or a SonarQube scan. */
export function analysableProjects(userId) {
  return db.prepare(`SELECT p.id, p.name, p.sonar_key, p.source_type AS type,
      (SELECT COUNT(*) FROM findings f WHERE f.project_id = p.id AND f.status IN ('Open','In Progress')) AS openFindings,
      (SELECT GROUP_CONCAT(DISTINCT f.tool) FROM findings f WHERE f.project_id = p.id) AS tools
    FROM projects p WHERE p.user_id = ? ORDER BY p.created_at DESC`).all(userId)
    .map(r => ({ ...r, tools: r.tools ? r.tools.split(",") : [], needsScan: !r.sonar_key && !r.openFindings && !r.tools }));
}
