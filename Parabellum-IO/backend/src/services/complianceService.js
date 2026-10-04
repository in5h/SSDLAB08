/**
 * complianceService.js
 * Calculates NIST CSF 2.0 compliance score from SonarQube scan results.
 *
 * Scoring model:
 *   score = max(0, 100 − (blockers×20 + criticals×10 + majors×3 + minors×1 + infos×0.2))
 *
 * NIST CSF function scores are derived by mapping SonarQube rule types
 * and severities to the 6 NIST functions.
 */
import db from "../db/database.js";

/** Calculate overall compliance score from a summary object */
function calcOverallScore(summary) {
    if (!summary) return 0;
    const { bySeverity = {} } = summary;
    const penalty =
        (bySeverity.BLOCKER || 0) * 20 +
        (bySeverity.CRITICAL || 0) * 10 +
        (bySeverity.MAJOR || 0) * 3 +
        (bySeverity.MINOR || 0) * 1 +
        (bySeverity.INFO || 0) * 0.2;
    return Math.max(0, Math.round(100 - penalty));
}

/**
 * Estimate NIST CSF function scores from issues.
 * Maps issue types and severities to NIST functions:
 *   PROTECT  ← VULNERABILITY + SECURITY_HOTSPOT (main impact)
 *   DETECT   ← Missing logging rules, anomaly detection gaps
 *   IDENTIFY ← CODE_SMELL exposing architecture / data flows
 *   RESPOND  ← Error handling issues
 *   GOVERN   ← Project-level quality metrics
 *   RECOVER  ← Reliability / availability (BUG)
 */
function calcFunctionScores(issues = [], qualityGate = {}) {
    let protectPenalty = 0;
    let detectPenalty = 0;
    let identifyPenalty = 0;
    let respondPenalty = 0;
    let governPenalty = 0;
    let recoverPenalty = 0;

    const severityWeight = { BLOCKER: 20, CRITICAL: 10, MAJOR: 5, MINOR: 2, INFO: 0.5 };

    for (const issue of issues) {
        const w = severityWeight[issue.severity] || 1;
        const type = issue.type || "";
        const rule = (issue.rule || "").toLowerCase();
        const msg = (issue.message || "").toLowerCase();

        if (type === "VULNERABILITY" || type === "SECURITY_HOTSPOT") {
            protectPenalty += w;
        } else if (type === "BUG") {
            recoverPenalty += w * 0.6;
            respondPenalty += w * 0.4;
        } else if (type === "CODE_SMELL") {
            identifyPenalty += w * 0.5;
            governPenalty += w * 0.5;
        }

        // Logging / detection gaps
        if (rule.includes("log") || msg.includes("log") || msg.includes("audit")) {
            detectPenalty += w;
        }
        // Error handling
        if (msg.includes("exception") || msg.includes("error handling") || rule.includes("squid:s")) {
            respondPenalty += w * 0.3;
        }
    }

    const cap = (penalty, max = 70) => Math.max(0, Math.round(100 - Math.min(penalty, max)));

    return {
        govern: qualityGate?.status === "ERROR" ? 40 : cap(governPenalty, 40),
        identify: cap(identifyPenalty, 50),
        protect: cap(protectPenalty, 80),
        detect: cap(detectPenalty, 60),
        respond: cap(respondPenalty, 50),
        recover: cap(recoverPenalty, 60),
    };
}

/**
 * Calculate and persist compliance score for a project scan.
 *
 * @param {number} projectId
 * @param {number} scanId
 * @param {object} summary       - { total, bySeverity, byType }
 * @param {object} qualityGate   - { status, conditions }
 * @param {Array}  issues        - full issues array
 * @returns {object} compliance score record
 */
export function calculateAndSaveCompliance(projectId, scanId, summary, qualityGate, issues = []) {
    const overallScore = calcOverallScore(summary);
    const fnScores = calcFunctionScores(issues, qualityGate);
    const bySev = summary?.bySeverity || {};

    db.prepare(`
        INSERT INTO compliance_scores
            (project_id, scan_id, overall_score,
             nist_govern, nist_identify, nist_protect, nist_detect, nist_respond, nist_recover,
             total_issues, blockers, criticals, majors, minors, infos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        projectId, scanId, overallScore,
        fnScores.govern, fnScores.identify, fnScores.protect,
        fnScores.detect, fnScores.respond, fnScores.recover,
        summary?.total || 0,
        bySev.BLOCKER || 0, bySev.CRITICAL || 0,
        bySev.MAJOR || 0, bySev.MINOR || 0, bySev.INFO || 0
    );

    return {
        overall: overallScore,
        nistScores: fnScores,
        totalIssues: summary?.total || 0,
        bySeverity: bySev,
    };
}

/** Get the latest compliance score for a project */
export function getProjectCompliance(projectId) {
    return db.prepare(`
        SELECT * FROM compliance_scores
        WHERE project_id = ?
        ORDER BY calculated_at DESC LIMIT 1
    `).get(projectId);
}

/** Get all compliance scores for a user's projects (for dashboard) */
export function getUserComplianceSummary(userId) {
    const projects = db.prepare(`
        SELECT p.id, p.name,
               cs.overall_score, cs.nist_protect, cs.nist_detect,
               cs.total_issues, cs.blockers, cs.criticals, cs.calculated_at
        FROM projects p
        LEFT JOIN compliance_scores cs ON cs.project_id = p.id
            AND cs.id = (SELECT MAX(id) FROM compliance_scores WHERE project_id = p.id)
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    `).all(userId);

    const scored = projects.filter(p => p.overall_score !== null);
    const avgScore = scored.length
        ? Math.round(scored.reduce((s, p) => s + p.overall_score, 0) / scored.length)
        : null;

    return { projects, averageScore: avgScore };
}
