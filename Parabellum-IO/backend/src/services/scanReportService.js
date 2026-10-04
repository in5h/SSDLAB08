/**
 * scanReportService.js
 *
 * Fetches the full SonarQube scan results after analysis and generates
 * a comprehensive JSON + YAML report saved to disk.
 *
 * Report includes:
 *  - Project info & scan metadata
 *  - Quality Gate status + all conditions
 *  - Project measures (complexity, coverage, duplications, LOC, etc.)
 *  - All issues paginated (bugs, vulnerabilities, code smells, security hotspots)
 *  - Summary statistics by severity and type
 */

import axios from "axios";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(__dirname, "..", "uploads", "reports");

// Ensure reports directory exists
fs.mkdirSync(REPORTS_DIR, { recursive: true });

function getSonarClient() {
    const baseURL = process.env.SONARQUBE_URL || "http://localhost:9000";
    const token = process.env.SONARQUBE_TOKEN || "";
    return axios.create({
        baseURL,
        auth: { username: token, password: "" },
        timeout: 30000,
    });
}

/** Fetch ALL issues for a project (handles pagination automatically) */
async function fetchAllIssues(client, projectKey) {
    const issues = [];
    let page = 1;
    const pageSize = 500;

    while (true) {
        const { data } = await client.get("/api/issues/search", {
            params: {
                componentKeys: projectKey,
                ps: pageSize,
                p: page,
                resolved: false,
                additionalFields: "rules,comments",
            },
        });

        issues.push(
            ...data.issues.map((i) => ({
                key: i.key,
                type: i.type,
                severity: i.severity,
                rule: i.rule,
                message: i.message,
                component: i.component.replace(`${projectKey}:`, ""),
                line: i.line || null,
                effort: i.effort || null,
                status: i.status,
                tags: i.tags || [],
                createdAt: i.creationDate,
            }))
        );

        const total = data.paging.total;
        if (page * pageSize >= total) break;
        page++;
    }

    await addRuleGuidance(client, issues);
    return issues;
}

// SonarQube's own rule documentation ("why is this an issue" / "how to fix it"), cached per rule
const ruleCache = new Map();
const htmlToText = (html) => String(html || "")
    .replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, (_, code) => `\n${code}\n`)
    .replace(/<(br|\/p|\/li|\/h\d)[^>]*>/gi, "\n").replace(/<li[^>]*>/gi, "• ")
    .replace(/<[^>]+>/g, "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&amp;/g, "&").replace(/\n{3,}/g, "\n\n").trim();

async function fetchRule(client, key) {
    if (ruleCache.has(key)) return ruleCache.get(key);
    let info = null;
    try {
        const { data } = await client.get("/api/rules/show", { params: { key } });
        const r = data.rule || {};
        const sections = r.descriptionSections || [];
        const pick = (k) => htmlToText(sections.filter(x => x.key === k).map(x => x.content).join("\n"));
        const howToFix = pick("how_to_fix");
        const rootCause = pick("root_cause");
        info = {
            ruleName: r.name || null,
            description: (rootCause || htmlToText(r.htmlDesc || r.mdDesc)).slice(0, 1500) || null,
            solution: howToFix ? howToFix.slice(0, 1500) : null,
            references: [...new Set((pick("resources") + " " + (r.htmlDesc || "")).match(/https?:\/\/[^\s"<>)]+/g) || [])].slice(0, 5),
        };
    } catch { /* rule docs are optional */ }
    ruleCache.set(key, info);
    return info;
}

/** Attach SonarQube's rule name, explanation and "how to fix" text to every issue. */
async function addRuleGuidance(client, issues) {
    const keys = [...new Set(issues.map(i => i.rule))];
    for (let i = 0; i < keys.length; i += 8) {
        await Promise.all(keys.slice(i, i + 8).map(k => fetchRule(client, k)));
    }
    for (const iss of issues) {
        const r = ruleCache.get(iss.rule);
        if (!r) continue;
        iss.ruleName = r.ruleName;
        if (r.description) iss.description = r.description;
        if (r.solution) iss.solution = r.solution;
        if (r.references?.length) iss.references = r.references;
    }
}

/** Fetch key project measures from SonarQube metrics API */
async function fetchMeasures(client, projectKey) {
    const metricKeys = [
        // Size
        "ncloc", "lines", "files", "classes", "functions", "statements",
        // Complexity
        "complexity", "cognitive_complexity",
        // Issues
        "violations", "bugs", "vulnerabilities", "code_smells",
        "blocker_violations", "critical_violations", "major_violations",
        "minor_violations", "info_violations",
        // Security
        "security_hotspots", "security_rating", "reliability_rating", "sqale_rating",
        // Coverage (if tests are present)
        "coverage", "line_coverage", "branch_coverage",
        "uncovered_lines", "uncovered_conditions",
        // Duplication
        "duplicated_lines_density", "duplicated_blocks", "duplicated_files",
    ].join(",");

    try {
        const { data } = await client.get("/api/measures/component", {
            params: { component: projectKey, metricKeys },
        });

        const measures = {};
        for (const m of data.component.measures || []) {
            measures[m.metric] = m.value === undefined ? (m.periods?.[0]?.value ?? null) : m.value;
        }
        return measures;
    } catch {
        return {};
    }
}

/** Fetch quality gate result */
async function fetchQualityGate(client, projectKey) {
    try {
        const { data } = await client.get("/api/qualitygates/project_status", {
            params: { projectKey },
        });
        return {
            status: data.projectStatus.status,
            conditions: (data.projectStatus.conditions || []).map((c) => ({
                metric: c.metricKey,
                status: c.status,
                operator: c.comparator,
                threshold: c.errorThreshold,
                actualValue: c.actualValue,
            })),
        };
    } catch {
        return { status: "UNKNOWN", conditions: [] };
    }
}

/** Build summary statistics from issues array */
function buildSummary(issues) {
    const bySeverity = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
    const byType = { BUG: 0, VULNERABILITY: 0, CODE_SMELL: 0, SECURITY_HOTSPOT: 0 };

    for (const i of issues) {
        if (i.severity in bySeverity) bySeverity[i.severity]++;
        if (i.type in byType) byType[i.type]++;
    }

    return { total: issues.length, bySeverity, byType };
}

/**
 * Helper to write YAML arrays
 */
function toYamlArray(pad, key, value) {
    const lines = [];
    if (value.length === 0) {
        lines.push(`${pad}${key}: []`);
    } else {
        lines.push(`${pad}${key}:`);
        for (const item of value) {
            if (typeof item === "object" && item !== null) {
                lines.push(
                    `${pad}  -`,
                    toYaml(item, pad.length / 2 + 2)
                        .split("\n")
                        .map((l) => "  " + l)
                        .join("\n")
                );
            } else {
                lines.push(`${pad}  - ${item}`);
            }
        }
    }
    return lines;
}

/**
 * Convert a plain JS object to YAML string (simple implementation,
 * handles the nested structures we produce without a heavy dependency).
 */
function toYaml(obj, indent = 0) {
    const pad = "  ".repeat(indent);
    const lines = [];

    for (const [key, value] of Object.entries(obj)) {
        if (value === null || value === undefined) {
            lines.push(`${pad}${key}: null`);
        } else if (Array.isArray(value)) {
            lines.push(...toYamlArray(pad, key, value));
        } else if (typeof value === "object") {
            lines.push(
                `${pad}${key}:`,
                toYaml(value, indent + 1)
            );
        } else {
            const safeVal = String(value).includes(":") || String(value).includes("#")
                ? '"' + String(value).replaceAll('"', String.raw`\"`) + '"'
                : value;
            lines.push(`${pad}${key}: ${safeVal}`);
        }
    }

    return lines.join("\n");
}

/**
 * Main export: generate and save the full scan report.
 *
 * @param {string} projectKey   - SonarQube project key
 * @param {string} projectName  - Human-readable project name
 * @param {object} compileInfo  - Result from javaCompileService (optional)
 * @returns {Promise<{ reportPath: string, yamlPath: string, report: object }>}
 */
export async function generateScanReport(projectKey, projectName, compileInfo = null) {
    const client = getSonarClient();
    console.log(`📊 Generating full scan report for ${projectKey}...`);

    // Fetch everything in parallel
    const [issues, measures, qualityGate] = await Promise.all([
        fetchAllIssues(client, projectKey),
        fetchMeasures(client, projectKey),
        fetchQualityGate(client, projectKey),
    ]);

    const summary = buildSummary(issues);
    const generatedAt = new Date().toISOString();

    const report = {
        meta: {
            generatedAt,
            projectKey,
            projectName,
            sonarqubeUrl: process.env.SONARQUBE_URL || "http://localhost:9000",
            reportVersion: "1.0",
        },
        compilation: compileInfo
            ? {
                method: compileInfo.method,
                success: compileInfo.success,
                binariesDir: compileInfo.binariesDir,
                note: compileInfo.success
                    ? "Full Java SAST performed (compiled classes available)"
                    : "Source-only Java analysis — some Java rules may not apply",
            }
            : null,
        qualityGate,
        measures,
        summary,
        issues,
    };

    // Save JSON report
    const safe = projectKey.replaceAll(/[^a-zA-Z0-9_-]/g, "_");
    const ts = generatedAt.replaceAll(/[:.]/g, "-").replaceAll("T", "_").substring(0, 19);
    const reportPath = path.join(REPORTS_DIR, `${safe}_${ts}.json`);
    const yamlPath = path.join(REPORTS_DIR, `${safe}_${ts}.yaml`);

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");
    fs.writeFileSync(yamlPath, `---\n${toYaml(report)}\n`, "utf8");

    console.log(`✅ Scan report saved:`);
    console.log(`   JSON → ${reportPath}`);
    console.log(`   YAML → ${yamlPath}`);

    return { reportPath, yamlPath, report };
}
