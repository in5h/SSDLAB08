/**
 * snykService.js
 * Real Snyk CLI integration — runs `snyk test --all-projects --json` against a project
 * directory and parses the vulnerability results. Works for every ecosystem Snyk
 * supports (npm/yarn, Maven/Gradle, pip/Poetry, Go, NuGet, …).
 */

import path from "path";
import fs from "fs";
import { runTool, getToolVersion, parseJsonOutput } from "./toolRunner.js";

const SNYK = process.env.SNYK_PATH || "snyk";
const NOT_INSTALLED_MSG = "Snyk CLI is not installed. Install it with: npm install -g snyk — then run: snyk auth (or set SNYK_TOKEN in backend/.env).";

/**
 * Check if Snyk CLI is available and authenticated.
 * @returns {Promise<{available: boolean, version: string|null, authenticated: boolean}>}
 */
export async function checkSnykAvailability() {
  const version = await getToolVersion(SNYK, ["--version"]);
  if (!version) return { available: false, version: null, authenticated: false, error: NOT_INSTALLED_MSG };

  let authenticated = !!process.env.SNYK_TOKEN;
  if (!authenticated) {
    try {
      const { code } = await runTool(SNYK, ["whoami", "--experimental"], { timeout: 15000 });
      authenticated = code === 0;
    } catch { /* not authenticated */ }
  }
  return {
    available: true,
    version,
    authenticated,
    error: authenticated ? undefined : "Snyk is installed but not logged in. Run: snyk auth (or set SNYK_TOKEN).",
  };
}

/**
 * Run a Snyk test on the given project directory.
 * @param {string} projectPath — absolute path to the project
 * @param {object} options — scan options
 * @returns {Promise<object>} — parsed scan results
 */
export async function runSnykScan(projectPath, options = {}) {
  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const args = ["test", "--json", "--all-projects"];
  if (options.severityThreshold) {
    args.push(`--severity-threshold=${options.severityThreshold}`);
  }

  console.log(`   📦 Running: snyk ${args.join(" ")}`);

  let result;
  try {
    result = await runTool(SNYK, args, { cwd: projectPath, timeout: options.timeout || 300000 });
  } catch (err) {
    if (err.notInstalled) throw new Error(NOT_INSTALLED_MSG);
    throw err;
  }

  // Exit codes: 0 = no issues, 1 = issues found, 2 = error, 3 = no supported manifest
  if (result.code === 3) {
    throw new Error("Snyk found no supported dependency manifest (package.json, pom.xml, build.gradle, requirements.txt, go.mod, …). Note: Python/Java projects may need their dependencies installed first.");
  }
  if (!result.stdout.trim()) {
    throw new Error(`Snyk failed (exit ${result.code}): ${result.stderr.substring(0, 800)}`);
  }

  const parsed = parseJsonOutput(result.stdout, "Snyk");
  if (result.code === 2 && !Array.isArray(parsed) && parsed.error) {
    throw new Error(`Snyk error: ${parsed.error}`);
  }

  // --all-projects returns an array when more than one manifest is found
  const results = Array.isArray(parsed) ? parsed : [parsed];
  return mergeSnykResults(results.map(r => normalizeSnykResults(r, projectPath)), projectPath);
}

function mergeSnykResults(list, projectPath) {
  if (list.length === 1) return list[0];
  const issues = list.flatMap(r => r.issues);
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  for (const iss of issues) sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
  return {
    tool: "Snyk",
    total: issues.length,
    issues,
    errors: list.flatMap(r => r.errors),
    summary: {
      total: issues.length,
      ...sevCounts,
      uniqueVulns: list.reduce((a, r) => a + (r.summary.uniqueVulns || 0), 0),
      fixableCount: issues.filter(i => i.isPatchable || i.isUpgradable).length,
      uniquePackages: new Set(issues.map(i => i.packageName)).size,
      dependencyCount: list.reduce((a, r) => a + (r.summary.dependencyCount || 0), 0),
    },
    projectName: path.basename(projectPath),
    packageManager: [...new Set(list.map(r => r.packageManager))].join(", "),
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Normalize Snyk JSON output into Parabellum standard format.
 */
function normalizeSnykResults(raw, projectPath) {
  // Handle Snyk error responses
  if (raw.error) {
    return {
      tool: "Snyk",
      total: 0,
      issues: [],
      errors: [{ type: "SNYK_ERROR", message: raw.error }],
      summary: { total: 0 },
      scannedAt: new Date().toISOString(),
      projectName: raw.projectName || path.basename(projectPath),
    };
  }

  const vulnerabilities = raw.vulnerabilities || [];
  const uniqueVulns = raw.uniqueCount || vulnerabilities.length;

  const issues = vulnerabilities.map((v, idx) => {
    const severity = mapSnykSeverity(v.severity);
    const cweIds = (v.identifiers?.CWE || []);
    const cveIds = (v.identifiers?.CVE || []);

    return {
      key: `snyk-${raw.displayTargetFile || ""}-${idx}-${v.id || "unknown"}`,
      tool: "Snyk",
      type: "VULNERABILITY",
      severity,
      rule: v.id || "unknown",
      message: v.title || "Snyk vulnerability",
      component: v.from ? v.from.join(" → ") : (v.packageName || ""),
      packageName: v.packageName || v.name || "",
      packageVersion: v.version || "",
      line: null,
      cwe: cweIds,
      cve: cveIds,
      cvssScore: v.cvssScore || null,
      exploitMaturity: v.exploit || "No Known Exploit",
      fixedIn: v.fixedIn || [],
      upgradePath: v.upgradePath || [],
      isPatchable: v.isPatchable || false,
      isUpgradable: v.isUpgradable || false,
      references: v.references || [],
      description: v.description || "",
      language: v.language || "js",
      severity_original: v.severity,
    };
  });

  // Build summary
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  for (const iss of issues) {
    sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
  }

  // Snyk-specific metrics
  const fixableCount = issues.filter(i => i.isPatchable || i.isUpgradable).length;
  const uniquePackages = [...new Set(issues.map(i => i.packageName))];

  return {
    tool: "Snyk",
    total: issues.length,
    issues,
    errors: [],
    summary: {
      total: issues.length,
      ...sevCounts,
      uniqueVulns: uniqueVulns,
      fixableCount,
      uniquePackages: uniquePackages.length,
      dependencyCount: raw.dependencyCount || 0,
    },
    projectName: raw.projectName || path.basename(projectPath),
    packageManager: raw.packageManager || "npm",
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Map Snyk severity to SonarQube-style severity.
 */
function mapSnykSeverity(snykSev) {
  const map = {
    "critical": "CRITICAL",
    "high": "MAJOR",
    "medium": "MINOR",
    "low": "INFO",
  };
  return map[snykSev?.toLowerCase()] || "MINOR";
}
