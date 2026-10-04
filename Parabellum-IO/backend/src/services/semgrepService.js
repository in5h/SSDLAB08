/**
 * semgrepService.js
 * Real Semgrep CLI integration — runs `semgrep scan --config auto --json`
 * against a project directory and parses the results.
 */

import path from "path";
import { runTool } from "./toolRunner.js";
import os from "os";
import fs from "fs";

// On Windows, semgrep may be installed in the user's Python Scripts dir
const SEMGREP_PATHS = [
  "semgrep",
  path.join(os.homedir(), "AppData", "Roaming", "Python", "Python314", "Scripts", "semgrep.exe"),
  path.join(os.homedir(), "AppData", "Roaming", "Python", "Python313", "Scripts", "semgrep.exe"),
  path.join(os.homedir(), "AppData", "Roaming", "Python", "Python312", "Scripts", "semgrep.exe"),
  path.join(os.homedir(), "AppData", "Roaming", "Python", "Python311", "Scripts", "semgrep.exe"),
];

/**
 * Get the python scripts directory for pysemgrep so it's on PATH.
 */
function getPythonScriptsDir() {
  const dirs = [
    path.join(os.homedir(), "AppData", "Roaming", "Python", "Python314", "Scripts"),
    path.join(os.homedir(), "AppData", "Roaming", "Python", "Python313", "Scripts"),
    path.join(os.homedir(), "AppData", "Roaming", "Python", "Python312", "Scripts"),
    path.join(os.homedir(), "AppData", "Roaming", "Python", "Python311", "Scripts"),
  ];
  return dirs.filter(d => {
    try { return fs.existsSync(d); } catch { return false; }
  });
}

/**
 * Check if semgrep CLI is available.
 * @returns {Promise<{available: boolean, version: string, path: string}>}
 */
export async function checkSemgrepAvailability() {
  for (const cmd of SEMGREP_PATHS) {
    try {
      const version = await runCommand(cmd, ["--version"], process.cwd(), 30000);
      return { available: true, version: version.trim(), path: cmd };
    } catch { /* try next */ }
  }
  return { available: false, version: null, path: null };
}

/**
 * Run a Semgrep scan on the given project directory.
 * @param {string} projectPath — absolute path to the project
 * @param {object} options — scan options
 * @returns {Promise<object>} — parsed scan results
 */
export async function runSemgrepScan(projectPath, options = {}) {
  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const { available, path: semgrepCmd } = await checkSemgrepAvailability();
  if (!available) {
    throw new Error("Semgrep is not installed or not found in PATH. Install with: pip install semgrep");
  }

  const timeout = options.timeout || 300000; // 5 min default
  // "auto" downloads rules from the Semgrep registry (needs internet). Set SEMGREP_CONFIG
  // to a local rules folder (e.g. a clone of github.com/semgrep/semgrep-rules) for offline demos.
  const config = options.config || process.env.SEMGREP_CONFIG || "auto";

  const args = [
    "scan",
    "--config", config,
    "--json",
    "--no-git-ignore",        // scan everything
    "--max-target-bytes", "1000000",
    projectPath,
  ];

  console.log(`   🔎 Running: ${semgrepCmd} ${args.join(" ")}`);

  const rawOutput = await runCommand(semgrepCmd, args, projectPath, timeout);

  // Semgrep outputs JSON to stdout
  let parsed;
  try {
    parsed = JSON.parse(rawOutput);
  } catch (e) {
    // Sometimes semgrep outputs non-JSON warnings before the JSON
    const jsonStart = rawOutput.indexOf("{");
    if (jsonStart >= 0) {
      parsed = JSON.parse(rawOutput.substring(jsonStart));
    } else {
      throw new Error("Failed to parse Semgrep output as JSON: " + rawOutput.substring(0, 500));
    }
  }

  return normalizeSemgrepResults(parsed, projectPath);
}

/**
 * Normalize Semgrep JSON output into Parabellum standard format.
 */
function normalizeSemgrepResults(raw, projectPath) {
  const results = raw.results || [];
  const errors = raw.errors || [];

  const issues = results.map((r, idx) => {
    const severity = mapSemgrepSeverity(r.extra?.severity || "WARNING");
    const cweIds = (r.extra?.metadata?.cwe || []);
    const owaspIds = (r.extra?.metadata?.owasp || []);

    return {
      key: `semgrep-${idx}-${r.check_id || "unknown"}`,
      tool: "Semgrep",
      type: mapSemgrepType(r.extra?.metadata?.category),
      severity,
      rule: r.check_id || "unknown",
      message: r.extra?.message || r.extra?.metadata?.message || "Semgrep finding",
      component: path.relative(projectPath, r.path || ""),
      line: r.start?.line || null,
      endLine: r.end?.line || null,
      column: r.start?.col || null,
      snippet: r.extra?.lines || "",
      cwe: cweIds,
      owasp: owaspIds,
      confidence: r.extra?.metadata?.confidence || "MEDIUM",
      fix: r.extra?.fix || null,
      references: r.extra?.metadata?.references || [],
      category: r.extra?.metadata?.category || "security",
    };
  });

  // Build summary
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  const typeCounts = { VULNERABILITY: 0, BUG: 0, CODE_SMELL: 0, SECURITY_HOTSPOT: 0 };
  for (const iss of issues) {
    sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
    typeCounts[iss.type] = (typeCounts[iss.type] || 0) + 1;
  }

  return {
    tool: "Semgrep",
    total: issues.length,
    issues,
    errors: errors.map(e => ({ type: e.type, message: e.message, path: e.path })),
    summary: {
      total: issues.length,
      ...sevCounts,
      ...typeCounts,
    },
    scannedAt: new Date().toISOString(),
  };
}

/**
 * Map Semgrep severity to SonarQube-style severity.
 */
function mapSemgrepSeverity(semgrepSev) {
  const map = {
    "ERROR": "CRITICAL",
    "WARNING": "MAJOR",
    "INFO": "MINOR",
    "INVENTORY": "INFO",
    "EXPERIMENT": "MINOR",
  };
  return map[semgrepSev?.toUpperCase()] || "MAJOR";
}

/**
 * Map Semgrep category to SonarQube-style type.
 */
function mapSemgrepType(category) {
  if (!category) return "CODE_SMELL";
  const cat = category.toLowerCase();
  if (cat.includes("security") || cat.includes("vuln")) return "VULNERABILITY";
  if (cat.includes("bug") || cat.includes("error") || cat.includes("correctness")) return "BUG";
  if (cat.includes("best-practice") || cat.includes("style")) return "CODE_SMELL";
  return "SECURITY_HOTSPOT";
}

/**
 * Run semgrep and return stdout. Exit code 1 means "findings found", which is fine.
 */
async function runCommand(cmd, args, cwd, timeout = 60000) {
  // Add Python Scripts dirs to PATH so pysemgrep is found, and skip the online
  // version check (it hangs for a long time when the internet is slow/blocked).
  const env = {
    ...process.env,
    PATH: [...getPythonScriptsDir(), process.env.PATH].join(path.delimiter),
    SEMGREP_ENABLE_VERSION_CHECK: "0",
  };
  const { code, stdout, stderr } = await runTool(cmd, args, { cwd, timeout, env });
  if (code === 0 || code === 1) return stdout;
  throw new Error(`${cmd} exited with code ${code}: ${stderr.substring(0, 1000)}`);
}
