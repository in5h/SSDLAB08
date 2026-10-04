/**
 * trivyService.js
 * Trivy Container & File System Vulnerability Scanner.
 * Runs the real Trivy CLI when it is installed. If it is not installed, the
 * user can still run Parabellum's small built-in Dockerfile/config checks —
 * these are clearly labelled and are NOT a Trivy scan (no CVE database).
 */

import path from "path";
import fs from "fs";
import { runTool, getToolVersion, parseJsonOutput } from "./toolRunner.js";

const TRIVY = process.env.TRIVY_PATH || "trivy";

/**
 * Check if Trivy CLI is available.
 * @returns {Promise<{available: boolean, version: string|null, builtInFallback: boolean}>}
 */
export async function checkTrivyAvailability() {
  const version = await getToolVersion(TRIVY, ["--version"]);
  return { available: !!version, version, builtInFallback: true };
}

/**
 * Run Trivy scan on project directory.
 */
export async function runTrivyScan(projectPath, options = {}) {
  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const { available } = await checkTrivyAvailability();
  if (!available) {
    console.log(`   🐳 Trivy not installed — running built-in container/config checks on ${projectPath}`);
    return {
      ...runLocalTrivyScanEngine(projectPath),
      engine: "built-in",
      warning: "Trivy is not installed, so only Parabellum's basic Dockerfile/config checks ran. No CVE database was used. Install Trivy (https://trivy.dev) for a real scan.",
    };
  }

  // Real Trivy: dependency CVEs + IaC misconfigurations + secrets.
  // The first run downloads the vulnerability DB, so allow plenty of time.
  const { code, stdout, stderr } = await runTool(
    TRIVY,
    ["fs", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", projectPath],
    { cwd: projectPath, timeout: options.timeout || 600000 }
  );
  if (code !== 0) {
    throw new Error(`Trivy failed (exit ${code}): ${stderr.substring(0, 800)}`);
  }
  return { ...normalizeTrivyCliResults(parseJsonOutput(stdout, "Trivy"), projectPath), engine: "trivy" };
}

/**
 * Normalize real Trivy CLI JSON output
 */
function normalizeTrivyCliResults(raw, projectPath) {
  const results = raw.Results || [];
  const issues = [];

  for (const res of results) {
    const target = res.Target || "filesystem";
    const vulns = res.Vulnerabilities || [];
    const misconfigs = res.Misconfigurations || [];
    const secrets = res.Secrets || [];

    for (const sec of secrets) {
      issues.push({
        key: `trivy-${sec.RuleID}-${target}-${sec.StartLine}`,
        tool: "Trivy",
        type: "VULNERABILITY",
        severity: mapTrivySeverity(sec.Severity),
        rule: sec.RuleID,
        message: `Secret detected: ${sec.Title}`,
        component: target,
        line: sec.StartLine || null,
        cwe: ["CWE-798"],
        target,
      });
    }

    for (const v of vulns) {
      issues.push({
        key: `trivy-${v.VulnerabilityID}-${v.PkgName}-${target}`,
        tool: "Trivy",
        type: "VULNERABILITY",
        severity: mapTrivySeverity(v.Severity),
        rule: v.VulnerabilityID,
        message: `${v.PkgName} (${v.InstalledVersion}) - ${v.Title || v.Description || "Container/Package Vulnerability"}`,
        component: target,
        line: null,
        cve: [v.VulnerabilityID],
        cwe: (v.CweIDs || ["CWE-937"]),
        installedVersion: v.InstalledVersion,
        fixedVersion: v.FixedVersion || "N/A",
        primaryUrl: v.PrimaryURL || "",
        pkgName: v.PkgName,
        target: target,
      });
    }

    for (const m of misconfigs) {
      issues.push({
        key: `trivy-${m.ID}-${target}-${m.CauseMetadata?.StartLine || 0}`,
        tool: "Trivy",
        type: "SECURITY_HOTSPOT",
        severity: mapTrivySeverity(m.Severity),
        rule: m.ID,
        message: `${m.Title} - ${m.Message || m.Description}`,
        component: target,
        line: m.CauseMetadata?.StartLine || null,
        cwe: ["CWE-16"],
        resolution: m.Resolution || "",
        target: target,
      });
    }
  }

  return formatTrivyResponse(issues, projectPath);
}

/**
 * Local Trivy Container & FS Security Engine
 */
function runLocalTrivyScanEngine(projectPath) {
  const issues = [];
  const files = getFilesRecursively(projectPath);

  const dockerfiles = files.filter(f => path.basename(f).toLowerCase().includes("dockerfile"));
  // Real env files only (.env, .env.production …) — not .env.example templates
  const envFiles = files.filter(f => /^\.env(\..+)?$/.test(path.basename(f)) && !/example|sample|template/i.test(path.basename(f)));
  const packageJsonFiles = files.filter(f => path.basename(f) === "package.json");

  // 1. Dockerfile Analysis
  // No Dockerfile → container checks are simply not applicable (not a finding)
  if (dockerfiles.length > 0) {
    for (const df of dockerfiles) {
      const relPath = path.relative(projectPath, df);
      const content = fs.readFileSync(df, "utf8");
      const lines = content.split("\n");

      let hasUser = false;
      let hasHealthcheck = false;

      lines.forEach((line, idx) => {
        const trimmed = line.trim();

        // Check base image
        if (trimmed.startsWith("FROM ")) {
          const image = trimmed.substring(5).trim();
          if (image.includes(":latest") || !image.includes(":")) {
            issues.push({
              key: `trivy-DS002-${idx}`,
              tool: "Built-in checks",
              type: "VULNERABILITY",
              severity: "CRITICAL",
              rule: "PB-CONTAINER-002",
              message: `Base image '${image}' uses untagged or ':latest' tag — risks non-deterministic builds and unvetted container updates.`,
              component: relPath,
              line: idx + 1,
              cwe: ["CWE-829"],
              pkgName: image,
              installedVersion: "latest",
              fixedVersion: "Use specific digest or release tag (e.g. node:20-alpine)",
            });
          }
        }

        if (trimmed.startsWith("USER ")) {
          hasUser = true;
        }

        if (trimmed.startsWith("HEALTHCHECK ")) {
          hasHealthcheck = true;
        }

        // Sensitive environment variables exposed in ENV
        if (trimmed.startsWith("ENV ") && (trimmed.includes("PASS") || trimmed.includes("SECRET") || trimmed.includes("KEY"))) {
          issues.push({
            key: `trivy-DS003-${idx}`,
            tool: "Built-in checks",
            type: "VULNERABILITY",
            severity: "CRITICAL",
            rule: "PB-SECRET-001",
            message: `Hardcoded secret/password exposed in Dockerfile ENV instruction: ${trimmed.substring(0, 30)}...`,
            component: relPath,
            line: idx + 1,
            cwe: ["CWE-798"],
            resolution: "Use Docker Secrets or environment variables injected at runtime.",
          });
        }
      });

      if (!hasUser) {
        issues.push({
          key: `trivy-DS004-${relPath}`,
          tool: "Built-in checks",
          type: "VULNERABILITY",
          severity: "MAJOR",
          rule: "PB-CONTAINER-003",
          message: "Container runs as root user by default — vulnerable to container escape attacks.",
          component: relPath,
          line: lines.length,
          cwe: ["CWE-250"],
          resolution: "Add 'USER node' or 'USER 10001' before CMD instruction.",
        });
      }

      if (!hasHealthcheck) {
        issues.push({
          key: `trivy-DS005-${relPath}`,
          tool: "Built-in checks",
          type: "SECURITY_HOTSPOT",
          severity: "MINOR",
          rule: "PB-CONTAINER-004",
          message: "Missing HEALTHCHECK instruction in Dockerfile — orchestrator cannot monitor container viability.",
          component: relPath,
          line: 1,
          cwe: ["CWE-390"],
          resolution: "Add HEALTHCHECK CMD curl -f http://localhost:4000/health || exit 1",
        });
      }
    }
  }

  // 2. Secret Leaks in .env files
  for (const envF of envFiles) {
    const relPath = path.relative(projectPath, envF);
    issues.push({
      key: `trivy-SECRET-${relPath}`,
      tool: "Built-in checks",
      type: "VULNERABILITY",
      severity: "MAJOR",
      rule: "PB-SECRET-002",
      message: `.env environment configuration file committed to repository filesystem.`,
      component: relPath,
      line: 1,
      cwe: ["CWE-532"],
      resolution: "Add .env to .gitignore and use .env.example for template environment variables.",
    });
  }

  // 3. Package Manifest Lock Check
  for (const pkgJson of packageJsonFiles) {
    const dir = path.dirname(pkgJson);
    const hasLock = fs.existsSync(path.join(dir, "package-lock.json")) || fs.existsSync(path.join(dir, "yarn.lock"));
    if (!hasLock) {
      issues.push({
        key: `trivy-FS001-${path.relative(projectPath, pkgJson)}`,
        tool: "Built-in checks",
        type: "SECURITY_HOTSPOT",
        severity: "MAJOR",
        rule: "PB-DEPS-001",
        message: "Missing lockfile (package-lock.json / yarn.lock) — builds may ingest unvetted transitively updated dependencies.",
        component: path.relative(projectPath, pkgJson),
        line: 1,
        cwe: ["CWE-1104"],
        resolution: "Run 'npm install' locally to generate package-lock.json and commit it to git.",
      });
    }
  }

  return formatTrivyResponse(issues, projectPath);
}

function formatTrivyResponse(issues, projectPath) {
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  for (const iss of issues) {
    sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
  }

  return {
    tool: "Trivy",
    total: issues.length,
    issues,
    summary: {
      total: issues.length,
      ...sevCounts,
    },
    targetPath: path.basename(projectPath),
    scannedAt: new Date().toISOString(),
  };
}

function mapTrivySeverity(sev) {
  const map = { CRITICAL: "CRITICAL", HIGH: "MAJOR", MEDIUM: "MINOR", LOW: "INFO" };
  return map[sev?.toUpperCase()] || "MAJOR";
}

function getFilesRecursively(dir, maxDepth = 4, depth = 0) {
  if (depth > maxDepth) return [];
  let results = [];
  try {
    const list = fs.readdirSync(dir);
    for (const file of list) {
      if (["node_modules", ".git", "dist", "build", ".venv", "__pycache__"].includes(file)) continue;
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat && stat.isDirectory()) {
        results = results.concat(getFilesRecursively(fullPath, maxDepth, depth + 1));
      } else {
        results.push(fullPath);
      }
    }
  } catch {}
  return results;
}
