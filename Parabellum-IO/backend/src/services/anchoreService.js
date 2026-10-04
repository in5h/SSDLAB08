/**
 * anchoreService.js
 * Container / dependency policy evaluation using Anchore's open-source scanner, Grype.
 * Runs `grype dir:<project> -o json` when Grype is installed and applies a simple
 * policy gate (STOP on Critical/High). If Grype is not installed, Parabellum's
 * built-in Dockerfile policy checks run instead and are clearly labelled.
 */

import path from "path";
import fs from "fs";
import { runTool, parseJsonOutput } from "./toolRunner.js";

const GRYPE = process.env.GRYPE_PATH || "grype";

/**
 * Check if Grype (Anchore) is available.
 */
export async function checkAnchoreAvailability() {
  try {
    const { code, stdout } = await runTool(GRYPE, ["version"], { timeout: 30000 });
    const version = code === 0 ? (stdout.match(/^Version:\s*(\S+)/m)?.[1] || "unknown") : null;
    return { available: !!version, version: version ? `Grype ${version}` : null, builtInFallback: true };
  } catch {
    return { available: false, version: null, builtInFallback: true };
  }
}

/**
 * Run Anchore (Grype) policy evaluation on project.
 */
export async function runAnchoreScan(projectPath, options = {}) {
  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const { available } = await checkAnchoreAvailability();
  if (!available) {
    console.log(`   🐳 Grype not installed — running built-in Dockerfile policy checks on ${projectPath}`);
    return {
      ...runLocalAnchoreEngine(projectPath),
      engine: "built-in",
      warning: "Anchore Grype is not installed, so only Parabellum's basic Dockerfile policy checks ran (no vulnerability database). Install Grype (https://github.com/anchore/grype) for a real scan.",
    };
  }

  const { code, stdout, stderr } = await runTool(
    GRYPE, [`dir:${projectPath}`, "-o", "json"],
    { cwd: projectPath, timeout: options.timeout || 600000 }
  );
  if (code !== 0) {
    // Show Grype's own ERROR lines (e.g. vulnerability DB could not be downloaded)
    const errors = stderr.split("\n").filter(l => /ERROR|FATAL/.test(l)).join(" | ") || stderr.slice(-800);
    throw new Error(`Grype failed (exit ${code}): ${errors}`);
  }
  return { ...normalizeGrypeResults(parseJsonOutput(stdout, "Grype"), projectPath), engine: "grype" };
}

const STOP_SEVERITIES = ["Critical", "High"];

function normalizeGrypeResults(raw, projectPath) {
  const issues = (raw.matches || []).map(m => {
    const v = m.vulnerability || {};
    const a = m.artifact || {};
    const fixed = v.fix?.versions?.length ? v.fix.versions.join(", ") : "no fix yet";
    const stop = STOP_SEVERITIES.includes(v.severity);
    return {
      key: `grype-${v.id}-${a.name}-${a.version}`,
      tool: "Anchore Grype",
      type: "VULNERABILITY",
      severity: mapGrypeSeverity(v.severity),
      rule: v.id,
      message: `${a.name} ${a.version} — ${v.id} (${v.severity}). Fixed in: ${fixed}`,
      component: a.locations?.[0]?.path?.replace(/^\//, "") || a.name,
      line: null,
      cwe: [],
      pkgName: a.name,
      installedVersion: a.version,
      fixedVersion: fixed,
      primaryUrl: v.dataSource || "",
      gate: "vulnerabilities",
      trigger: `package_severity_${String(v.severity).toLowerCase()}`,
      policyAction: stop ? "STOP" : "WARN",
    };
  });
  return formatAnchoreResponse(issues, projectPath);
}

function mapGrypeSeverity(sev) {
  const map = { Critical: "CRITICAL", High: "MAJOR", Medium: "MINOR", Low: "INFO", Negligible: "INFO" };
  return map[sev] || "INFO";
}

function runLocalAnchoreEngine(projectPath) {
  const issues = [];
  const files = getFilesRecursively(projectPath);

  const dockerfiles = files.filter(f => path.basename(f).toLowerCase().includes("dockerfile"));
  const composeFiles = files.filter(f => path.basename(f).includes("docker-compose") || path.basename(f).endsWith(".yaml") || path.basename(f).endsWith(".yml"));

  // No Dockerfile → Dockerfile gates are not applicable (not a finding)
  if (dockerfiles.length > 0) {
    for (const df of dockerfiles) {
      const relPath = path.relative(projectPath, df);
      const content = fs.readFileSync(df, "utf8");
      const lines = content.split("\n");

      let userDefined = false;

      lines.forEach((line, idx) => {
        const trimmed = line.trim();

        // Gate: base_image_check
        if (trimmed.startsWith("FROM ")) {
          const baseImg = trimmed.substring(5).trim();

          if (baseImg.includes("ubuntu:18.04") || baseImg.includes("node:12") || baseImg.includes("python:2.7")) {
            issues.push({
              key: `anchore-POLICY-BASE-DEPRECATED-${idx}`,
              tool: "Built-in checks",
              type: "VULNERABILITY",
              severity: "CRITICAL",
              rule: "PB-POLICY-BASE_IMAGE",
              message: `POLICY FAIL: Gate [base_image] -> Trigger [deprecated_os]. Base image '${baseImg}' reached End-Of-Life (EOL).`,
              component: relPath,
              line: idx + 1,
              cwe: ["CWE-1104"],
              gate: "base_image",
              trigger: "deprecated_os",
              policyAction: "STOP",
              remediation: "Upgrade base image to a supported LTS distribution (e.g. alpine:3.19 or node:20-alpine).",
            });
          }

          if (!baseImg.includes("alpine") && !baseImg.includes("slim") && !baseImg.includes("distroless")) {
            issues.push({
              key: `anchore-POLICY-BASE-BLOAT-${idx}`,
              tool: "Built-in checks",
              type: "SECURITY_HOTSPOT",
              severity: "MINOR",
              rule: "PB-POLICY-IMAGE_SIZE",
              message: `POLICY WARN: Gate [image_footprint] -> Trigger [heavy_base_image]. Heavy distribution '${baseImg}' increases container attack surface.`,
              component: relPath,
              line: idx + 1,
              cwe: ["CWE-1008"],
              gate: "image_footprint",
              trigger: "heavy_base_image",
              policyAction: "WARN",
              remediation: "Consider migrating to minimal base images like 'distroless' or 'alpine'.",
            });
          }
        }

        // Gate: user_check
        if (trimmed.startsWith("USER ")) {
          userDefined = true;
          if (trimmed.includes("root") || trimmed.includes("0")) {
            issues.push({
              key: `anchore-POLICY-ROOT-USER-${idx}`,
              tool: "Built-in checks",
              type: "VULNERABILITY",
              severity: "CRITICAL",
              rule: "PB-POLICY-USER",
              message: "POLICY FAIL: Gate [user_check] -> Trigger [root_user_configured]. Container explicitly executes as ROOT.",
              component: relPath,
              line: idx + 1,
              cwe: ["CWE-250"],
              gate: "user_check",
              trigger: "root_user_configured",
              policyAction: "STOP",
              remediation: "Set 'USER 10001' or non-privileged system user.",
            });
          }
        }

        // Gate: package_check (apt-get update without cleaning cache)
        if (trimmed.includes("apt-get update") && !trimmed.includes("rm -rf /var/lib/apt/lists/*")) {
          issues.push({
            key: `anchore-POLICY-APT-CACHE-${idx}`,
            tool: "Built-in checks",
            type: "SECURITY_HOTSPOT",
            severity: "MAJOR",
            rule: "PB-POLICY-PACKAGE_CACHE",
            message: "POLICY WARN: Gate [package_check] -> Trigger [uncleaned_apt_cache]. Package manager cache left in container image layer.",
            component: relPath,
            line: idx + 1,
            cwe: ["CWE-459"],
            gate: "package_check",
            trigger: "uncleaned_apt_cache",
            policyAction: "WARN",
            remediation: "Append '&& rm -rf /var/lib/apt/lists/*' to your RUN apt-get statement.",
          });
        }
      });

      if (!userDefined) {
        issues.push({
          key: `anchore-POLICY-NO-USER-${relPath}`,
          tool: "Built-in checks",
          type: "VULNERABILITY",
          severity: "CRITICAL",
          rule: "PB-POLICY-USER_MISSING",
          message: "POLICY FAIL: Gate [user_check] -> Trigger [no_user_defined]. Default container execution falls back to ROOT.",
          component: relPath,
          line: lines.length,
          cwe: ["CWE-250"],
          gate: "user_check",
          trigger: "no_user_defined",
          policyAction: "STOP",
          remediation: "Add USER directive before container entrypoint.",
        });
      }
    }
  }

  // Evaluate Docker Compose privileged execution
  for (const cf of composeFiles) {
    const relPath = path.relative(projectPath, cf);
    const content = fs.readFileSync(cf, "utf8");
    if (content.includes("privileged: true")) {
      issues.push({
        key: `anchore-POLICY-PRIVILEGED-${relPath}`,
        tool: "Built-in checks",
        type: "VULNERABILITY",
        severity: "CRITICAL",
        rule: "PB-POLICY-PRIVILEGED_MODE",
        message: "POLICY FAIL: Gate [container_capabilities] -> Trigger [privileged_mode_enabled]. Service runs with full host kernel privileges.",
        component: relPath,
        line: getLineNumber(content, "privileged: true"),
        cwe: ["CWE-269"],
        gate: "container_capabilities",
        trigger: "privileged_mode_enabled",
        policyAction: "STOP",
        remediation: "Remove 'privileged: true' and grant only explicit cap_add capabilities.",
      });
    }
  }

  const hasDockerAssets = dockerfiles.length > 0 || composeFiles.some(f => /docker-compose|compose\.ya?ml/i.test(path.basename(f)));
  return formatAnchoreResponse(issues, projectPath, !hasDockerAssets && issues.length === 0);
}

function formatAnchoreResponse(issues, projectPath, notApplicable = false) {
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  for (const iss of issues) {
    sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
  }

  const stopCount = issues.filter(i => i.policyAction === "STOP").length;
  const warnCount = issues.filter(i => i.policyAction === "WARN").length;

  return {
    tool: "Anchore",
    total: issues.length,
    issues,
    summary: {
      total: issues.length,
      policyStatus: notApplicable ? "N/A (no Docker files)" : stopCount > 0 ? "FAIL (STOP)" : warnCount > 0 ? "WARN" : "PASS",
      stopRulesTriggered: stopCount,
      warnRulesTriggered: warnCount,
      ...sevCounts,
    },
    targetPath: path.basename(projectPath),
    scannedAt: new Date().toISOString(),
  };
}

function getLineNumber(content, substring) {
  const index = content.indexOf(substring);
  if (index === -1) return null;
  return content.substring(0, index).split("\n").length;
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
