/**
 * zapService.js
 * OWASP ZAP DAST (Dynamic Application Security Testing).
 *
 * Real mode: talks to a running ZAP daemon through its REST API (ZAP_URL),
 * spiders the target URL, waits for the passive scan, optionally runs an
 * active scan, and returns ZAP's alerts.
 *   Start ZAP e.g.:  docker run -p 8090:8090 zaproxy/zap-stable zap.sh -daemon \
 *     -host 0.0.0.0 -port 8090 -config api.key=<key> \
 *     -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
 *
 * Fallback: if ZAP is not running, Parabellum's small built-in web-config checks
 * read the source code. That is a static check, NOT a DAST scan, and is labelled so.
 */

import axios from "axios";
import path from "path";
import fs from "fs";
import { lineOf, stripJsComments } from "./toolRunner.js";

const ZAP_URL = () => process.env.ZAP_URL || "http://localhost:8090";

function zapClient() {
  return axios.create({
    baseURL: ZAP_URL(),
    timeout: 30000,
    params: process.env.ZAP_API_KEY ? { apikey: process.env.ZAP_API_KEY } : {},
  });
}

/**
 * Check if a ZAP daemon is reachable.
 * @returns {Promise<{available: boolean, version: string|null, url: string, builtInFallback: boolean}>}
 */
export async function checkZapAvailability() {
  try {
    const { data } = await zapClient().get("/JSON/core/view/version/", { timeout: 5000 });
    return { available: true, version: data.version, url: ZAP_URL(), builtInFallback: true };
  } catch {
    return { available: false, version: null, url: ZAP_URL(), builtInFallback: true };
  }
}

/**
 * Run OWASP ZAP DAST scan.
 * @param {string} projectPath — project source (used only by the built-in fallback)
 * @param {{targetUrl?: string, active?: boolean, timeout?: number}} options
 */
export async function runZapScan(projectPath, options = {}) {
  const { available } = await checkZapAvailability();

  if (!available) {
    if (!fs.existsSync(projectPath)) {
      throw new Error(`Project path does not exist: ${projectPath}`);
    }
    console.log(`   🌐 ZAP not running — running built-in web-config checks on ${projectPath}`);
    return {
      ...runLocalWebChecks(projectPath),
      engine: "built-in",
      warning: `OWASP ZAP is not running at ${ZAP_URL()}, so only Parabellum's basic source-code web-config checks ran. This is NOT a DAST scan. Start the ZAP daemon and enter the app's URL for a real scan.`,
    };
  }

  const targetUrl = validateTargetUrl(options.targetUrl);
  return runRealZapScan(targetUrl, options);
}

function validateTargetUrl(targetUrl) {
  if (!targetUrl) {
    throw Object.assign(new Error("Enter the URL of the running application to scan (e.g. http://localhost:3000)."), { status: 400 });
  }
  let u;
  try { u = new URL(targetUrl); } catch {
    throw Object.assign(new Error(`Invalid target URL: ${targetUrl}`), { status: 400 });
  }
  if (!["http:", "https:"].includes(u.protocol)) {
    throw Object.assign(new Error("Target URL must start with http:// or https://"), { status: 400 });
  }
  return u.toString();
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function waitFor(check, timeoutMs, label) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await check()) return;
    await sleep(2000);
  }
  throw new Error(`ZAP ${label} did not finish within ${Math.round(timeoutMs / 1000)}s`);
}

async function runRealZapScan(targetUrl, options) {
  const zap = zapClient();
  const timeout = options.timeout || 600000;
  console.log(`   🌐 ZAP scanning ${targetUrl} (active=${!!options.active})`);

  // Start a fresh ZAP session so alerts from earlier scans are not reported again
  await zap.get("/JSON/core/action/newSession/", { params: { overwrite: true } });

  // Make sure the target is reachable through ZAP before spidering
  await zap.get("/JSON/core/action/accessUrl/", { params: { url: targetUrl, followRedirects: true } })
    .catch(err => { throw new Error(`ZAP could not reach ${targetUrl}: ${err.response?.data?.message || err.message}`); });

  // 1. Spider
  const { data: spider } = await zap.get("/JSON/spider/action/scan/", { params: { url: targetUrl, recurse: true, maxChildren: 50 } });
  await waitFor(async () => {
    const { data } = await zap.get("/JSON/spider/view/status/", { params: { scanId: spider.scan } });
    return Number(data.status) >= 100;
  }, timeout, "spider");

  // 2. Active scan (optional — sends attack payloads, only use on apps you own)
  if (options.active) {
    const { data: ascan } = await zap.get("/JSON/ascan/action/scan/", { params: { url: targetUrl, recurse: true } });
    await waitFor(async () => {
      const { data } = await zap.get("/JSON/ascan/view/status/", { params: { scanId: ascan.scan } });
      return Number(data.status) >= 100;
    }, timeout, "active scan");
  }

  // 3. Wait for passive scanner to process all recorded requests
  await waitFor(async () => {
    const { data } = await zap.get("/JSON/pscan/view/recordsToScan/");
    return Number(data.recordsToScan) === 0;
  }, 120000, "passive scan");

  // 4. Collect alerts for this target
  const { data } = await zap.get("/JSON/core/view/alerts/", { params: { baseurl: targetUrl, start: 0, count: 5000 } });
  return { ...normalizeZapAlerts(data.alerts || [], targetUrl), engine: "zap", active: !!options.active };
}

function normalizeZapAlerts(alerts, targetUrl) {
  // ZAP reports the same alert once per URL/parameter — show one row per alert type
  const byPlugin = new Map();
  for (const a of alerts) {
    const row = byPlugin.get(a.pluginId);
    if (row) {
      row.urls.add(a.url);
      continue;
    }
    byPlugin.set(a.pluginId, {
      key: `zap-${a.pluginId}`,
      tool: "OWASP ZAP",
      type: "VULNERABILITY",
      severity: mapZapRisk(a.risk),
      rule: `ZAP-${a.pluginId}`,
      message: a.alert || a.name,
      component: a.url,
      urls: new Set([a.url]),
      line: null,
      cwe: a.cweid && a.cweid !== "-1" ? [`CWE-${a.cweid}`] : [],
      owasp: a.wascid && a.wascid !== "-1" ? [`WASC-${a.wascid}`] : [],
      confidence: a.confidence || "",
      description: a.description || "",
      solution: a.solution || "",
      evidence: a.evidence || "",
    });
  }
  const issues = [...byPlugin.values()].map(({ urls, ...row }) => ({
    ...row,
    message: urls.size > 1 ? `${row.message} (${urls.size} URLs)` : row.message,
    affectedUrls: [...urls],
  }));
  const order = { CRITICAL: 0, MAJOR: 1, MINOR: 2, INFO: 3 };
  issues.sort((x, y) => order[x.severity] - order[y.severity]);
  return formatZapResponse(issues, targetUrl);
}

/**
 * Built-in web-config checks (static source review — NOT DAST).
 * Comments are ignored and line numbers point at the real line.
 */
function runLocalWebChecks(projectPath) {
  const issues = [];
  const files = getFilesRecursively(projectPath);

  const jsFiles = files.filter(f => /\.(js|jsx|ts|tsx|mjs|cjs)$/.test(f));
  const htmlFiles = files.filter(f => f.endsWith(".html"));

  let hasHelmet = false;
  let hasCsrf = false;
  let expressFile = null;

  const add = (rule, relPath, line, severity, type, message, cwe, owasp, solution) => issues.push({
    key: `web-${rule}-${relPath}-${line}`,
    tool: "Built-in checks",
    type, severity, rule, message,
    component: relPath, line, cwe: [cwe], owasp: [owasp], solution,
  });

  for (const f of jsFiles) {
    const relPath = path.relative(projectPath, f);
    const content = stripJsComments(fs.readFileSync(f, "utf8"));

    if (/express\(\)/.test(content) && !expressFile) expressFile = relPath;
    if (/helmet\(/.test(content)) hasHelmet = true;
    if (/csurf\(|csrf\(|lusca\.csrf/.test(content)) hasCsrf = true;

    const cors = content.match(/origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]\s*,\s*['"]\*/);
    if (cors) add("PB-WEB-001", relPath, lineOf(content, cors[0]), "CRITICAL", "VULNERABILITY",
      "Wildcard CORS origin ('*') — any website can call this API from a user's browser.",
      "CWE-942", "A05:2021", "Restrict CORS origin to trusted explicit domains instead of '*'.");

    const cookie = content.match(/res\.cookie\([^)]*\)/);
    if (cookie && !/httpOnly\s*:\s*true/.test(cookie[0])) add("PB-WEB-002", relPath, lineOf(content, cookie[0]), "MAJOR", "VULNERABILITY",
      "Cookie set without the HttpOnly flag — JavaScript (and XSS) can read it.",
      "CWE-1004", "A07:2021", "Pass { httpOnly: true, secure: true, sameSite: 'strict' } to res.cookie().");

    for (const sink of ["dangerouslySetInnerHTML", ".innerHTML =", "eval("]) {
      const line = lineOf(content, sink);
      if (line) add("PB-WEB-003", relPath, line, "CRITICAL", "VULNERABILITY",
        `Possible XSS / code-injection sink: ${sink.replace(" =", "")}`,
        "CWE-79", "A03:2021", "Sanitize with DOMPurify, use textContent, and never eval() user input.");
    }
  }

  if (expressFile && !hasHelmet) add("PB-WEB-004", expressFile, null, "MAJOR", "SECURITY_HOTSPOT",
    "No security headers middleware (Helmet): missing Content-Security-Policy, X-Frame-Options, HSTS.",
    "CWE-693", "A05:2021", "npm install helmet, then app.use(helmet()) before your routes.");

  if (expressFile && !hasCsrf) add("PB-WEB-005", expressFile, null, "MAJOR", "VULNERABILITY",
    "No anti-CSRF protection found for state-changing routes.",
    "CWE-352", "A01:2021", "Use SameSite cookies or CSRF-token middleware on POST/PUT/DELETE routes.");

  for (const hf of htmlFiles) {
    const relPath = path.relative(projectPath, hf);
    const content = fs.readFileSync(hf, "utf8");
    const line = lineOf(content, 'type="password"');
    const action = content.match(/<form[^>]*action="(http:[^"]*)"/i);
    if (line && action) add("PB-WEB-006", relPath, line, "MAJOR", "VULNERABILITY",
      "Password form submits over plain HTTP.",
      "CWE-319", "A02:2021", "Submit login forms only to https:// URLs.");
  }

  return formatZapResponse(issues, path.basename(projectPath));
}

function formatZapResponse(issues, target) {
  const sevCounts = { BLOCKER: 0, CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0 };
  for (const iss of issues) {
    sevCounts[iss.severity] = (sevCounts[iss.severity] || 0) + 1;
  }

  return {
    tool: "OWASP ZAP",
    total: issues.length,
    issues,
    summary: {
      total: issues.length,
      ...sevCounts,
    },
    target,
    scannedAt: new Date().toISOString(),
  };
}

function mapZapRisk(risk) {
  const map = { High: "CRITICAL", Medium: "MAJOR", Low: "MINOR", Informational: "INFO" };
  return map[risk] || "MAJOR";
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
  } catch { /* unreadable folder */ }
  return results;
}
