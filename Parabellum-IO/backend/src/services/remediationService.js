/**
 * remediationService.js
 * Builds a concrete fix plan for each finding: numbered steps, an example,
 * effort, priority / due date (SLA by risk) and how to verify the fix.
 */
import { getCWE } from "./cweRiskService.js";

// Step-by-step guidance per CWE (falls back to the CWE one-liner from cweRiskService)
const PLAYBOOK = {
  "CWE-89": {
    steps: [
      "Find every query built with string concatenation or template strings.",
      "Replace it with a parameterized query / prepared statement (placeholders such as ? or $1).",
      "Validate input type and length before it reaches the data layer.",
      "Run the database account with least privilege (no DROP/ALTER).",
    ],
    example: `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])`,
    effort: "Low (hours)",
  },
  "CWE-94": {
    steps: [
      "Remove eval(), new Function() and string-based setTimeout/setInterval calls.",
      "If you need to parse data, use JSON.parse; for maths use a safe expression library.",
      "Reject unexpected input with an allow-list.",
    ],
    example: `const value = JSON.parse(req.body.data);   // instead of eval(req.query.expr)`,
    effort: "Low (hours)",
  },
  "CWE-79": {
    steps: [
      "Never insert user input with innerHTML / dangerouslySetInnerHTML.",
      "Use textContent, or sanitize HTML with DOMPurify when HTML is really needed.",
      "Add a Content-Security-Policy header to limit script sources.",
    ],
    example: `element.textContent = location.hash.substring(1);`,
    effort: "Low (hours)",
  },
  "CWE-798": {
    steps: [
      "Remove the secret from source code, Dockerfiles and committed .env files.",
      "Rotate the exposed credential immediately (it is in git history).",
      "Load secrets from environment variables or a secrets manager at runtime.",
      "Add .env to .gitignore and keep only .env.example in the repository.",
    ],
    example: `const DB_PASSWORD = process.env.DB_PASSWORD;`,
    effort: "Low (hours) + rotation",
  },
  "CWE-942": {
    steps: [
      "Replace origin: '*' with an explicit list of trusted front-end origins.",
      "Do not reflect the request Origin header without checking it.",
    ],
    example: `app.use(cors({ origin: ["https://app.example.com"] }));`,
    effort: "Low (minutes)",
  },
  "CWE-1004": {
    steps: [
      "Set httpOnly, secure and sameSite on every session cookie.",
      "Serve the app over HTTPS so the Secure flag works.",
    ],
    example: `res.cookie("session", id, { httpOnly: true, secure: true, sameSite: "strict" });`,
    effort: "Low (minutes)",
  },
  "CWE-352": {
    steps: [
      "Use SameSite=Strict/Lax session cookies.",
      "Add CSRF tokens (e.g. csrf-csrf / lusca) to every state-changing form and API call.",
    ],
    example: `app.use(doubleCsrfProtection);`,
    effort: "Medium (1–2 days)",
  },
  "CWE-1021": {
    steps: [
      "Add security headers middleware (Helmet) before all routes.",
      "Set Content-Security-Policy, X-Frame-Options/frame-ancestors and X-Content-Type-Options: nosniff.",
      "Remove the X-Powered-By header.",
    ],
    example: `app.use(helmet()); app.disable("x-powered-by");`,
    effort: "Low (minutes)",
  },
  "CWE-250": {
    steps: [
      "Create an unprivileged user in the Dockerfile and switch to it with USER before CMD.",
      "Remove privileged: true from docker-compose; add only the capabilities you need.",
    ],
    example: `RUN useradd -r app\nUSER app`,
    effort: "Low (hours)",
  },
  "CWE-829": {
    steps: [
      "Pin the base image to a specific version or digest (e.g. node:20.11-alpine).",
      "Update it on purpose through a dependency bot and re-scan.",
    ],
    example: `FROM node:20.11-alpine`,
    effort: "Low (minutes)",
  },
  "CWE-1104": {
    steps: [
      "Upgrade the package to the fixed version shown in the finding.",
      "Regenerate and commit the lockfile (package-lock.json / poetry.lock / pom.xml).",
      "Run the test suite, then re-run the SCA/container scan to confirm.",
    ],
    example: `npm install lodash@4.17.21 --save`,
    effort: "Low–Medium (hours)",
  },
  "CWE-319": {
    steps: [
      "Serve the site and all form actions over HTTPS only.",
      "Redirect HTTP to HTTPS and enable HSTS.",
    ],
    example: `<form action="https://example.com/login" method="post">`,
    effort: "Low (hours)",
  },
  "CWE-200": {
    steps: [
      "Stop exposing internal details: remove version banners (X-Powered-By) and return generic error messages.",
      "In Dockerfiles copy only what the app needs (COPY package*.json src/ …) and add a .dockerignore for .env, .git and keys.",
      "Check the image / responses again to confirm nothing sensitive is visible.",
    ],
    example: `# .dockerignore\n.env\n.git\n*.pem`,
    effort: "Low (minutes)",
  },
  "CWE-22": {
    steps: [
      "Resolve the requested path and check it stays inside the allowed folder.",
      "Use an allow-list of file names instead of raw user input.",
    ],
    example: `const p = path.resolve(BASE, name); if (!p.startsWith(BASE)) throw new Error("bad path");`,
    effort: "Low (hours)",
  },
};

// Days to fix, by risk rating (typical vulnerability-management SLA)
const SLA_DAYS = { Critical: 7, High: 30, Medium: 90, Low: 180, Info: 365 };

/** Priority bucket shown in the fix plan. */
export function priorityFor(risk) {
  return { Critical: "P1 – fix now", High: "P2 – this sprint", Medium: "P3 – next release", Low: "P4 – backlog", Info: "P5 – optional" }[risk] || "P3 – next release";
}

/** Due date (YYYY-MM-DD) for a finding first seen at `from`. */
export function dueDateFor(risk, from = new Date()) {
  const d = new Date(from);
  d.setDate(d.getDate() + (SLA_DAYS[risk] ?? 90));
  return d.toISOString().slice(0, 10);
}

/**
 * Fix plan for one finding.
 * @param {object} f — unified finding (cwe, tool, package_name, fixed_version, file, line, url…)
 * @param {string} risk — Critical/High/Medium/Low/Info
 */
export function buildFixPlan(f, risk) {
  const cwe = getCWE(f.cwe);
  const play = PLAYBOOK[f.cwe];
  const tool = String(f.tool || "the scanner").replace(" (built-in)", "");
  const where = f.url ? `URL ${f.url}` : f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.package_name ? `package ${f.package_name}` : "the affected component";
  const quality = ["BUG", "CODE_SMELL"].includes(f.type) && (!f.cwe || f.cwe === "CWE-693") && !f.package_name && !f.url;
  const toolAdvice = f.toolGuidance || null;

  let steps;
  if (play) steps = [...play.steps];
  else if (quality) steps = [
    `Open ${where} and read the rule${f.rule ? ` (${f.rule})` : ""} explanation${toolAdvice ? " and the tool's fix advice below" : ""}.`,
    `Make the change the rule asks for: "${String(f.message || f.title || "").replace(/\s+/g, " ").slice(0, 200)}"`,
    f.type === "BUG"
      ? "Check the surrounding logic so the code behaves as intended in every case (null/undefined values, error paths, edge cases)."
      : "Keep the behaviour the same while refactoring (simplify, remove dead/duplicate code, rename, split long functions).",
    "Run the project's tests (or start the app) to confirm nothing broke.",
  ];
  else steps = [
    `Locate the issue at ${where}.`,
    cwe?.remediation || "Apply the vendor / rule guidance for this weakness.",
    ...(toolAdvice ? [`Apply ${tool}'s advice shown below.`] : []),
    "Add a regression test or check so the weakness cannot come back.",
  ];
  let example = play?.example || f.toolFix || null;
  let effort = play?.effort || (quality ? "Low (minutes–hours)" : "Medium (1–2 days)");

  // Dependency findings: say exactly what to upgrade
  if (f.package_name) {
    const target = f.fixed_version && f.fixed_version !== "N/A" && f.fixed_version !== "no fix yet"
      ? `version ${f.fixed_version}` : "a version without this vulnerability (no fix published yet — consider replacing the package)";
    steps = [`Upgrade ${f.package_name} from ${f.installed_version || "the current version"} to ${target}.`,
      ...(play ? steps.slice(1) : PLAYBOOK["CWE-1104"].steps.slice(1))];
    example = f.fixed_version && /^\d/.test(f.fixed_version)
      ? `npm install ${f.package_name}@${String(f.fixed_version).split(",")[0].trim()}` : example;
    effort = PLAYBOOK["CWE-1104"].effort;
  }

  return {
    summary: `${quality ? (f.title || "Code-quality issue") : (cwe?.shortName || f.title || "Issue")} in ${where}.`,
    why: quality
      ? "Code-quality issues make the code harder to maintain and can hide real bugs; they do not directly expose data."
      : (cwe ? `${cwe.name}${cwe.riskImpact ? ` — ${cwe.riskImpact}` : ""}` : null),
    steps,
    toolAdvice,
    toolAdviceSource: toolAdvice ? tool : null,
    example,
    effort,
    priority: priorityFor(risk),
    slaDays: SLA_DAYS[risk] ?? 90,
    verification: f.url
      ? "Re-run the OWASP ZAP stage of the pipeline against the same URL; the alert must not appear."
      : `Re-run the pipeline (same tools). The finding is marked "Verified Fixed" automatically when ${tool} no longer reports it, and the report shows it under Fix Verification.`,
  };
}
