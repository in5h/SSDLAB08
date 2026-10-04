/**
 * cweRiskService.js
 * Maps SonarQube findings to CWE entries with CVSS scores, attack types,
 * and risk impact summaries. Uses keyword-based inference (no ML required).
 */

// ── CWE Knowledge Base ──────────────────────────────────────────────────────
// Each entry: id, name, cvss (base score), severity, attackTypes, attackVector,
//             riskImpact, keywords (matched against sonar rule + message)
const CWE_DATABASE = [
  // ── Weaknesses reported by Semgrep / Trivy / ZAP / Grype / Snyk and JS/Docker rules ──
  {
    id: "CWE-94", name: "Improper Control of Generation of Code ('Code Injection')", shortName: "Code Injection",
    top25: 23, cvss: 9.8, severity: "Critical", attackVector: "Network",
    attackTypes: ["Remote Code Execution", "Data Leakage", "Privilege Escalation"],
    riskImpact: "User input that reaches eval() or a similar code-execution sink lets an attacker run arbitrary code on the server or in the browser.",
    remediation: "Never pass user input to eval(), Function(), setTimeout(string) or similar. Parse data with JSON.parse or a safe expression parser.",
    keywords: ["eval(", "eval-detected", "code injection", "dynamic injection or execution of code", "code-string-concat", "s1523"],
  },
  {
    id: "CWE-942", name: "Permissive Cross-domain Policy with Untrusted Domains", shortName: "Permissive CORS",
    top25: null, cvss: 6.5, severity: "Medium", attackVector: "Network",
    attackTypes: ["Data Leakage", "Session Riding"],
    riskImpact: "A wildcard CORS policy lets any website read API responses from a logged-in user's browser.",
    remediation: "Allow only trusted origins in the CORS configuration; never combine '*' with credentials.",
    keywords: ["cors", "access-control-allow-origin", "cross-domain misconfiguration", "s5122"],
  },
  {
    id: "CWE-1004", name: "Sensitive Cookie Without 'HttpOnly' Flag", shortName: "Insecure Cookie",
    top25: null, cvss: 5.4, severity: "Medium", attackVector: "Network",
    attackTypes: ["Session Hijacking", "Credential Theft"],
    riskImpact: "Session cookies readable by JavaScript can be stolen through any XSS bug.",
    remediation: "Set HttpOnly, Secure and SameSite=Strict on session cookies.",
    keywords: ["httponly", "samesite", "cookie without", "cookie no"],
  },
  {
    id: "CWE-1021", name: "Improper Restriction of Rendered UI Layers or Frames (Clickjacking)", shortName: "Clickjacking / Missing Headers",
    top25: null, cvss: 4.3, severity: "Medium", attackVector: "Network",
    attackTypes: ["Clickjacking", "UI Redress"],
    riskImpact: "Without frame protection and security headers the site can be embedded and abused by malicious pages.",
    remediation: "Send X-Frame-Options / CSP frame-ancestors, Content-Security-Policy and X-Content-Type-Options headers (e.g. with Helmet).",
    keywords: ["anti-clickjacking", "x-frame-options", "content security policy", "csp header", "x-content-type-options", "helmet", "security headers"],
  },
  {
    id: "CWE-250", name: "Execution with Unnecessary Privileges", shortName: "Runs as Root",
    top25: null, cvss: 7.8, severity: "High", attackVector: "Local",
    attackTypes: ["Privilege Escalation", "Container Escape"],
    riskImpact: "A container running as root gives an attacker who compromises the app full control of the container and an easier path to the host.",
    remediation: "Add a non-root USER in the Dockerfile and drop privileged mode / extra capabilities.",
    keywords: ["root", "privileged", "missing-user", "user instruction", "s6471"],
  },
  {
    id: "CWE-1104", name: "Use of Unmaintained or Vulnerable Third-Party Components", shortName: "Vulnerable Dependency",
    top25: null, cvss: 7.5, severity: "High", attackVector: "Network",
    attackTypes: ["Known Exploit", "Remote Code Execution", "Denial of Service"],
    riskImpact: "Libraries with published CVEs can be exploited with public exploit code.",
    remediation: "Upgrade the package to the fixed version, regenerate the lockfile and re-test.",
    keywords: ["prototype pollution", "redos", "denial of service", "vulnerable component", "outdated"],
  },
  {
    id: "CWE-829", name: "Inclusion of Functionality from Untrusted Control Sphere", shortName: "Unpinned Base Image",
    top25: null, cvss: 5.3, severity: "Medium", attackVector: "Network",
    attackTypes: ["Supply Chain Compromise"],
    riskImpact: "Using ':latest' or unpinned images pulls whatever the registry serves today, so builds can silently change or be poisoned.",
    remediation: "Pin base images to a specific version tag or digest and update them deliberately.",
    keywords: [":latest", "latest tag", "specific version tag", "source-not-pinned", "avoid-latest", "s6596"],
  },
  {
    id: "CWE-319", name: "Cleartext Transmission of Sensitive Information", shortName: "Cleartext Transmission",
    top25: null, cvss: 7.4, severity: "High", attackVector: "Adjacent",
    attackTypes: ["Credential Theft", "Network Sniffing"],
    riskImpact: "Passwords or tokens sent over plain HTTP can be read by anyone on the network path.",
    remediation: "Serve and submit everything over HTTPS and enable HSTS.",
    keywords: ["over plain http", "cleartext", "without enforcing https", "insecure password transmission"],
  },
  {
    id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", shortName: "Information Exposure",
    top25: null, cvss: 5.3, severity: "Medium", attackVector: "Network",
    attackTypes: ["Reconnaissance", "Data Leakage"],
    riskImpact: "Version banners, stack traces or copied secrets help attackers plan targeted attacks.",
    remediation: "Remove version headers (X-Powered-By), avoid copying secrets into images, and return generic error messages.",
    keywords: ["x-powered-by", "discloses version", "information disclosure", "copying recursively", "s5689", "s6470"],
  },
  {
    id: "CWE-89",
    name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    shortName: "SQL Injection",
    top25: 3,
    cvss: 9.8,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Remote Code Execution", "Data Leakage", "Authentication Bypass", "Data Manipulation"],
    riskImpact: "An attacker can manipulate SQL queries to read, modify or delete database data, bypass authentication, and in some configurations execute OS-level commands.",
    remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    keywords: ["sql injection", "sqli", "sql query", "sql statement", "jdbc", "orm injection", "s2077", "s3649", "s2076"],
  },
  {
    id: "CWE-79",
    name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    shortName: "XSS",
    top25: 2,
    cvss: 8.8,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Session Hijacking", "Credential Theft", "Phishing", "Malware Distribution"],
    riskImpact: "Attackers can inject malicious scripts into web pages viewed by other users, stealing session tokens, redirecting users, or performing actions on their behalf.",
    remediation: "Escape all user-supplied output. Use Content-Security-Policy headers. Validate and sanitize inputs.",
    keywords: ["xss", "cross-site scripting", "script injection", "output encoding", "html escape", "s5131", "reflected", "stored xss"],
  },
  {
    id: "CWE-798",
    name: "Use of Hard-coded Credentials",
    shortName: "Hard-coded Credentials",
    top25: 18,
    cvss: 9.1,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Authentication Bypass", "Credential Theft", "Unauthorized Access", "Privilege Escalation"],
    riskImpact: "Hard-coded passwords or API keys embedded in source code can be extracted by anyone with access to the codebase, granting full unauthorized access.",
    remediation: "Store credentials in environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). Rotate any exposed credentials immediately.",
    keywords: ["hardcod", "hard-cod", "secret", "api key", "private key", "password", "credential", "s2068", "s6437", "token hard"],
  },
  {
    id: "CWE-22",
    name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    shortName: "Path Traversal",
    top25: 8,
    cvss: 8.6,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Arbitrary File Read", "Arbitrary File Write", "Data Leakage", "Remote Code Execution"],
    riskImpact: "Attackers can navigate outside intended directories using sequences like '../' to read sensitive files (config, keys, /etc/passwd) or write malicious files to the server.",
    remediation: "Validate and canonicalize file paths. Use allow-lists for permitted directories. Never construct file paths from user input directly.",
    keywords: ["path traversal", "directory traversal", "file inclusion", "../", "path injection", "s6096", "s2083"],
  },
  {
    id: "CWE-476",
    name: "NULL Pointer Dereference",
    shortName: "NULL Pointer Dereference",
    top25: 12,
    cvss: 7.5,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Denial of Service", "Application Crash", "Information Disclosure"],
    riskImpact: "Dereferencing a null pointer causes an application crash, resulting in denial of service. In some cases it may also expose memory contents.",
    remediation: "Always null-check objects before use. Use Optional<> patterns. Enable NullAway or similar static analysis.",
    keywords: ["null pointer", "nullpointer", "null dereference", "npe", "nullpointerexception", "s2259", "may be null"],
  },
  {
    id: "CWE-787",
    name: "Out-of-bounds Write",
    shortName: "Out-of-bounds Write",
    top25: 1,
    cvss: 9.8,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Remote Code Execution", "Memory Corruption", "Privilege Escalation", "Arbitrary Code Execution"],
    riskImpact: "Writing data beyond a buffer boundary corrupts adjacent memory, potentially allowing attackers to overwrite return addresses or function pointers and execute arbitrary code.",
    remediation: "Use bounds-checked containers. Validate all array indices. Enable AddressSanitizer during testing.",
    keywords: ["out of bounds write", "buffer overflow", "heap overflow", "stack overflow", "bounds check", "oob write"],
  },
  {
    id: "CWE-125",
    name: "Out-of-bounds Read",
    shortName: "Out-of-bounds Read",
    top25: 7,
    cvss: 7.5,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Information Disclosure", "Memory Leakage", "Crash / DoS"],
    riskImpact: "Reading beyond the intended buffer boundary can expose sensitive data in memory (keys, tokens, PII) or cause application crashes.",
    remediation: "Validate array bounds before access. Use safe string/array APIs. Enable compiler bounds checking.",
    keywords: ["out of bounds read", "oob read", "buffer over-read", "uninitialized data", "information disclosure"],
  },
  {
    id: "CWE-327",
    name: "Use of a Broken or Risky Cryptographic Algorithm",
    shortName: "Weak Cryptography",
    top25: null,
    cvss: 7.5,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Decrypt Encrypted Data", "Forgery", "Collision Attack", "Man-in-the-Middle"],
    riskImpact: "Use of weak or deprecated algorithms (MD5, SHA-1, DES, RC4) allows attackers to decrypt data, forge signatures, or conduct collision attacks.",
    remediation: "Use AES-256, SHA-256+, RSA-2048+ or elliptic curve cryptography. Migrate away from MD5/SHA1/DES/RC4.",
    keywords: ["weak crypt", "weak cipher", "md5", "sha1", "sha-1", "des ", "rc4", "weak hash", "s5542", "s5547", "s2278", "s4790"],
  },
  {
    id: "CWE-352",
    name: "Cross-Site Request Forgery (CSRF)",
    shortName: "CSRF",
    top25: 9,
    cvss: 8.8,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Unauthorized State Change", "Account Takeover", "Privilege Escalation", "Data Manipulation"],
    riskImpact: "Attackers trick authenticated users into submitting malicious requests, performing actions (fund transfer, password change, account deletion) without their knowledge.",
    remediation: "Implement CSRF tokens. Use SameSite cookie attribute. Validate Origin/Referer headers.",
    keywords: ["csrf", "cross-site request forgery", "s4502", "forged request", "anti-csrf"],
  },
  {
    id: "CWE-611",
    name: "Improper Restriction of XML External Entity Reference",
    shortName: "XXE",
    top25: null,
    cvss: 9.1,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Server-Side Request Forgery", "Arbitrary File Read", "Remote Code Execution", "DoS"],
    riskImpact: "Malicious XML with external entity references allows attackers to read local files, perform SSRF attacks, scan internal networks, or trigger denial of service.",
    remediation: "Disable external entity processing in XML parsers. Use DTD-less parsing. Upgrade to safe XML libraries.",
    keywords: ["xxe", "xml external entity", "external entity", "dtd", "s2755", "xml injection"],
  },
  {
    id: "CWE-362",
    name: "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    shortName: "Race Condition",
    top25: 21,
    cvss: 8.1,
    severity: "High",
    attackVector: "Local",
    attackTypes: ["Privilege Escalation", "Data Corruption", "Authentication Bypass", "DoS"],
    riskImpact: "Time-of-check to time-of-use (TOCTOU) flaws and threading races allow attackers to manipulate shared state between the check and use of a resource.",
    remediation: "Use proper synchronization primitives (locks, atomics). Avoid TOCTOU patterns. Perform atomic operations.",
    keywords: ["race condition", "toctou", "time-of-check", "concurrent", "thread safe", "synchroniz", "s2445"],
  },
  {
    id: "CWE-862",
    name: "Missing Authorization",
    shortName: "Missing Authorization",
    top25: 11,
    cvss: 9.8,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Unauthorized Access", "Privilege Escalation", "Data Breach", "Account Takeover"],
    riskImpact: "Missing authorization checks allow attackers to access resources or perform operations they should not be permitted to, potentially exposing all user data.",
    remediation: "Implement role-based access control (RBAC). Check authorization on every sensitive operation server-side. Never trust client-side role checks.",
    keywords: ["missing authorization", "missing permission", "permission check", "access control", "unauthorized", "s5131"],
  },
  {
    id: "CWE-502",
    name: "Deserialization of Untrusted Data",
    shortName: "Insecure Deserialization",
    top25: 15,
    cvss: 9.8,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Remote Code Execution", "Privilege Escalation", "Data Tampering", "DoS"],
    riskImpact: "Deserializing attacker-controlled data can trigger gadget chains that execute arbitrary code, bypass authentication, or corrupt application state.",
    remediation: "Never deserialize data from untrusted sources. Use safe serialization formats (JSON). Implement integrity checks.",
    keywords: ["deserializ", "serializ", "object injection", "pickle", "java deserializ", "s1948"],
  },
  {
    id: "CWE-918",
    name: "Server-Side Request Forgery (SSRF)",
    shortName: "SSRF",
    top25: 19,
    cvss: 9,
    severity: "Critical",
    attackVector: "Network",
    attackTypes: ["Internal Network Access", "Cloud Metadata Theft", "Port Scanning", "RCE via Internal Services"],
    riskImpact: "SSRF allows attackers to make the server perform requests to internal resources, potentially accessing cloud metadata services, internal APIs, and exfiltrating credentials.",
    remediation: "Validate and allowlist URLs. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x). Disable unnecessary URL-fetching features.",
    keywords: ["ssrf", "server-side request", "url redirect", "open redirect fetch", "request forgery"],
  },
  {
    id: "CWE-601",
    name: "URL Redirection to Untrusted Site ('Open Redirect')",
    shortName: "Open Redirect",
    top25: null,
    cvss: 6.1,
    severity: "Medium",
    attackVector: "Network",
    attackTypes: ["Phishing", "Credential Harvesting", "Malware Distribution"],
    riskImpact: "Attackers craft URLs that redirect users from a trusted domain to a malicious site, facilitating phishing attacks and bypassing security filters.",
    remediation: "Validate redirect URLs against an allow-list. Avoid using user-supplied input in redirect destinations.",
    keywords: ["open redirect", "redirect", "unvalidated redirect", "url redirect"],
  },
  {
    id: "CWE-400",
    name: "Uncontrolled Resource Consumption",
    shortName: "Resource Exhaustion / DoS",
    top25: null,
    cvss: 7.5,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Denial of Service", "Application Crash", "Resource Exhaustion"],
    riskImpact: "Uncontrolled loops, unbounded memory allocation, or missing rate limiting allows attackers to exhaust server resources, causing denial of service for legitimate users.",
    remediation: "Implement rate limiting, timeouts, and resource quotas. Validate input sizes before processing.",
    keywords: ["resource exhaustion", "infinite loop", "dos", "denial of service", "memory exhaustion", "cpu exhaustion", "s2189"],
  },
  {
    id: "CWE-209",
    name: "Generation of Error Message Containing Sensitive Information",
    shortName: "Sensitive Error Messages",
    top25: null,
    cvss: 5.3,
    severity: "Medium",
    attackVector: "Network",
    attackTypes: ["Information Disclosure", "Reconnaissance", "Targeted Attack Facilitation"],
    riskImpact: "Verbose error messages revealing stack traces, database structure, or internal paths help attackers understand the system and craft targeted attacks.",
    remediation: "Use generic error messages in production. Log detailed errors server-side only. Implement a global exception handler.",
    keywords: ["exception", "error handling", "stack trace", "s112", "s1166", "generic exception", "log error"],
  },
  {
    id: "CWE-532",
    name: "Insertion of Sensitive Information into Log File",
    shortName: "Sensitive Log Data",
    top25: null,
    cvss: 5.5,
    severity: "Medium",
    attackVector: "Local",
    attackTypes: ["Information Disclosure", "Credential Theft", "Compliance Violation"],
    riskImpact: "Logging sensitive data (passwords, tokens, PII) creates audit trails that expose confidential information to anyone with log access.",
    remediation: "Never log passwords, tokens, or PII. Use structured logging with field filtering. Implement log retention policies.",
    keywords: ["log", "logging", "system.out", "console.log", "s106", "print sensitive", "log password"],
  },
  {
    id: "CWE-330",
    name: "Use of Insufficiently Random Values",
    shortName: "Weak Randomness",
    top25: null,
    cvss: 7.5,
    severity: "High",
    attackVector: "Network",
    attackTypes: ["Predictable Token Forgery", "Session Hijacking", "Crypto Break"],
    riskImpact: "Using non-cryptographic random number generators for security-sensitive values (tokens, nonces, keys) produces predictable values that attackers can guess.",
    remediation: "Use cryptographically secure RNG (SecureRandom in Java, secrets module in Python, crypto.randomBytes in Node.js).",
    keywords: ["random", "weak random", "predictable", "math.random", "s2245", "insecure random"],
  },
  {
    id: "CWE-693",
    name: "Protection Mechanism Failure",
    shortName: "Protection Mechanism Failure",
    top25: null,
    cvss: 5,
    severity: "Medium",
    attackVector: "Network",
    attackTypes: ["Security Control Bypass", "Unspecified Exploitation"],
    riskImpact: "A general weakness in security mechanisms that may allow various forms of exploitation depending on the specific context.",
    remediation: "Review security controls. Apply defense-in-depth. Follow secure coding guidelines.",
    keywords: [],   // default fallback
  },
];

// ── SonarQube rule key → CWE override ──────────────────────────────────────
const RULE_TO_CWE = {
  "java:S2077": "CWE-89",  "java:S3649": "CWE-89",  "java:S2076": "CWE-89",
  "java:S5131": "CWE-79",  "java:S4684": "CWE-79",
  "java:S2068": "CWE-798", "java:S6437": "CWE-798",
  "java:S6096": "CWE-22",  "java:S2083": "CWE-22",
  "java:S2259": "CWE-476",
  "java:S5542": "CWE-327", "java:S5547": "CWE-327", "java:S2278": "CWE-327", "java:S4790": "CWE-327",
  "java:S4502": "CWE-352",
  "java:S2755": "CWE-611",
  "java:S2445": "CWE-362",
  "java:S1948": "CWE-502",
  "java:S2245": "CWE-330",
  "java:S112":  "CWE-209", "java:S1166": "CWE-209",
  "java:S106":  "CWE-532",
  "java:S2189": "CWE-400",
  // JavaScript / Docker rules seen in this project
  "javascript:S1523": "CWE-94",  "javascript:S2077": "CWE-89",  "javascript:S5122": "CWE-942",
  "javascript:S5689": "CWE-200", "javascript:S2068": "CWE-798", "javascript:S4502": "CWE-352",
  "docker:S6471": "CWE-250",     "docker:S6596": "CWE-829",     "docker:S6470": "CWE-200",
};

// ── CWE lookup map ──────────────────────────────────────────────────────────
const cweMap = Object.fromEntries(CWE_DATABASE.map(c => [c.id, c]));

/** Knowledge-base entry for a CWE id ("CWE-89"), or null if unknown. */
export function getCWE(id) {
  return cweMap[id] || null;
}
const fallbackCWE = cweMap["CWE-693"];

/**
 * Map a single SonarQube issue to its CWE entry.
 * Priority: exact rule key → keyword match → default
 */
export function mapIssueToCWE(issue) {
  const text = `${issue.message || ""} ${issue.rule || ""}`.toLowerCase();

  // 0. CWE already known (unified findings from Semgrep / Trivy / ZAP / Snyk …)
  const known = String(Array.isArray(issue.cwe) ? issue.cwe[0] : issue.cwe || "").match(/CWE-\d+/i)?.[0]?.toUpperCase();
  if (known && cweMap[known] && known !== "CWE-693") return cweMap[known];

  // 1. Exact rule match
  const cweId = RULE_TO_CWE[issue.rule];
  if (cweId && cweMap[cweId]) return cweMap[cweId];

  // 2. Keyword match
  for (const cwe of CWE_DATABASE) {
    if (cwe.keywords.some(k => text.includes(k))) {
      return cwe;
    }
  }

  // 3. Type-based fallback
  if (issue.type === "VULNERABILITY") return cweMap["CWE-693"];
  if (issue.type === "SECURITY_HOTSPOT") return cweMap["CWE-693"];
  return fallbackCWE;
}

/**
 * Aggregate SonarQube issues into CWE groups with risk scoring.
 * @param {Array} issues — raw SonarQube issue objects
 * @returns {Array} cweFindings — grouped, scored, sorted by risk
 */
export function buildCWEFindings(issues) {
  const groups = {};   // cweId → { cwe, issues[], maxCvss }

  for (const issue of issues) {
    const cwe = mapIssueToCWE(issue);
    if (!groups[cwe.id]) {
      groups[cwe.id] = { cwe, issues: [], affectedFiles: new Set() };
    }
    groups[cwe.id].issues.push(issue);
    if (issue.component) groups[cwe.id].affectedFiles.add(issue.component);
  }

  // Build sorted findings
  const findings = Object.values(groups).map(({ cwe, issues: issList, affectedFiles }) => {
    // Risk score = CVSS × log(count+1), capped at 10
    const count = issList.length;
    const riskScore = Math.min(10, +(cwe.cvss * Math.log10(count + 2) * 0.8).toFixed(1));

    // Worst SonarQube severity in this group
    const sevOrder = { BLOCKER: 5, CRITICAL: 4, MAJOR: 3, MINOR: 2, INFO: 1 };
    const worstSev = issList.reduce((a, i) => {
      return (sevOrder[i.severity] || 0) > (sevOrder[a.severity] || 0) ? i : a;
    }, issList[0]).severity;

    return {
      cwe_id:       cwe.id,
      cwe_name:     cwe.name,
      cwe_short:    cwe.shortName || cwe.name,
      cwe_top25:    cwe.top25 || null,
      cvss_score:   cwe.cvss,
      severity:     cwe.severity,
      sonar_severity: worstSev,
      risk_score:   riskScore,
      attack_vector: cwe.attackVector,
      attack_types:  cwe.attackTypes,
      risk_impact:   cwe.riskImpact,
      remediation:   cwe.remediation,
      issue_count:   count,
      affected_files: affectedFiles.size,
      issues: issList.map(i => ({
        key:       i.key,
        type:      i.type,
        severity:  i.severity,
        rule:      i.rule,
        message:   i.message,
        component: i.component,
        line:      i.line,
      })),
    };
  });

  // Sort: Critical first, then by risk score descending
  const sevSort = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  findings.sort((a, b) =>
    (sevSort[b.severity] - sevSort[a.severity]) || (b.risk_score - a.risk_score)
  );

  return findings;
}

/**
 * Build top-level risk summary from CWE findings.
 */
export function buildRiskSummary(findings, totalIssues) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  // Overall risk level
  let level = "Low";
  if (counts.Critical > 0) level = "Critical";
  else if (counts.High > 0) level = "High";
  else if (counts.Medium > 0) level = "Medium";

  // Risk score: weighted average of CWE risk scores
  const avgRisk = findings.length
    ? +(findings.reduce((a, f) => a + f.risk_score, 0) / findings.length).toFixed(1)
    : 0;

  const topRisks = findings.slice(0, 3).map(f => ({
    cwe_id:      f.cwe_id,
    cwe_name:    f.cwe_name,
    severity:    f.severity,
    cvss_score:  f.cvss_score,
    issue_count: f.issue_count,
    attack_types: f.attack_types.slice(0, 2),
  }));

  return {
    overall_risk_level: level,
    overall_risk_score: avgRisk,
    total_issues:       totalIssues,
    unique_cwes:        findings.length,
    critical_cwes:      counts.Critical,
    high_cwes:          counts.High,
    medium_cwes:        counts.Medium,
    low_cwes:           counts.Low,
    top_risks:          topRisks,
  };
}
