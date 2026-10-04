// src/services/grcMappingService.js
// Rule-based multi-framework GRC mapping using SonarQube severity, type, and rule patterns.
// Used as fallback when the Python RAG service is offline.
// Supports: NIST CSF 2.0, ISO 27001, ISO 27034, NIST SP 800-53, CIS Controls v8, OWASP ASVS v4

// ── Type-based mappings for all 6 frameworks ──────────────────────
const TYPE_MAPPINGS = {
  VULNERABILITY: {
    nist_csf:    ["PR.DS-01", "PR.AA-01", "ID.RA-01"],
    cis_controls: ["CIS-4", "CIS-16"],
    iso_27001:    ["A.8.28", "A.8.29"],
    nist_sp800:   ["SI-10", "RA-5"],
    iso27034:     ["ISO27034-ASC-8", "ISO27034-ASC-9"],
    owasp_asvs:   ["ASVS-V5.3", "ASVS-V14.2"],
  },
  BUG: {
    nist_csf:    ["PR.PS-01", "PR.PS-02", "PR.PS-01"],
    cis_controls: ["CIS-4"],
    iso_27001:    ["A.8.25"],
    nist_sp800:   ["SI-2", "CM-6"],
    iso27034:     ["ISO27034-ASC-16"],
    owasp_asvs:   ["ASVS-V14.3"],
  },
  SECURITY_HOTSPOT: {
    nist_csf:    ["PR.DS-01", "PR.DS-02", "DE.CM-01"],
    cis_controls: ["CIS-4", "CIS-13"],
    iso_27001:    ["A.8.24", "A.8.29"],
    nist_sp800:   ["SC-13", "CA-7"],
    iso27034:     ["ISO27034-ASC-11", "ISO27034-ASC-19"],
    owasp_asvs:   ["ASVS-V6.2", "ASVS-V10.1"],
  },
  CODE_SMELL: {
    nist_csf:    ["PR.PS-01", "GV.RM-01"],
    cis_controls: ["CIS-4"],
    iso_27001:    ["A.8.25"],
    nist_sp800:   ["SA-15"],
    iso27034:     ["ISO27034-ASC-16"],
    owasp_asvs:   ["ASVS-V14.3"],
  },
};

// ── Keyword → specific controls across all frameworks ──
const KEYWORD_RULES = [
  { kw: ["sql injection", "sqli"],
    nist_csf: ["PR.DS-01", "PR.AA-01", "PR.DS-02"], iso: ["A.8.28", "A.8.29"],
    nist_sp800: ["SI-10", "SA-11"], iso27034: ["ISO27034-ASC-10", "ISO27034-ASC-8"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V5.3"] },
  { kw: ["xss", "cross-site scripting", "output encoding", "escape"],
    nist_csf: ["PR.DS-01", "PR.DS-01", "PR.PS-01"], iso: ["A.8.24", "A.8.29"],
    nist_sp800: ["SI-10"], iso27034: ["ISO27034-ASC-9"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V5.2", "ASVS-V5.3"] },
  { kw: ["csrf", "cross-site request"],
    nist_csf: ["PR.AA-01", "PR.AA-05"], iso: ["A.8.29"],
    nist_sp800: ["SC-23"], iso27034: ["ISO27034-ASC-7"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V13.2", "ASVS-V3.4"] },
  { kw: ["dependency", "cve", "library", "outdated", "vulnerable component"],
    nist_csf: ["ID.RA-01", "ID.RA-01"], iso: ["A.12.6.1"],
    nist_sp800: ["RA-5", "SI-2", "CM-8"], iso27034: ["ISO27034-ASC-17"],
    cis: ["CIS-2.2", "CIS-7.4"], owasp: ["ASVS-V14.2"] },
  { kw: ["null pointer", "nullpointer", "null dereference", "npe"],
    nist_csf: ["PR.PS-02", "PR.PS-01"], iso: ["A.8.25"],
    nist_sp800: ["SI-16"], iso27034: ["ISO27034-ASC-14"],
    cis: ["CIS-16.1"], owasp: ["ASVS-V5.4"] },
  { kw: ["exception", "error handling", "catch"],
    nist_csf: ["PR.PS-01", "RS.MA-01"], iso: ["A.8.25"],
    nist_sp800: ["SI-10"], iso27034: ["ISO27034-ASC-14"],
    cis: ["CIS-16.1"], owasp: ["ASVS-V7.4"] },
  { kw: ["authentication", "auth", "password", "credential", "login", "session"],
    nist_csf: ["PR.AA-01", "PR.AA-05", "PR.DS-01"], iso: ["A.5.17", "A.8.5"],
    nist_sp800: ["IA-2", "IA-5"], iso27034: ["ISO27034-ASC-5"],
    cis: ["CIS-5.2", "CIS-6.3"], owasp: ["ASVS-V2.1", "ASVS-V2.4"] },
  { kw: ["authorization", "privilege", "permission", "access control", "role"],
    nist_csf: ["PR.AA-05", "PR.AA-01"], iso: ["A.5.15", "A.8.2"],
    nist_sp800: ["AC-3", "AC-6"], iso27034: ["ISO27034-ASC-6"],
    cis: ["CIS-6", "CIS-6.8"], owasp: ["ASVS-V4.1", "ASVS-V4.2"] },
  { kw: ["crypto", "encrypt", "cipher", "tls", "ssl", "certificate", "hash", "random"],
    nist_csf: ["PR.DS-02", "PR.DS-01"], iso: ["A.8.24"],
    nist_sp800: ["SC-8", "SC-13", "SC-12"], iso27034: ["ISO27034-ASC-11", "ISO27034-ASC-13"],
    cis: ["CIS-3.10", "CIS-3.11"], owasp: ["ASVS-V6.2", "ASVS-V9.1"] },
  { kw: ["injection", "command injection", "ldap", "xpath", "template injection"],
    nist_csf: ["PR.DS-01", "PR.PS-01"], iso: ["A.8.28"],
    nist_sp800: ["SI-10", "SI-3"], iso27034: ["ISO27034-ASC-10"],
    cis: ["CIS-10", "CIS-16.12"], owasp: ["ASVS-V5.3"] },
  { kw: ["log", "audit", "monitor", "logging"],
    nist_csf: ["DE.CM-01", "DE.AE-02"], iso: ["A.8.15", "A.8.16"],
    nist_sp800: ["AU-2", "AU-3"], iso27034: ["ISO27034-ASC-15"],
    cis: ["CIS-8", "CIS-8.2"], owasp: ["ASVS-V7.1", "ASVS-V7.2"] },
  { kw: ["container", "docker", "image", "kubernetes"],
    nist_csf: ["ID.RA-01", "PR.PS-01"], iso: ["A.14.2.8"],
    nist_sp800: ["CM-6", "CM-7"], iso27034: ["ISO27034-ASC-18"],
    cis: ["CIS-4", "CIS-16.7"], owasp: ["ASVS-V14.1"] },
  { kw: ["hardcod", "secret", "api key", "token", "private key"],
    nist_csf: ["PR.DS-01", "PR.AA-01"], iso: ["A.5.17", "A.8.24"],
    nist_sp800: ["IA-5", "SC-12"], iso27034: ["ISO27034-ASC-12"],
    cis: ["CIS-5.2", "CIS-3.11"], owasp: ["ASVS-V6.4"] },
  { kw: ["path traversal", "directory traversal", "file inclusion"],
    nist_csf: ["PR.DS-01", "PR.AA-05"], iso: ["A.8.28"],
    nist_sp800: ["SI-10"], iso27034: ["ISO27034-ASC-8"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V12.3"] },
  { kw: ["deserialization", "serializ"],
    nist_csf: ["PR.DS-01", "PR.PS-02"], iso: ["A.8.28"],
    nist_sp800: ["SI-3", "SI-10"], iso27034: ["ISO27034-ASC-10"],
    cis: ["CIS-10"], owasp: ["ASVS-V5.5"] },
  { kw: ["xxe", "xml external"],
    nist_csf: ["PR.DS-01", "PR.PS-01"], iso: ["A.8.29"],
    nist_sp800: ["SI-10"], iso27034: ["ISO27034-ASC-8"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V13.3"] },
  { kw: ["open redirect", "redirect"],
    nist_csf: ["PR.DS-01", "PR.AA-05"], iso: ["A.8.29"],
    nist_sp800: ["AC-4"], iso27034: ["ISO27034-ASC-8"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V13.1"] },
  { kw: ["buffer overflow", "memory", "stack"],
    nist_csf: ["PR.PS-02", "PR.DS-01"], iso: ["A.8.25"],
    nist_sp800: ["SI-16"], iso27034: ["ISO27034-ASC-10"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V5.4"] },
  { kw: ["information disclosure", "sensitive data", "pii", "privacy"],
    nist_csf: ["PR.DS-01", "PR.DS-02", "GV.RM-01"], iso: ["A.8.11", "A.8.12"],
    nist_sp800: ["SC-28", "IA-6"], iso27034: ["ISO27034-ASC-12"],
    cis: ["CIS-3", "CIS-3.6"], owasp: ["ASVS-V8.1", "ASVS-V8.3"] },
  { kw: ["race condition", "concurren", "thread"],
    nist_csf: ["PR.PS-01", "PR.PS-02"], iso: ["A.8.25"],
    nist_sp800: ["SI-16"], iso27034: ["ISO27034-ASC-10"],
    cis: ["CIS-16.1"], owasp: ["ASVS-V11.1"] },
  { kw: ["dead code", "unused", "empty", "void", "unreachable"],
    nist_csf: ["PR.PS-01", "GV.RM-01"], iso: ["A.8.25"],
    nist_sp800: ["SA-15"], iso27034: ["ISO27034-ASC-16"],
    cis: ["CIS-4.8"], owasp: ["ASVS-V14.3"] },
  { kw: ["input validation", "sanitiz", "whitelist", "blacklist"],
    nist_csf: ["PR.DS-01", "PR.PS-01"], iso: ["A.8.28"],
    nist_sp800: ["SI-10"], iso27034: ["ISO27034-ASC-8"],
    cis: ["CIS-16.12"], owasp: ["ASVS-V5.1"] },
  { kw: ["ssrf", "server-side request"],
    nist_csf: ["PR.DS-01", "PR.AA-05", "DE.CM-01"], iso: ["A.8.20"],
    nist_sp800: ["AC-4", "SC-8"], iso27034: ["ISO27034-ASC-8"],
    cis: ["CIS-12", "CIS-16.12"], owasp: ["ASVS-V13.1"] },
];

// ── SonarQube rule prefix → NIST controls ──────────────────────────
const RULE_PREFIX_MAPPINGS = {
  "java:S2076":  { nist_csf: ["PR.DS-01"],         desc: "OS command injection" },
  "java:S2077":  { nist_csf: ["PR.DS-01"],         desc: "SQL injection" },
  "java:S3649":  { nist_csf: ["PR.DS-01"],         desc: "SQL injection" },
  "java:S5131":  { nist_csf: ["PR.DS-01","PR.DS-01"], desc: "XSS" },
  "java:S2755":  { nist_csf: ["PR.DS-01"],         desc: "XXE" },
  "java:S1948":  { nist_csf: ["PR.DS-01"],         desc: "Serializable" },
  "java:S5542":  { nist_csf: ["PR.DS-02"],         desc: "Weak crypto" },
  "java:S5547":  { nist_csf: ["PR.DS-02"],         desc: "Weak cipher" },
  "java:S2278":  { nist_csf: ["PR.DS-02"],         desc: "DES cipher" },
  "java:S4790":  { nist_csf: ["PR.DS-01"],         desc: "Weak hash" },
  "java:S2068":  { nist_csf: ["PR.DS-01","PR.AA-01"], desc: "Hardcoded credential" },
  "java:S6437":  { nist_csf: ["PR.DS-01","PR.AA-01"], desc: "Hardcoded secret" },
  "java:S1186":  { nist_csf: ["PR.PS-01"],          desc: "Empty method" },
  "java:S112":   { nist_csf: ["RS.MA-01"],         desc: "Generic exception" },
  "java:S106":   { nist_csf: ["DE.CM-01"],         desc: "System.out logs" },
  "java:S4502":  { nist_csf: ["PR.AA-01"],         desc: "CSRF" },
  "java:S5344":  { nist_csf: ["PR.DS-01"],         desc: "Weak password storage" },
  "Web:":        { nist_csf: ["PR.DS-01","PR.PS-01"], desc: "Web vulnerability" },
  "csharpsquid": { nist_csf: ["PR.PS-01"],         desc: "C# quality" },
  "python:":     { nist_csf: ["PR.PS-01"],         desc: "Python quality" },
};

function mapByKeyword(text) {
  const t = (text || "").toLowerCase();
  for (const rule of KEYWORD_RULES) {
    if (rule.kw.some(k => t.includes(k))) {
      return {
        nist_csf:     rule.nist_csf,
        cis_controls: rule.cis || ["CIS-4"],
        iso_27001:    rule.iso || ["A.8.28"],
        nist_sp800:   rule.nist_sp800 || ["SI-10"],
        iso27034:     rule.iso27034 || ["ISO27034-ASC-8"],
        owasp_asvs:   rule.owasp || ["ASVS-V5.3"],
      };
    }
  }
  return null;
}

function mapByRule(ruleKey) {
  if (!ruleKey) return null;
  if (RULE_PREFIX_MAPPINGS[ruleKey]) {
    return {
      nist_csf:     RULE_PREFIX_MAPPINGS[ruleKey].nist_csf,
      cis_controls: ["CIS-4"],
      iso_27001:    [],
      nist_sp800:   ["SI-10"],
      iso27034:     ["ISO27034-ASC-8"],
      owasp_asvs:   ["ASVS-V5.3"],
    };
  }
  for (const prefix of Object.keys(RULE_PREFIX_MAPPINGS)) {
    if (ruleKey.startsWith(prefix)) {
      return {
        nist_csf:     RULE_PREFIX_MAPPINGS[prefix].nist_csf,
        cis_controls: ["CIS-4"],
        iso_27001:    [],
        nist_sp800:   ["SI-10"],
        iso27034:     ["ISO27034-ASC-8"],
        owasp_asvs:   ["ASVS-V5.3"],
      };
    }
  }
  return null;
}

/**
 * Map a single SonarQube issue to GRC controls across all 6 frameworks.
 * Priority: rule prefix → keyword match → type default
 */
export function mapIssueToGRC(issue) {
  const text = `${issue.message || ""} ${issue.rule || ""}`.toLowerCase();
  const ruleMapping = mapByRule(issue.rule);
  const kwMapping   = mapByKeyword(text);
  const typeDefault = TYPE_MAPPINGS[issue.type] || TYPE_MAPPINGS.CODE_SMELL;

  const mapping = ruleMapping || kwMapping || typeDefault;
  const uniq = (list) => [...new Set(list)];
  return {
    title: `SonarQube finding`,
    description: issue.message || "",
    severity: issue.severity || "MINOR",
    grc_mapping: {
      nist_csf:     uniq(mapping.nist_csf || ["PR.PS-01"]),
      cis_controls: uniq(mapping.cis_controls || ["CIS-4"]),
      iso_27001:    uniq(mapping.iso_27001 || []),
      nist_sp800:   uniq(mapping.nist_sp800 || ["SI-10"]),
      iso27034:     uniq(mapping.iso27034 || ["ISO27034-ASC-8"]),
      owasp_asvs:   uniq(mapping.owasp_asvs || ["ASVS-V5.3"]),
    },
  };
}

/**
 * Map a list of SonarQube issues directly (preferred call from compliance.js).
 */
export function mapIssuesToGRC(issues) {
  return issues.map(issue => {
    const { grc_mapping } = mapIssueToGRC(issue);
    return {
      issue,
      nist_controls: grc_mapping.nist_csf.map(id => ({ control_id: id, confidence: 0.75 })),
      grc_mapping,
    };
  });
}

/**
 * Legacy text-based API kept for backward compatibility.
 */
export async function mapFindingsToGRC(toolName, findingsText) {
  const lines = (findingsText || "")
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l.length > 0);

  if (lines.length === 0) {
    return { summary: "No findings text provided.", overall_risk_level: "Low", items: [] };
  }

  const items = lines.map((line, idx) => {
    const fakeIssue = { message: line, type: "CODE_SMELL" };
    const mapped = mapIssueToGRC(fakeIssue);
    return {
      title: `Finding ${idx + 1} from ${toolName}`,
      description: line,
      severity: mapped.severity,
      grc_mapping: mapped.grc_mapping,
    };
  });

  return {
    summary: `Mapped ${items.length} findings from ${toolName} to NIST CSF, CIS Controls, ISO 27001, NIST SP 800-53, ISO 27034, and OWASP ASVS.`,
    overall_risk_level: items.some(i => i.severity === "Critical") ? "Critical"
      : items.some(i => i.severity === "High") ? "High"
      : items.length > 0 ? "Medium" : "Low",
    items,
  };
}
