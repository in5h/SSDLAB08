/**
 * threatMappings.js
 * Maps CWE IDs to MITRE ATT&CK techniques, OWASP Top 10 / API Top 10,
 * and CAPEC attack patterns for heatmap generation on the Risk page.
 */

// ── MITRE ATT&CK technique catalogue ──────────────────────────────────────
export const MITRE_TECHNIQUES = {
  "T1190": { id:"T1190", name:"Exploit Public-Facing Application", tactic:"Initial Access",   severity:"Critical" },
  "T1059": { id:"T1059", name:"Command and Scripting Interpreter",  tactic:"Execution",       severity:"Critical" },
  "T1203": { id:"T1203", name:"Exploitation for Client Execution",  tactic:"Execution",       severity:"High" },
  "T1068": { id:"T1068", name:"Exploitation for Privilege Escalation", tactic:"Privilege Escalation", severity:"Critical" },
  "T1552": { id:"T1552", name:"Unsecured Credentials",              tactic:"Credential Access", severity:"Critical" },
  "T1078": { id:"T1078", name:"Valid Accounts",                     tactic:"Persistence",     severity:"Critical" },
  "T1110": { id:"T1110", name:"Brute Force",                        tactic:"Credential Access", severity:"High" },
  "T1557": { id:"T1557", name:"Adversary-in-the-Middle",            tactic:"Credential Access", severity:"High" },
  "T1071": { id:"T1071", name:"Application Layer Protocol",         tactic:"Command and Control", severity:"High" },
  "T1499": { id:"T1499", name:"Endpoint Denial of Service",         tactic:"Impact",          severity:"High" },
  "T1565": { id:"T1565", name:"Data Manipulation",                  tactic:"Impact",          severity:"High" },
  "T1005": { id:"T1005", name:"Data from Local System",             tactic:"Collection",      severity:"Medium" },
  "T1530": { id:"T1530", name:"Data from Cloud Storage",            tactic:"Collection",      severity:"High" },
  "T1040": { id:"T1040", name:"Network Sniffing",                   tactic:"Credential Access", severity:"Medium" },
  "T1592": { id:"T1592", name:"Gather Victim Host Information",     tactic:"Reconnaissance",  severity:"Low" },
  "T1595": { id:"T1595", name:"Active Scanning",                    tactic:"Reconnaissance",  severity:"Medium" },
  "T1562": { id:"T1562", name:"Impair Defenses",                    tactic:"Defense Evasion",  severity:"High" },
  "T1114": { id:"T1114", name:"Email Collection",                   tactic:"Collection",      severity:"Medium" },
  "T1185": { id:"T1185", name:"Browser Session Hijacking",          tactic:"Collection",      severity:"High" },
  "T1189": { id:"T1189", name:"Drive-by Compromise",                tactic:"Initial Access",  severity:"High" },
};

// ── OWASP Top 10 2021 + API Top 10 2023 ───────────────────────────────────
export const OWASP_CATEGORIES = {
  "A01": { id:"A01:2021", name:"Broken Access Control",           severity:"Critical" },
  "A02": { id:"A02:2021", name:"Cryptographic Failures",          severity:"Critical" },
  "A03": { id:"A03:2021", name:"Injection",                       severity:"Critical" },
  "A04": { id:"A04:2021", name:"Insecure Design",                 severity:"High" },
  "A05": { id:"A05:2021", name:"Security Misconfiguration",       severity:"High" },
  "A06": { id:"A06:2021", name:"Vulnerable Components",           severity:"High" },
  "A07": { id:"A07:2021", name:"Auth & Identity Failures",        severity:"Critical" },
  "A08": { id:"A08:2021", name:"Software & Data Integrity",       severity:"High" },
  "A09": { id:"A09:2021", name:"Logging & Monitoring Failures",   severity:"Medium" },
  "A10": { id:"A10:2021", name:"Server-Side Request Forgery",     severity:"Critical" },
  "API1": { id:"API1:2023", name:"Broken Object Level Auth",      severity:"Critical" },
  "API2": { id:"API2:2023", name:"Broken Authentication",         severity:"Critical" },
  "API3": { id:"API3:2023", name:"Broken Object Property Auth",   severity:"High" },
  "API4": { id:"API4:2023", name:"Unrestricted Resource Consumption", severity:"High" },
  "API5": { id:"API5:2023", name:"Broken Function Level Auth",    severity:"Critical" },
  "API8": { id:"API8:2023", name:"Security Misconfiguration",     severity:"High" },
};

// ── CAPEC attack pattern catalogue ────────────────────────────────────────
export const CAPEC_PATTERNS = {
  "CAPEC-66":  { id:"CAPEC-66",  name:"SQL Injection",                  severity:"Critical" },
  "CAPEC-86":  { id:"CAPEC-86",  name:"XSS via HTTP Headers",           severity:"High" },
  "CAPEC-63":  { id:"CAPEC-63",  name:"Cross-Site Scripting (XSS)",     severity:"High" },
  "CAPEC-196": { id:"CAPEC-196", name:"Session Credential Falsification", severity:"Critical" },
  "CAPEC-191": { id:"CAPEC-191", name:"Read Sensitive Strings in Executable", severity:"High" },
  "CAPEC-126": { id:"CAPEC-126", name:"Path Traversal",                 severity:"High" },
  "CAPEC-100": { id:"CAPEC-100", name:"Overflow Buffers",               severity:"Critical" },
  "CAPEC-20":  { id:"CAPEC-20",  name:"Encryption Brute Forcing",       severity:"High" },
  "CAPEC-62":  { id:"CAPEC-62",  name:"Cross-Site Request Forgery",     severity:"High" },
  "CAPEC-201": { id:"CAPEC-201", name:"XML Entity Expansion",           severity:"Critical" },
  "CAPEC-26":  { id:"CAPEC-26",  name:"Leveraging Race Conditions",     severity:"High" },
  "CAPEC-122": { id:"CAPEC-122", name:"Privilege Abuse",                severity:"Critical" },
  "CAPEC-586": { id:"CAPEC-586", name:"Object Injection",               severity:"Critical" },
  "CAPEC-664": { id:"CAPEC-664", name:"Server-Side Request Forgery",    severity:"Critical" },
  "CAPEC-194": { id:"CAPEC-194", name:"Fake the Source of Data",        severity:"Medium" },
  "CAPEC-125": { id:"CAPEC-125", name:"Flooding",                       severity:"High" },
  "CAPEC-54":  { id:"CAPEC-54",  name:"Query System for Information",   severity:"Medium" },
  "CAPEC-215": { id:"CAPEC-215", name:"Fuzzing for Application Mapping", severity:"Medium" },
  "CAPEC-112": { id:"CAPEC-112", name:"Brute Force",                    severity:"High" },
  "CAPEC-242": { id:"CAPEC-242", name:"Code Injection",                 severity:"Critical" },
  "CAPEC-111": { id:"CAPEC-111", name:"JSON Hijacking",                 severity:"Medium" },
  "CAPEC-31":  { id:"CAPEC-31",  name:"Accessing/Modifying HTTP Cookies", severity:"High" },
  "CAPEC-103": { id:"CAPEC-103", name:"Clickjacking",                   severity:"Medium" },
  "CAPEC-310": { id:"CAPEC-310", name:"Scanning for Vulnerable Software", severity:"High" },
  "CAPEC-538": { id:"CAPEC-538", name:"Open-Source Library Manipulation", severity:"High" },
  "CAPEC-157": { id:"CAPEC-157", name:"Sniffing Attacks",               severity:"High" },
  "CAPEC-118": { id:"CAPEC-118", name:"Collect and Analyze Information", severity:"Medium" },
};

// ── CWE → threat intelligence mappings ────────────────────────────────────
export const CWE_THREAT_MAP = {
  "CWE-89":  { mitre:["T1190","T1059"],       owasp:["A03"],        capec:["CAPEC-66"] },
  "CWE-79":  { mitre:["T1189","T1185","T1203"], owasp:["A03"],      capec:["CAPEC-86","CAPEC-63"] },
  "CWE-798": { mitre:["T1552","T1078"],       owasp:["A07"],        capec:["CAPEC-191"] },
  "CWE-22":  { mitre:["T1005","T1190"],       owasp:["A01"],        capec:["CAPEC-126"] },
  "CWE-476": { mitre:["T1499"],               owasp:["A05"],        capec:["CAPEC-100"] },
  "CWE-787": { mitre:["T1068","T1203"],       owasp:["A03"],        capec:["CAPEC-100"] },
  "CWE-125": { mitre:["T1005","T1592"],       owasp:["A05"],        capec:["CAPEC-100"] },
  "CWE-327": { mitre:["T1557","T1040"],       owasp:["A02"],        capec:["CAPEC-20"] },
  "CWE-352": { mitre:["T1185","T1565"],       owasp:["A01"],        capec:["CAPEC-62"] },
  "CWE-611": { mitre:["T1190","T1005"],       owasp:["A05"],        capec:["CAPEC-201"] },
  "CWE-362": { mitre:["T1068"],               owasp:["A04"],        capec:["CAPEC-26"] },
  "CWE-862": { mitre:["T1078","T1068"],       owasp:["A01","API1","API5"], capec:["CAPEC-122"] },
  "CWE-502": { mitre:["T1059","T1068"],       owasp:["A08"],        capec:["CAPEC-586"] },
  "CWE-918": { mitre:["T1190","T1071"],       owasp:["A10"],        capec:["CAPEC-664"] },
  "CWE-601": { mitre:["T1189"],               owasp:["A01"],        capec:["CAPEC-194"] },
  "CWE-400": { mitre:["T1499"],               owasp:["A05","API4"], capec:["CAPEC-125"] },
  "CWE-209": { mitre:["T1592"],               owasp:["A05"],        capec:["CAPEC-54"] },
  "CWE-532": { mitre:["T1005","T1552"],       owasp:["A09"],        capec:["CAPEC-215"] },
  "CWE-330": { mitre:["T1110"],               owasp:["A02"],        capec:["CAPEC-112"] },
  "CWE-693": { mitre:["T1562"],               owasp:["A05"],        capec:["CAPEC-122"] },
  "CWE-94":   { mitre:["T1059","T1190"],       owasp:["A03"],        capec:["CAPEC-242"] },
  "CWE-942":  { mitre:["T1185"],               owasp:["A05"],        capec:["CAPEC-111"] },
  "CWE-1004": { mitre:["T1185"],               owasp:["A05"],        capec:["CAPEC-31"] },
  "CWE-1021": { mitre:["T1189"],               owasp:["A05"],        capec:["CAPEC-103"] },
  "CWE-250":  { mitre:["T1068"],               owasp:["A05"],        capec:["CAPEC-122"] },
  "CWE-1104": { mitre:["T1190"],               owasp:["A06"],        capec:["CAPEC-310"] },
  "CWE-829":  { mitre:["T1190"],               owasp:["A08"],        capec:["CAPEC-538"] },
  "CWE-319":  { mitre:["T1040","T1557"],       owasp:["A02"],        capec:["CAPEC-157"] },
  "CWE-200":  { mitre:["T1592"],               owasp:["A01"],        capec:["CAPEC-118"] },
};

/**
 * Resolve full threat mapping for a CWE ID.
 * Returns { mitre: [...], owasp: [...], capec: [...] } with full metadata.
 */
export function resolveThreatMapping(cweId) {
  const map = CWE_THREAT_MAP[cweId] || CWE_THREAT_MAP["CWE-693"];
  return {
    mitre: (map.mitre || []).map(id => MITRE_TECHNIQUES[id]).filter(Boolean),
    owasp: (map.owasp || []).map(id => OWASP_CATEGORIES[id]).filter(Boolean),
    capec: (map.capec || []).map(id => CAPEC_PATTERNS[id]).filter(Boolean),
  };
}

/**
 * Build heatmap aggregation data from an array of CWE findings.
 * Each finding must have cwe_id set.
 */
export function buildHeatmaps(findings) {
  const mitre = {};    // technique_id → { ...technique, count, cwes[] }
  const owasp = {};    // category_id → { ...category, count, cwes[] }
  const capec = {};    // pattern_id  → { ...pattern,  count, cwes[] }

  for (const f of findings) {
    const map = CWE_THREAT_MAP[f.cwe_id] || CWE_THREAT_MAP["CWE-693"];

    for (const id of (map.mitre || [])) {
      const t = MITRE_TECHNIQUES[id];
      if (!t) continue;
      if (!mitre[id]) mitre[id] = { ...t, count: 0, issues: 0, cwes: [] };
      mitre[id].count++;
      mitre[id].issues += f.issue_count || 0;
      mitre[id].cwes.push(f.cwe_id);
    }
    for (const id of (map.owasp || [])) {
      const o = OWASP_CATEGORIES[id];
      if (!o) continue;
      if (!owasp[id]) owasp[id] = { ...o, count: 0, issues: 0, cwes: [] };
      owasp[id].count++;
      owasp[id].issues += f.issue_count || 0;
      owasp[id].cwes.push(f.cwe_id);
    }
    for (const id of (map.capec || [])) {
      const p = CAPEC_PATTERNS[id];
      if (!p) continue;
      if (!capec[id]) capec[id] = { ...p, count: 0, issues: 0, cwes: [] };
      capec[id].count++;
      capec[id].issues += f.issue_count || 0;
      capec[id].cwes.push(f.cwe_id);
    }
  }

  const sortDesc = obj => Object.values(obj).sort((a, b) => b.issues - a.issues);
  return { mitre: sortDesc(mitre), owasp: sortDesc(owasp), capec: sortDesc(capec) };
}
