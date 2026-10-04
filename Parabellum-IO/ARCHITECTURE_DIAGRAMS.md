# Parabellum Core Engine - Architecture & Data Flow Diagrams

## 📐 System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      PARABELLUM IO - CORE ENGINE                         │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐
│  SonarQube Instance  │
│   (Remote/Local)     │
└──────────────┬───────┘
               │
        Export (JSON/YAML)
               │
               ▼
    ┌──────────────────────────┐
    │  INGESTION ENGINE        │     ┌─────────────────────┐
    │                          │────▶│ Cache Management    │
    │ • Parse JSON/YAML        │     │ • Index inventory   │
    │ • Extract Issues array   │     │ • Store findings    │
    │ • Normalize fields       │     └─────────────────────┘
    │ • Compute hashes         │
    └──────────┬───────────────┘
               │
       Standardized Findings
               │
               ▼
    ┌──────────────────────────┐
    │   FINDING DIFFER         │     ┌─────────────────────┐
    │                          │────▶│ Diff Report         │
    │ • Compare with cache     │     │ • New findings      │
    │ • Track resolution       │     │ • Resolved issues   │
    │ • Severity changes       │     │ • Severity shifts   │
    │ • Unchanged tracking     │     └─────────────────────┘
    └──────────┬───────────────┘
               │
      Enriched Finding Batch
               │
               ▼
    ┌──────────────────────────────────────────┐
    │   RISK ANALYSIS MODULE                   │
    │                                          │
    │ ┌────────────────────────────────────┐   │
    │ │ CWE DATABASE                       │   │
    │ │ • 20+ CWE definitions              │   │
    │ │ • SonarQube rule mappings          │   │
    │ │ • Attack patterns                  │   │
    │ │ • OWASP categories                 │   │
    │ └────────────────────────────────────┘   │
    │           ▲                               │
    │           │                               │
    │ ┌────────────────────────────────────┐   │
    │ │ RISK SCORER                        │   │
    │ │ • CVSS × multipliers               │   │
    │ │ • Severity mapping                 │   │
    │ │ • Attack vector analysis           │   │
    │ │ • Risk level calculation (0-100)   │   │
    │ └────────────────────────────────────┘   │
    │           ▲                               │
    │           │                               │
    │ ┌────────────────────────────────────┐   │
    │ │ VULNERABILITY ANALYZER             │   │
    │ │ • CWE enrichment                   │   │
    │ │ • NIST CSF alignment               │   │
    │ │ • Attack pattern matching          │   │
    │ │ • Impact summary generation        │   │
    │ │ • Policy violation detection       │   │
    │ └────────────────────────────────────┘   │
    └──────────┬───────────────────────────────┘
               │
    Analyzed Findings with Risk Metadata
               │
               ▼
    ┌──────────────────────────────────────────┐
    │   COMPLIANCE REPORTER                    │
    │                                          │
    │ ┌─ Executive Summary ──────────────────┐ │
    │ │ • Compliance status (Pass/Fail)      │ │
    │ │ • Portfolio risk level               │ │
    │ │ • Key metrics dashboard              │ │
    │ └──────────────────────────────────────┘ │
    │                                          │
    │ ┌─ Technical Deep Dive ────────────────┐ │
    │ │ • CWE distribution                   │ │
    │ │ • Severity breakdown                 │ │
    │ │ • OWASP category mapping             │ │
    │ │ • Component inventory                │ │
    │ └──────────────────────────────────────┘ │
    │                                          │
    │ ┌─ Governance Mapping ─────────────────┐ │
    │ │ • NIST CSF 2.0 controls              │ │
    │ │ • OPA guardrail status               │ │
    │ │ • Policy compliance matrix           │ │
    │ └──────────────────────────────────────┘ │
    │                                          │
    │ ┌─ Recommendations ────────────────────┐ │
    │ │ • Critical actions (1h SLA)          │ │
    │ │ • High priority (1d SLA)             │ │
    │ │ • Medium term (1w SLA)               │ │
    │ └──────────────────────────────────────┘ │
    └──────────┬───────────────────────────────┘
               │
    ┌──────────┴───────────┬──────────────┬─────────────────┐
    │                      │              │                 │
    ▼                      ▼              ▼                 ▼
compliance_report    summary.json    session_log      portfolio_report
   (Text)          (Machine-readable)  (Audit)         (Multi-project)
```

---

## 🔄 Data Flow - Single Finding Analysis

```
┌──────────────────────────────────────────────────────────────────────────┐
│ SONARQUBE ISSUE (Input)                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│ {                                                                        │
│   "key": "AVxxx",                     // Unique identifier               │
│   "component": "project:File.java",   // File location                   │
│   "rule": "java:S2077",               // SonarQube rule ID              │
│   "severity": "CRITICAL",             // SonarQube severity              │
│   "type": "VULNERABILITY",            // Issue type (VULN/BUG/etc)      │
│   "message": "SQL injection...",      // Description                    │
│   "status": "OPEN"                    // Status                          │
│ }                                                                        │
└──────────────────────────────────────────────────────────────────────────┘
  │
  │ Step 1: Extract & Normalize
  │
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ CWE MAPPING                                                              │
├──────────────────────────────────────────────────────────────────────────┤
│ Rule "java:S2077" ──────────────────────────────────────────────┐       │
│                                                                 │       │
│ From SONARQUBE_RULE_TO_CWE mapping ──────▶ "CWE-89"            │       │
│                                                 │               │       │
│                                                 ▼               │       │
│                                    Get CWE Info from Database    │       │
│                                                 │               │       │
│                                                 ▼               │       │
│ CWE-89 Details:                                │               │       │
│ {                                              │               │       │
│   "name": "SQL Injection",                    │               │       │
│   "severity": "Critical",      ◀──────────────┘               │       │
│   "cvss_base": 9.8,                                           │       │
│   "nist_csf": ["PR.DS-01", "PR.AA-01"],                       │       │
│   "attack_vectors": ["NETWORK"],                              │       │
│   "impact_types": ["Confidentiality", "Integrity", "Availability"],   │
│   "risk_keywords": ["Remote Code Execution", "Data Leakage"],  
│   "owasp_category": "A03:2021 – Injection"                     
│ }                                                              │
└──────────────────────────────────────────────────────────────────────────┘
  │
  │ Step 2: Calculate Risk Score
  │
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ RISK CALCULATION                                                         │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ Base Score = CVSS × 10                                                  │
│            = 9.8 × 10 = 98                                              │
│                                                                          │
│ Severity Multiplier (Critical) = 4.0                                    │
│ Type Multiplier (VULNERABILITY) = 3.0                                   │
│ Attack Vector Multiplier (NETWORK) = 2.0                                │
│                                                                          │
│ Risk Score = (98 × 4.0 × 3.0 × 2.0) / 10                               │
│            = 2352 / 10 = 235.2                                          │
│            = Capped at 100 = 100.0                                      │
│                                                                          │
│ Risk Level = "Critical" (80-100 range)                                  │
│ Response SLA = "1 hour"                                                  │
│ Remediation Priority = 1 (Highest)                                      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
  │
  │ Step 3: Attack & Impact Analysis
  │
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ ATTACK PATTERN MATCHING                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ From CWE-89 (SQL Injection):                                            │
│ Applicable Attack Patterns:                                             │
│  • Remote Code Execution         (Likelihood: High, Impact: Critical)   │
│  • Data Leakage                  (Likelihood: High, Impact: Critical)   │
│                                                                          │
│ Impact Summary:                                                          │
│ "Improper SQL Query Construction → Risk: Remote Code Execution         │
│  and Data Leakage via Unauthorized Database Access"                    │
│                                                                          │
│ Components Impacted:                                                     │
│  □ API authentication bypass                                            │
│  □ Sensitive data exposure (passwords, PII)                             │
│  □ Production database compromise potential                             │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
  │
  │ Step 4: NIST & Policy Compliance
  │
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ GOVERNANCE MAPPING                                                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ NIST CSF 2.0 Controls Mapped:                                           │
│  • PR.DS-01 (Data Security)                                             │
│  • PR.AA-01 (Identity & Authentication)                                 │
│  • PR.PS-01 (Platform Security)                                         │
│                                                                          │
│ Policy Violations:                                                       │
│  ⚠️  Critical severity finding - violates threshold                     │
│  ⚠️  Unresolved security vulnerability                                  │
│  ⚠️  Requires NIST PR.DS-01 remediation                                 │
│                                                                          │
│ OPA Guardrail Status: FAIL                                              │
│  • Policy: "No critical vulnerabilities in production"                  │
│  • Result: VIOLATION (1 Critical finding detected)                      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
  │
  │ Final Output
  │
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ ENRICHED FINDING (Output)                                               │
├──────────────────────────────────────────────────────────────────────────┤
│ {                                                                        │
│   "original_issue": { ... },                                            │
│   "cwe_mapping": {                                                      │
│     "cwe_id": "CWE-89",                                                 │
│     "cwe_name": "SQL Injection",                                        │
│     "owasp_category": "A03:2021 – Injection"                           │
│   },                                                                    │
│   "risk_assessment": {                                                  │
│     "severity": "Critical",        ◄── From CWE, not SonarQube  │
│     "cvss_score": 9.8,                                          │
│     "risk_score": 100.0,           ◄── Composite calculation    │
│     "risk_level": "Critical",                                   │
│     "remediation_priority": 1,     ◄── Action now!              │
│     "response_time": "1 hour"                                    │
│   },                                                                    │
│   "attack_analysis": {                                                  │
│     "applicable_patterns": [                                            │
│       "Remote Code Execution",                                          │
│       "Data Leakage"                                                    │
│     ],                                                                  │
│     "attack_types": [ {...}, {...} ],                                   │
│     "impact_summary": "Improper SQL Construction → Risk: RCE..."       │
│   },                                                                    │
│   "compliance": {                                                       │
│     "nist_csf_controls": ["PR.DS-01", "PR.AA-01", "PR.PS-01"],         │
│     "policy_violations": [                                              │
│       "Critical severity finding - violates policy",                    │
│       "NIST PR.DS-01 remediation required"                              │
│     ]                                                                   │
│   },                                                                    │
│   "remediation": {                                                      │
│     "guidance": "1) Use parameterized queries...",                      │
│     "effort_estimate": "1h",                                            │
│     "technical_debt": "30min"                                           │
│   }                                                                     │
│ }                                                                        │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Batch Analysis - Aggregate Metrics

```
┌──────────────────────────────────────────────────────────────────────────┐
│ N FINDINGS INPUT                                                         │
│ (e.g., 42 issues from SonarQube export)                                  │
└──────────┬───────────────────────────────────────────────────────────────┘
           │
           │ Analyze each finding individually (see diagram above)
           │
           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ AGGREGATE ANALYSIS                                                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│ Severity Distribution:                                                   │
│  Critical: ███████ 7 findings (16.7%)                                    │
│  High:     ████████████████ 14 findings (33.3%)                         │
│  Medium:   ████████████░░░░ 14 findings (33.3%)                         │
│  Low:      ███ 7 findings (16.7%)                                        │
│                                                                          │
│ Risk Level Distribution:                                                 │
│  Critical: 7 (Immediate action required)                                 │
│  High:     14 (Within 1 week)                                            │
│  Medium:   14 (Within 1 month)                                           │
│  Low:      7 (Normal maintenance)                                        │
│                                                                          │
│ CWE Distribution (Top 5):                                                │
│  CWE-89 (SQL Injection):       8 occurrences                             │
│  CWE-79 (XSS):                 6 occurrences                             │
│  CWE-327 (Weak Crypto):        4 occurrences                             │
│  CWE-798 (Hardcoded Creds):    3 occurrences                             │
│  CWE-20 (Input Validation):    3 occurrences                             │
│                                                                          │
│ OWASP Top 10 Mapping:                                                    │
│  A03:2021 – Injection:         11 findings                               │
│  A01:2021 – Access Control:     6 findings                               │
│  A02:2021 – Cryptographic:      5 findings                               │
│  A04:2021 – Insecure Design:    4 findings                               │
│                                                                          │
│ NIST CSF 2.0 Coverage:                                                   │
│  PR.DS-01 (Data Security):        15 controls mapped                     │
│  PR.AA-01 (Authentication):       8 controls mapped                      │
│  PR.PS-01 (Platform Security):    10 controls mapped                     │
│  DE.CM-01 (Monitoring):           3 controls mapped                      │
│                                                                          │
│ Overall Metrics:                                                         │
│  Average Risk Score:    65.2 / 100                                       │
│  Total Technical Debt:  42 hours                                         │
│  Estimated Remediation: 2 weeks (sequential) / 3 days (parallel)        │
│                                                                          │
│ Portfolio Risk Assessment:                                               │
│  ⚠️  Portfolio Risk Level: HIGH                                          │
│  ⚠️  Requires Immediate Action: YES (7 critical)                         │
│  ⚠️  Policy Compliance: FAIL                                             │
│      → Threshold: Max 0 critical issues                                  │
│      → Actual: 7 critical issues found                                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📄 Compliance Report Structure

```
COMPLIANCE REPORT
═════════════════════════════════════════════════════════════════════════

Project: MyApplication
Scan Date: 2024-01-20
Report Date: 2024-01-20 14:32:00

─────────────────────────────────────────────────────────────────────────
SECTION 1: EXECUTIVE SUMMARY
─────────────────────────────────────────────────────────────────────────

Compliance Status: ❌ FAIL

Key Metrics:
  • Total Findings:        42
  • Critical Severity:     7
  • High Severity:         14
  • Average Risk Score:    65.2 / 100
  • Estimated Effort:      2 weeks

Portfolio Risk Level:    HIGH
Policy Compliance:       FAIL (Threshold: 0 critical, Found: 7)
Requires Action:         YES - Within 1 hour

Top Risk Areas:
  1. SQL Injection (CWE-89): 8 occurrences
  2. Cross-Site Scripting (CWE-79): 6 occurrences
  3. Weak Cryptography (CWE-327): 4 occurrences

─────────────────────────────────────────────────────────────────────────
SECTION 2: TECHNICAL DEEP DIVE
─────────────────────────────────────────────────────────────────────────

CWE Distribution:
  CWE-89:     ████████ 8
  CWE-79:     ██████ 6
  CWE-327:    ████ 4
  CWE-798:    ███ 3
  CWE-20:     ███ 3

OWASP Top 10 Alignment:
  A03:2021 – Injection:        11 findings
  A01:2021 – Access Control:    6 findings
  A02:2021 – Cryptographic:     5 findings
  A04:2021 – Insecure Design:   4 findings

Critical Vulnerabilities (Immediate Action):

  [1/7] SQL Injection in UserAuthController.java:152
       Component: app:UserAuthController.java
       Rule: java:S2077
       CWE: CWE-89 (SQL Injection)
       Risk Score: 100.0 / 100 (Critical)
       Impact: Remote Code Execution, Data Leakage, Unauthorized Access
       NIST Controls: PR.DS-01, PR.AA-01, PR.PS-01
       SLA: 1 hour
       Effort: 1 hour
       
  [2/7] XXE Vulnerability in XMLParser.java:87
       ... (similar detail)

High Severity Findings (Top 3):
  ... (14 total, showing first 3)

─────────────────────────────────────────────────────────────────────────
SECTION 3: GOVERNANCE MAPPING
─────────────────────────────────────────────────────────────────────────

NIST CSF 2.0 Control Alignment:

├─ PROTECT (PR)
│  ├─ PR.DS (Data Security)
│  │  └─ PR.DS-01 (Data Classification): 15 findings aligned
│  ├─ PR.AA (Identity & Access)
│  │  └─ PR.AA-01 (Identification): 8 findings aligned
│  └─ PR.PS (Platform Security)
│     └─ PR.PS-01 (Secure Configuration): 10 findings aligned
│
├─ DETECT (DE)
│  └─ DE.CM (Continuous Monitoring)
│     └─ DE.CM-01 (Monitoring): 3 findings aligned

Policy-as-Code (OPA) Guardrails:

  Policy: "Production Security Baseline"
  Status: ❌ FAIL
  
  Rule 1: No Critical vulnerabilities in production
    Status: ❌ FAIL
    Threshold: 0 critical issues
    Actual: 7 critical issues
    Implications: Production cannot be deployed

  Rule 2: High risk issues < 10
    Status: ⚠️  WARNING
    Threshold: < 10 high findings
    Actual: 14 high findings
    Implications: Requires exception approval

  Rule 3: Average risk score < 50
    Status: ⚠️  WARNING
    Threshold: < 50
    Actual: 65.2
    Implications: Portfolio risk is elevated

─────────────────────────────────────────────────────────────────────────
SECTION 4: RECOMMENDATIONS & ACTION PLAN
─────────────────────────────────────────────────────────────────────────

🔴 IMMEDIATE ACTIONS (Critical - 1 hour SLA):

  Priority 1: Fix SQL Injection in UserAuthController (CWE-89)
    Effort: 1 hour
    Guidance:
      - Use parameterized queries / prepared statements
      - Implement input validation whitelist
      - Use ORM (Hibernate, SQLAlchemy) when possible
      - Add SQL injection tests to CI/CD
    NIST Control: PR.DS-01 (Data Security)

  [... 6 more critical items ...]

🟠 SHORT-TERM REMEDIATION (High - 1 day SLA):

  Priority 2-7: XSS Vulnerabilities & Cryptography Issues
    Total Effort: 14 hours (2 days parallel work)
    Deadline: End of business day tomorrow

🟡 LONG-TERM IMPROVEMENTS (Medium - 1 week SLA):

  Priority 8+: Code quality and logging improvements
    Total Effort: 8 hours
    Deadline: End of sprint

─────────────────────────────────────────────────────────────────────────
SECTION 5: APPENDIX
─────────────────────────────────────────────────────────────────────────

Methodology:
  • Scanning Tool: SonarQube v9.8.0.56155
  • Analysis Standard: NIST CSF 2.0 + CWE MITRE
  • Risk Scoring: Composite CVSS-based algorithm
  • Scan Date: 2024-01-20 12:00:00 UTC

Severity Definitions:
  Critical (9.0-10):    Exploitable vulnerability requiring remediation within 1 hour
  High (7.0-8.9):       Significant risk requiring remediation within 1 day
  Medium (4.0-6.9):     Moderate risk requiring remediation within 1 week
  Low (0.1-3.9):        Minor risk addressing in normal maintenance

Attack Vector Mappings:
  NETWORK:      Remotely exploitable over network
  APPLICATION:  Exploitable via application logic
  LOCAL:        Requires local system access
  PHYSICAL:     Requires physical access to system

Disclaimer:
  This report is generated from static code analysis using SonarQube.
  It should be reviewed by security professionals and combined with:
    • Dynamic application security testing (DAST)
    • Penetration testing
    • Runtime monitoring
  for comprehensive security assessment.

═════════════════════════════════════════════════════════════════════════
End of Report
```

---

## 🔄 Session Workflow

```
TIME │ EVENT                                    │ STATUS
─────┼──────────────────────────────────────────┼─────────────────
T+0  │ SESSION START                            │ ✓ Initialized
     │ - Session ID: session_MyProject_...      │
     │ - Project: MyApplication                 │
     │ - Description: Q1 2024 Baseline Scan     │
─────┼──────────────────────────────────────────┼─────────────────
T+1s │ SONARQUBE EXPORT INGESTION               │ ✓ Processing
     │ - Read export.json (42 issues)           │
     │ - Parse to standard format               │
     │ - Compare with previous cache            │
     │ - Diff report: +5 new, -3 resolved       │
─────┼──────────────────────────────────────────┼─────────────────
T+2s │ CACHE UPDATE                             │ ✓ Saved
     │ - Store findings in cache                │
     │ - Update inventory index                 │
     │ - Export ID: export_20240120_143022      │
─────┼──────────────────────────────────────────┼─────────────────
T+3s │ VULNERABILITY ANALYSIS                   │ ✓ Analyzing
     │ - Enrich each of 42 findings             │
     │ - Map to CWE database                    │
     │ - Calculate risk scores                  │
     │ - Identify NIST controls                 │
     │ - Analyze attack patterns                │
─────┼──────────────────────────────────────────┼─────────────────
T+5s │ AGGREGATE METRICS COMPUTATION            │ ✓ Calculated
     │ - 7 critical, 14 high findings           │
     │ - Average risk: 65.2 / 100               │
     │ - Effort estimate: 2 weeks               │
     │ - Policy compliance: FAIL               │
─────┼──────────────────────────────────────────┼─────────────────
T+6s │ COMPLIANCE REPORT GENERATION             │ ✓ Generated
     │ - Executive summary                      │
     │ - Technical deep dive                    │
     │ - Governance mapping                     │
     │ - Recommendations                        │
     │ - Save report to disk                    │
─────┼──────────────────────────────────────────┼─────────────────
T+7s │ JSON SUMMARY CREATION                    │ ✓ Created
     │ - Machine-readable format                │
     │ - For API/UI consumption                 │
     │ - Save to reports directory              │
─────┼──────────────────────────────────────────┼─────────────────
T+8s │ SESSION COMPLETE                         │ ✓ Success
     │ - Session log saved                      │
     │ - Total events: 8                        │
     │ - Duration: 8 seconds                    │
     │ - Reports: 2 files generated             │
─────┴──────────────────────────────────────────┴─────────────────
```

---

## 📁 Output Files Structure

```
reports/
├── compliance_report_MyApplication_20240120_143022.txt
│   └── Human-readable report with sections above
│
├── MyApplication_summary.json
│   └── {
│       "report_metadata": {...},
│       "executive_summary": {...},
│       "technical_summary": {...},
│       "governance": {...},
│       "recommendations": {...}
│     }
│
├── portfolio_report_20240120_143022.json
│   └── Aggregated data from multiple projects
│
└── session/
    └── session_20240120_143022.json
        └── Complete audit trail:
            - Session start/end times
            - All processing events
            - Metrics snapshots
            - Error logs (if any)
```

