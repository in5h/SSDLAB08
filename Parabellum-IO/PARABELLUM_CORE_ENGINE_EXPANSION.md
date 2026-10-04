# Parabellum IO - Core Engine Expansion

## 📋 Overview

This document describes the expansion of the **Parabellum IO Core Engine** with three integrated subsystems:

1. **SonarQube Ingestion Engine** - Monitors and parses SonarQube exports with diff tracking
2. **Risk & Vulnerability Analysis Module** - NIST/CWE mapping with AI-assisted risk scoring  
3. **PDF Compliance Reporting System** - Professional compliance reports with governance mapping

---

## 🏗️ Updated File Structure

```
backend/src/services/
├── ✨ parabellum_core_engine.py          # Main orchestration engine
├── ✨ sonarqube_ingestion_engine.py      # SonarQube export ingestion & diffing
├── ✨ risk_module.py                     # Vulnerability analysis & risk scoring
├── ✨ compliance_reporter.py             # PDF/JSON compliance reporting
├── ✨ cwe_database.py                    # CWE/NIST mappings & risk data
├── sonarService.js
├── scanReportService.js
├── grcMappingService.js
├── riskReportService.js
├── authService.js
├── complianceService.js
├── geminiClient.js
├── githubService.js
├── emailService.js
├── javaCompileService.js
└── ragService.js

cache/
├── sonarqube/           # SonarQube ingestion cache
│   ├── index.json       # Cache inventory
│   └── *.json          # Cached findings
└── sessions/            # Session logs

reports/
├── compliance_report_*.txt         # Compliance reports (text format)
├── *_summary.json                  # JSON summaries
├── portfolio_report_*.json         # Portfolio aggregations
└── session_*.json                  # Session audit logs
```

---

## 🔄 Module Architecture & Data Flow

### 1. SonarQube Ingestion Engine (`sonarqube_ingestion_engine.py`)

**Purpose**: Monitor and ingest SonarQube exports with diff-based tracking

**Key Classes**:
- `SonarQubeIngestionCache` - Manages local caching of processed exports
- `SonarQubeExportParser` - Parses JSON/YAML SonarQube exports
- `SonarQubeFindingsDiffer` - Compares previous vs current findings
- `SonarQubeIngestionEngine` - Main orchestrator

**Features**:
- ✅ Monitors designated directory for `.json` and `.yaml` SonarQube exports
- ✅ Parses "Issues" array extracting: `key`, `component`, `severity`, `message`
- ✅ Diffs against cached results to identify:
  - `new` - Newly introduced vulnerabilities
  - `resolved` - Fixed issues
  - `changed_severity` - Severity regressions/improvements
  - `unchanged` - Persistent issues

**Data Structure**:
```python
{
  "key": "AVxxx",
  "component": "project:file.java",
  "rule": "java:S2077",
  "severity": "Critical|High|Medium|Low",
  "type": "VULNERABILITY|BUG|SECURITY_HOTSPOT|CODE_SMELL",
  "message": "Vulnerability description",
  "status": "OPEN|FIXED",
  "hash": "abc123..."  # For tracking
}
```

---

### 2. CWE Database (`cwe_database.py`)

**Purpose**: Provides offline CWE/NIST mappings and risk assessment data

**Key Data**:
- **CWE_DATABASE**: 20+ CWE definitions with:
  - Severity levels (`Critical`, `High`, `Medium`, `Low`)
  - CVSS base scores (0-10)
  - NIST CSF 2.0 control mappings
  - Attack vectors and impact types
  - OWASP Top 10 categories
  - Remediation guidance

- **SONARQUBE_RULE_TO_CWE**: Maps SonarQube rules to CWE IDs
  - Example: `"java:S2077"` → `"CWE-89"` (SQL Injection)

- **ATTACK_PATTERNS**: Predefined attack scenarios with likelihood/impact

**Supported CWEs**:
```
CWE-89    (SQL Injection)
CWE-79    (XSS - Cross-Site Scripting)
CWE-352   (CSRF)
CWE-611   (XXE - XML External Entity)
CWE-287   (Broken Authentication)
CWE-639   (Broken Authorization)
CWE-502   (Deserialization)
CWE-798   (Hardcoded Credentials)
CWE-327   (Weak Cryptography)
CWE-778   (Insufficient Logging)
CWE-16    (Configuration)
CWE-120   (Buffer Overflow)
CWE-22    (Path Traversal)
CWE-476   (NULL Pointer Dereference)
CWE-362   (Race Condition)
CWE-78    (Command Injection)
CWE-90    (LDAP Injection)
CWE-918   (SSRF)
CWE-601   (Open Redirect)
CWE-20    (Input Validation)
```

---

### 3. Risk & Vulnerability Module (`risk_module.py`)

**Purpose**: Analyze SonarQube findings and assign NIST-aligned risk scores

**Key Classes**:
- `RiskScorer` - Computes composite risk scores (0-100)
- `VulnerabilityAnalyzer` - Enriches findings with risk analysis

**Risk Scoring Model**:
```
risk_score = (CVSS × 10) × severity_mult × type_mult × attack_mult

severity_mult:
  - Critical: 4.0
  - High: 2.0
  - Medium: 1.0
  - Low: 0.3

type_mult:
  - VULNERABILITY: 3.0
  - SECURITY_HOTSPOT: 2.5
  - BUG: 1.5
  - CODE_SMELL: 0.5

attack_mult: (highest of applicable vectors)
  - NETWORK: 2.0
  - APPLICATION: 1.5
  - LOCAL: 0.8
  - PHYSICAL: 0.3
```

**Output for Each Finding**:
```json
{
  "cwe_mapping": {
    "cwe_id": "CWE-89",
    "cwe_name": "SQL Injection",
    "owasp_category": "A03:2021 – Injection"
  },
  "risk_assessment": {
    "severity": "Critical",
    "cvss_score": 9.8,
    "risk_score": 85.3,
    "risk_level": "Critical",
    "remediation_priority": 1,
    "response_time": "1 hour"
  },
  "attack_analysis": {
    "applicable_patterns": ["Remote Code Execution", "Data Leakage"],
    "attack_types": [...],
    "impact_summary": "Improper Input Validation → Risk: Remote Code Execution and Data Leakage"
  },
  "compliance": {
    "nist_csf_controls": ["PR.DS-01", "PR.AA-01", "PR.PS-01"],
    "policy_violations": [...]
  },
  "remediation": {
    "guidance": "...",
    "effort_estimate": "1h",
    "technical_debt": "30min"
  }
}
```

**Batch Analysis Output**:
```json
{
  "total_findings": 42,
  "aggregate_metrics": {
    "severity_distribution": {"Critical": 3, "High": 7, ...},
    "risk_level_distribution": {"Critical": 3, "High": 7, ...},
    "average_risk_score": 65.2,
    "critical_count": 3,
    "high_count": 7,
    "estimated_remediation_effort": "2 days"
  },
  "overall_risk_assessment": {
    "portfolio_risk_level": "High",
    "requires_immediate_action": true,
    "policy_compliance": "FAIL"
  }
}
```

---

### 4. Compliance Reporter (`compliance_reporter.py`)

**Purpose**: Generate professional compliance reports with executive summaries and governance mappings

**Report Sections**:

#### 📊 Executive Summary
- Compliance status (PASS/FAIL/WARNING)
- Portfolio risk level
- Critical/High finding counts
- Estimated remediation effort
- Key metrics dashboard

#### 🔍 Technical Deep Dive
- CWE distribution (top vulnerabilities)
- OWASP category breakdown
- Detailed vulnerability list by severity
- Component → CWE mappings

#### 🏛️ Governance Mapping
- NIST CSF 2.0 Control alignment
- Policy-as-Code (OPA) guardrail status
- Compliance violations summary

#### 💡 Recommendations
- Prioritized action items
- Immediate actions (Critical severity)
- Short-term remediation (High)
- Long-term improvements (Medium/Low)

#### 📋 Appendix
- Methodology & scan date
- Severity definitions
- Attack vector glossary
- Disclaimer

**Output Formats**:
- `compliance_report_[project]_[timestamp].txt` - Human-readable
- `[project]_summary.json` - Machine-readable
- `portfolio_report_[timestamp].json` - Multi-project aggregation

---

### 5. Parabellum Core Engine (`parabellum_core_engine.py`)

**Purpose**: Main orchestration engine tying all components together

**Main Class**: `ParabellumCoreEngine`

**Key Methods**:
```python
# Session management
session_id = engine.start_session(project_name, description)

# Processing
result = engine.process_sonarqube_export(file_path)
batch = engine.process_directory(directory_path)

# Reporting
portfolio = engine.generate_portfolio_report(analyses)

# Status
status = engine.get_engine_status()
summary = engine.get_session_summary()
log = engine.save_session_log()
```

**Processing Pipeline**:
```
SonarQube Export
    ↓
[1] Ingestion Engine (Parse, Diff, Cache)
    ↓
[2] Risk Analyzer (CWE Map, Score, NIST Align)
    ↓
[3] Compliance Reporter (Executive Summary, Deep Dive, Governance)
    ↓
Reports + Session Log
```

---

## 🚀 Usage Examples

### Example 1: Process Single Export
```python
engine = ParabellumCoreEngine()
engine.start_session("MyProject")

result = engine.process_sonarqube_export("sonar_export_2024.json")

print(f"Findings: {result['analysis']['total_findings']}")
print(f"Critical: {result['analysis']['aggregate_metrics']['critical_count']}")
print(f"Report: {result['reporting']['compliance_report']}")
```

### Example 2: Batch Processing Directory
```python
engine = ParabellumCoreEngine()
engine.start_session("SecurityScan", "Monthly audit")

batch_result = engine.process_directory("./sonarqube_exports/")

portfolio = engine.generate_portfolio_report(batch_result['results'])
log_path = engine.save_session_log()
```

### Example 3: Direct Risk Analysis
```python
from risk_module import VulnerabilityAnalyzer
from sonarqube_ingestion_engine import SonarQubeIngestionEngine

# Get findings from SonarQube
sonar = SonarQubeIngestionEngine()
findings = sonar.ingest_file("export.json")['findings']

# Analyze
analyzer = VulnerabilityAnalyzer()
analysis = analyzer.analyze_findings_batch(findings)

# Report
reporter = ComplianceReporter()
report = reporter.generate_report(analysis, "MyProject")
```

---

## 📊 Key Metrics & Data

### Risk Scoring
- **Range**: 0-100
- **Levels**: Critical (80+), High (60-79), Medium (40-59), Low (20-39), Minimal (0-19)
- **Factors**: CVSS score, severity, issue type, attack vectors

### Severity Mapping (CVSS)
| Level     | Range   | SLA     | Priority |
|-----------|---------|---------|----------|
| Critical  | 9.0-10  | 1 hour  | 1        |
| High      | 7.0-8.9 | 1 day   | 2        |
| Medium    | 4.0-6.9 | 1 week  | 3        |
| Low       | 0.1-3.9 | 1 month | 4        |

### NIST CSF 2.0 Function Coverage
- **GOVERN** (GV) - Governance
- **IDENTIFY** (ID) - Asset & Risk Discovery
- **PROTECT** (PR) - Security Controls
- **DETECT** (DE) - Monitoring & Detection
- **RESPOND** (RS) - Incident Management
- **RECOVER** (RC) - Restoration

---

## 🔧 Integration Points

### Backend Integration (`routes/sonar.js`)
```javascript
import { ParabellumCoreEngine } from "../services/parabellum_core_engine.py"

router.post("/api/sonar/full-analysis", async (req, res) => {
  const engine = new ParabellumCoreEngine()
  const result = await engine.process_sonarqube_export(filePath)
  res.json(result)
})
```

### Frontend Display
```javascript
// Display executive summary
const summary = response.analysis.aggregate_metrics
const risks = summary.severity_distribution

// Show compliance status
const status = response.analysis.risk_assessment.policy_compliance
```

---

## 📝 Dependencies

**Minimal External Dependencies**:
- `PyYAML` (for YAML parsing)
- Standard library: `json`, `hashlib`, `datetime`, `pathlib`, `io`

**Optional** (for enhanced PDF generation):
- `reportlab` - Professional PDF generation
- `fpdf` - Lightweight PDF alternative

**No required dependencies for**:
- Text-based compliance reporting
- JSON output
- NIST/CWE data (all hardcoded)

---

## 💾 Data Persistence

### Cache Structure
```
cache/
├── sonarqube/
│   ├── index.json                    # Cache inventory
│   ├── export_20240115_120000_findings.json
│   └── export_20240120_140000_findings.json
└── sessions/
    └── session_20240120_143022.json  # Audit trail
```

### Session Logging
Each session tracks:
- Start/end timestamps
- Processing events
- Errors & warnings
- File paths
- Metrics snapshots

---

## 🔐 Security Considerations

1. **Data Isolation**: All data stays local to session/workspace
2. **No External Calls**: All CWE/NIST data is hardcoded
3. **Audit Trail**: Complete session logs maintained
4. **Input Validation**: File formats validated before processing
5. **Error Handling**: Graceful failure with detailed logs

---

## 📈 Scaling & Performance

- **Cache Strategy**: Incremental ingestion with diff tracking
- **Batch Processing**: Support for multi-project analysis
- **Memory Efficient**: Streaming JSON/YAML parsing
- **Database-Free**: JSON-based storage for portability

---

## ✨ Future Enhancements

1. **Database Backend**: Replace JSON caching with SQLite
2. **Real-time Monitoring**: Watch directory for new exports
3. **AI Prioritization**: Use ML for risk ranking
4. **PDF Export**: Generate PDF reports with charts
5. **API Integration**: REST endpoints for all components
6. **Trend Analysis**: Historical comparison and forecasting
7. **Remediation Tracking**: Integration with issue tracking systems

---

## 📄 License & Attribution

- **NIST CSF 2.0**: Public domain framework
- **CWE Database**: Derived from MITRE CWE
- **CVSS Scoring**: Based on CVSS v3.1 methodology

