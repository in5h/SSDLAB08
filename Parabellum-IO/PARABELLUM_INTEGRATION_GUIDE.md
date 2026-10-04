# Parabellum Core Engine - Integration & Reference Guide

## 🚀 Quick Start

### Installation

1. **Place Python modules in backend services directory**:
   ```bash
   # Already created in:
   backend/src/services/
   ├── parabellum_core_engine.py
   ├── sonarqube_ingestion_engine.py
   ├── risk_module.py
   ├── compliance_reporter.py
   └── cwe_database.py
   ```

2. **Install only one optional dependency** (YAML parsing):
   ```bash
   pip install PyYAML
   ```

3. **Ensure Python 3.8+ available** in backend environment

### Basic Usage

```python
# 1. Initialize the engine
from services.parabellum_core_engine import ParabellumCoreEngine

engine = ParabellumCoreEngine(
    workspace_dir="./workspace",
    cache_dir="./cache", 
    reports_dir="./reports"
)

# 2. Start a processing session
session_id = engine.start_session(
    project_name="MyProject",
    description="Security scan - Q1 2024"
)

# 3. Process SonarQube export
result = engine.process_sonarqube_export("sonarqube_export.json")

# 4. Check results
print(f"Risk Level: {result['analysis']['risk_assessment']['portfolio_risk_level']}")
print(f"Compliance: {result['analysis']['risk_assessment']['policy_compliance']}")
print(f"Report: {result['reporting']['compliance_report']}")

# 5. Save session log
engine.save_session_log()
```

---

## 📦 Module Reference

### `cwe_database.py` - CWE & NIST Mappings

**Key Functions**:
```python
from cwe_database import *

# Get CWE information
cwe_info = get_cwe_info("CWE-89")  # Returns full CWE details

# Map SonarQube rule to CWE
cwe_id = map_sonarqube_rule_to_cwe("java:S2077")  # Returns "CWE-89"

# Get severity level from CVSS
severity = get_severity_level(8.5)  # Returns "High"

# Get attack patterns for a CWE
patterns = get_attack_patterns_for_cwe("CWE-89")
# Returns: ["Remote Code Execution", "Data Leakage"]

# NIST CSF name lookup
control_name = get_nist_csf_full_name("PR.DS-01")
# Returns: "Data Security"
```

---

### `sonarqube_ingestion_engine.py` - SonarQube Processing

**Main Classes**:

#### `SonarQubeIngestionEngine`
```python
from sonarqube_ingestion_engine import SonarQubeIngestionEngine

engine = SonarQubeIngestionEngine(
    cache_dir="./cache",
    watch_dir="./sonarqube_exports"  # Optional
)

# Ingest single file
result = engine.ingest_file("export.json")
print(result["diff"]["new_count"])      # Newly introduced issues
print(result["diff"]["resolved_count"]) # Fixed issues
print(result["diff_report"])            # Human-readable report

# Ingest entire directory
results = engine.ingest_directory("./sonarqube_exports")

# Get cache inventory
inventory = engine.get_inventory()
print(inventory["cached_exports"])      # List of cached exports
```

**Output Structure**:
```json
{
  "success": true,
  "export_id": "export_20240120_143022",
  "total_findings": 42,
  "diff": {
    "new_count": 5,
    "resolved_count": 3,
    "changed_severity": 2,
    "unchanged_count": 32
  }
}
```

---

### `risk_module.py` - Vulnerability Analysis

**Main Class: `VulnerabilityAnalyzer`**

```python
from risk_module import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer()

# Analyze single finding
single_issue = {
    "key": "AVxxx",
    "component": "project:file.java",
    "rule": "java:S2077",
    "severity": "CRITICAL",
    "type": "VULNERABILITY",
    "message": "SQL injection vulnerability"
}

analysis = analyzer.analyze_finding(single_issue)

print(analysis["cwe_mapping"]["cwe_id"])           # "CWE-89"
print(analysis["risk_assessment"]["risk_score"])   # 85.3 (0-100)
print(analysis["risk_assessment"]["risk_level"])   # "Critical"
print(analysis["attack_analysis"]["impact_summary"])
# → "Impacts: Confidentiality, Integrity, Availability"

# Analyze batch of findings
batch_analysis = analyzer.analyze_findings_batch(findings)

print(batch_analysis["aggregate_metrics"]["critical_count"])
print(batch_analysis["overall_risk_assessment"]["portfolio_risk_level"])
print(batch_analysis["overall_risk_assessment"]["policy_compliance"])
```

**Risk Scoring Formula**:
```
risk_score = (CVSS × 10) × severity_mult × type_mult × attack_mult

Cap at 100

Severity: 0-100
├─ Critical:  80-100
├─ High:      60-79
├─ Medium:    40-59
├─ Low:       20-39
└─ Minimal:   0-19
```

---

### `compliance_reporter.py` - Report Generation

**Main Class: `ComplianceReporter`**

```python
from compliance_reporter import ComplianceReporter

reporter = ComplianceReporter(output_dir="./reports")

# Generate complete compliance report
report_path = reporter.generate_report(
    analysis_results=batch_analysis,
    project_name="MyProject",
    scan_config={"policy_thresholds": {...}}
)

print(f"Report saved: {report_path}")
# Output: ./reports/compliance_report_MyProject_20240120_143022.txt

# Generate JSON summary (machine-readable)
json_summary = reporter.generate_summary_json(
    analysis_results=batch_analysis,
    project_name="MyProject"
)
```

**Report Sections**:
1. **Executive Summary** - Compliance status, metrics, key findings
2. **Technical Deep Dive** - CWE mappings, severity breakdown
3. **Governance Mapping** - NIST CSF controls, OPA guardrails
4. **Recommendations** - Prioritized action items
5. **Appendix** - Methodology, definitions, disclaimer

---

### `parabellum_core_engine.py` - Orchestration

**Main Class: `ParabellumCoreEngine`**

```python
from parabellum_core_engine import ParabellumCoreEngine

# Initialize
engine = ParabellumCoreEngine(
    workspace_dir="./workspace",
    cache_dir="./cache",
    reports_dir="./reports"
)

# Start session
session_id = engine.start_session(
    project_name="SecurityAudit",
    description="Q1 2024 compliance review"
)

# Process single export
result = engine.process_sonarqube_export("export.json")

# Process entire directory
batch = engine.process_directory("./exports/")

# Generate portfolio report (multiple projects)
portfolio = engine.generate_portfolio_report(batch['results'])

# Get engine status
status = engine.get_engine_status()

# Get session info
session = engine.get_session_summary()

# Save session log
log_path = engine.save_session_log()
```

**Processing Result Structure**:
```json
{
  "session_id": "session_...",
  "project_name": "MyProject",
  "status": "SUCCESS",
  "ingestion": {
    "export_id": "...",
    "total_findings": 42,
    "diff": {...}
  },
  "analysis": {
    "total_findings": 42,
    "aggregate_metrics": {...},
    "risk_assessment": {...}
  },
  "reporting": {
    "compliance_report": "path/to/report.txt",
    "summary_json": "path/to/summary.json"
  }
}
```

---

## 🔌 Node.js/Express Integration

### Approach 1: Child Process

```javascript
// routes/sonar-ai.js
import { spawn } from 'child_process';
import path from 'path';

router.post("/api/sonar/ai-analysis/:projectId", async (req, res) => {
  const exportPath = req.body.exportPath;
  
  const python = spawn('python', [
    path.join(__dirname, '../services/parabellum_core_engine.py'),
    '--process', exportPath
  ]);
  
  let output = '';
  
  python.stdout.on('data', (data) => {
    output += data.toString();
  });
  
  python.on('close', (code) => {
    if (code === 0) {
      const result = JSON.parse(output);
      res.json(result);
    } else {
      res.status(500).json({ error: 'Analysis failed' });
    }
  });
});
```

### Approach 2: Python HTTP Server

Create `services/parabellum_api.py`:

```python
from flask import Flask, jsonify, request
from parabellum_core_engine import ParabellumCoreEngine

app = Flask(__name__)
engine = ParabellumCoreEngine()

@app.route('/analyze', methods=['POST'])
def analyze():
    file_path = request.json.get('file_path')
    result = engine.process_sonarqube_export(file_path)
    return jsonify(result)

@app.route('/status', methods=['GET'])
def status():
    return jsonify(engine.get_engine_status())

if __name__ == '__main__':
    app.run(port=5001)
```

Then call from Node.js:
```javascript
const response = await fetch('http://localhost:5001/analyze', {
  method: 'POST',
  body: JSON.stringify({ file_path: exportPath })
});
```

---

## 📊 Data Mapping Reference

### SonarQube Severity → Risk Level

| SonarQube  | Normalized | Risk Level | CVSS Est |
|-----------|-----------|-----------|----------|
| BLOCKER   | Critical  | Critical  | 9.5      |
| CRITICAL  | Critical  | Critical  | 9.5      |
| MAJOR     | High      | High      | 7.5      |
| MINOR     | Medium    | Medium    | 5.5      |
| INFO      | Low       | Low       | 2.5      |

### Common SonarQube Rules → CWE

```python
{
  "java:S2077": "CWE-89",    # SQL Injection
  "java:S3649": "CWE-89",    # SQL Injection
  "java:S5131": "CWE-79",    # XSS
  "java:S2755": "CWE-611",   # XXE
  "java:S4502": "CWE-352",   # CSRF
  "java:S2076": "CWE-78",    # Command Injection
  "java:S1948": "CWE-502",   # Deserialization
  "java:S2068": "CWE-798",   # Hardcoded Credential
  "java:S5542": "CWE-327",   # Weak Crypto
}
```

### NIST CSF Control Examples

| Control | Category | Typical CWE Mappings |
|---------|----------|----------------------|
| PR.DS-01 | Data Security | CWE-89, CWE-79, CWE-20 |
| PR.AA-01 | Identity & Auth | CWE-287, CWE-798 |
| PR.AA-05 | Access Control | CWE-639, CWE-352 |
| PR.PS-01 | Platform Security | CWE-78, CWE-611 |
| DE.CM-01 | Monitoring | CWE-778 |

---

## 🔍 Troubleshooting

### Issue: Import errors for Python modules

**Solution**: Ensure modules are in the correct path:
```python
import sys
sys.path.insert(0, '/path/to/backend/src/services')
from parabellum_core_engine import ParabellumCoreEngine
```

### Issue: Cache directory not created

**Solution**: Manually create cache structure:
```bash
mkdir -p cache/sonarqube cache/sessions
```

### Issue: YAML parsing fails

**Solution**: Install PyYAML:
```bash
pip install PyYAML
```

### Issue: Report file not generated

**Solution**: Check output directory permissions:
```bash
chmod 755 reports/
```

---

## 📈 Performance Tips

1. **Batch Processing**: Process multiple exports in one session to share cache
2. **Incremental Ingestion**: The diff engine only re-analyzes changed findings
3. **Cache Strategy**: Keep cache directory on fast storage (SSD)
4. **Session Logging**: Disable verbose logging for production:
   ```python
   engine.session_log = []  # Clear logs periodically
   ```

---

## 🔐 Security Best Practices

1. **Access Control**: Restrict access to `/reports` directory
2. **Input Validation**: Always validate file paths before processing
3. **Audit Trail**: Review session logs regularly for anomalies
4. **Data Retention**: Implement cache cleanup policy (e.g., delete > 90 days)

---

## 📚 Example Workflows

### Workflow 1: Monthly Security Audit
```python
engine = ParabellumCoreEngine()
engine.start_session("MonthlyAudit", "Q1 2024")

# Process all projects
for project_name in ["frontendapp", "backendapi", "dataservice"]:
    export_file = f"./exports/{project_name}_jan2024.json"
    result = engine.process_sonarqube_export(export_file)
    print(f"{project_name}: {result['analysis']['risk_assessment']['portfolio_risk_level']}")

# Generate portfolio overview
engine.generate_portfolio_report(...)
```

### Workflow 2: Real-time Monitoring
```python
import time
import os

engine = ParabellumCoreEngine()
watch_dir = "./sonarqube_exports"

while True:
    files = os.listdir(watch_dir)
    for file in files:
        result = engine.process_sonarqube_export(os.path.join(watch_dir, file))
        # Send alert if critical findings
        if result['analysis']['aggregate_metrics']['critical_count'] > 0:
            send_alert(result)
    time.sleep(300)  # Check every 5 minutes
```

---

## ✨ Summary

This expansion provides **production-ready vulnerability assessment and compliance reporting** with:

✅ **Zero external database dependencies** - All data local and hardcoded
✅ **Comprehensive CWE/NIST mappings** - 20+ CWEs with full context
✅ **Intelligent risk scoring** - Multi-factor CVSS-based algorithm
✅ **Professional reporting** - Executive summaries and deep-dives
✅ **Session tracking** - Complete audit trail for compliance
✅ **Minimal dependencies** - Only PyYAML needed

**Next Steps**:
1. Test with real SonarQube exports
2. Integrate Python API endpoints in Express routes
3. Add UI dashboard for reports
4. Implement historical trending
5. Set up automated scheduling

