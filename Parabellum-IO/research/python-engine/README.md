# Python research engine (not used by the running app)

These scripts were written during the research phase of the project:

| File | What it does |
|---|---|
| `sonarqube_ingestion_engine.py` | Reads SonarQube JSON exports |
| `cwe_database.py` | SonarQube rule → CWE lookup table |
| `risk_module.py` | Risk scoring experiments |
| `compliance_reporter.py` | Stand-alone compliance report generator |
| `parabellum_core_engine.py` | Command-line pipeline that ties the above together |

The web application does **not** call them. The live platform implements the same
ideas in Node.js:

| Python script | Live implementation |
|---|---|
| `cwe_database.py`, `risk_module.py` | `backend/src/services/cweRiskService.js`, `threatMappings.js` |
| `compliance_reporter.py` | `backend/src/routes/compliance.js`, `frontend/src/pages/ComplianceReportPage.jsx` |
| `sonarqube_ingestion_engine.py` | `backend/src/services/sonarService.js`, `scanReportService.js` |

They were moved here from `backend/src/services/` so the backend folder only
contains code that actually runs. You can still run them on their own, e.g.
`python parabellum_core_engine.py` (each file has its own demo under `if __name__ == "__main__"`).
