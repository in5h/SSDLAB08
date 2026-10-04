# Fixes applied after manual testing

All 20 bugs from the manual testing report were fixed and re-tested.

## Before you run the new version

1. `cd backend && npm install` (adds `helmet` and `express-rate-limit`).
2. In `backend/.env` set:
   - `JWT_SECRET` to 16+ random characters. **The backend now refuses to start without it.**
   - `ADMIN_EMAIL` to your own e-mail. That account becomes admin when it signs up or logs in. The old "promote-admin" route is gone.
   - Real SMTP details (`EMAIL_USER` / `EMAIL_PASS`) to e-mail the login code. Without them the code is shown on the login screen (`OTP_DELIVERY=auto`, see below).
   - `PROJECTS_ROOT`: the folder normal users may register local projects from (admins can register any folder when this is empty).
   - `RAG_SERVICE_URL=http://localhost:5000`.
3. To show the real tools in the demo, install them (see "Security tools setup" in README.md): Snyk (`npm i -g snyk` + `snyk auth`), Trivy, Grype, and the ZAP daemon (Docker).

## What changed

| # | Bug | Fix |
|---|---|---|
| 1 | Any user could make themselves admin | `POST /api/auth/promote-admin` removed. Admins come from `ADMIN_EMAIL`. Signup ignores any `role` sent by the browser. Admin pages check the role in the database, not just the token. |
| 2 | Users could read other users' data | Policies, risk, compliance and SonarQube issue/status/quality-gate routes check the owner. The reports list and download only show your own files. SonarQube keys now include the user id, so two users' projects with the same name no longer clash. |
| 3 | Deleting a project deleted the real folder; any path accepted | Delete only removes copies the app made (ZIP uploads and GitHub clones in `backend/src/uploads`). Local folders must be inside `PROJECTS_ROOT` (or the user must be an admin). |
| 4 | OTP shown in browser; known default JWT secret | The OTP is only shown when `DEV_MODE=true`; otherwise login says SMTP must be configured. There is no default JWT secret. An OTP is cancelled after 5 wrong tries. Also fixed: `.env` was loaded *after* the other modules, so secrets read at start-up were empty. |
| 5 | SonarQube found 0 issues on local folders | Added `sonar.projectBaseDir`. Removed the old `sonar.analysis.mode` option. |
| 6 | Trivy not real when missing; fake CVE IDs | Runs real `trivy fs --scanners vuln,misconfig,secret`. If Trivy is missing, the tab shows "Not installed · basic checks only" plus a warning. Built-in rule IDs are now `PB-…` instead of fake CVEs. Real `.env` files only; a missing Dockerfile is no longer a finding. |
| 7 | ZAP was not real and not DAST | Real ZAP REST API integration: spider, passive scan, optional active scan, then alerts, grouped per alert type. The scan tab has a Target URL box. The fallback is labelled "built-in checks", ignores comments and reports the right line. |
| 8 | Anchore was not real; "Critical" without a Dockerfile | Runs Anchore's Grype (`grype dir:… -o json`) with a STOP/WARN policy gate. Without Docker files the built-in result is "N/A". |
| 9 | Gemini never used | New "Get AI fix advice" button on Risk Analysis (`POST /api/risk/ai-advice`). The Gemini client loads lazily and gives a clear message if the key is missing. |
| 10 | Tool status always "Connected" | SonarQube is checked with `/api/system/status`; every other tool is checked for real. |
| 11 | RAG port mismatch | Everything uses port 5000 and `RAG_SERVICE_URL` (no hard-coded URLs). The RAG port can be changed with `RAG_PORT`. The `/map/multi` route now comes before `/map/{framework}`. |
| 12 | Snyk was npm-only | `snyk test --all-projects --json`, so Python, Java, Go etc. work too. Friendly install/auth messages. Works on Windows (`snyk.cmd`). |
| 13 | Old NIST CSF 1.1 IDs | Replaced with CSF 2.0 IDs (PR.AA, PR.PS, ID.RA …). |
| 14 | Python engine never used | Moved to `research/python-engine/` with a README explaining it is research code. |
| 15 | No rate limit / open CORS / no Helmet / no upload limit | Added `helmet`, CORS limited to `FRONTEND_URL`, 20 login attempts per 15 minutes, ZIP-only uploads up to `MAX_UPLOAD_MB`. |
| 16 | Policies page and Dashboard were hard-coded | New `GET /api/policies/frameworks`. The Policies page shows all 6 frameworks and the real policy rules. |
| 17 | Fake version numbers | Removed. Versions come from the real tools. |
| 18 | Local projects labelled "Upload" | Uses `sourceType`. |
| 19 | CIS controls had no titles; duplicate counts | Official titles and groups for all 6 frameworks (`backend/src/data/controlCatalog.json`, generated from `rag-service/*_data.py`). Each issue is counted once. |
| 20 | Semgrep status hung offline; wrong ZAP line numbers | The Semgrep version check is turned off (`SEMGREP_CONFIG` allows offline rules). Correct line numbers. |

All tool commands now go through `backend/src/services/toolRunner.js`, which starts programs without a shell on Linux/macOS, so paths with spaces work and can't inject commands.

---

# Round 2 – Application and Final Report improvements

## Application

| Request | What was done | Where |
|---|---|---|
| Configure OTP properly | OTP codes are stored only as an HMAC hash, expire after 5 min, are burned after 5 wrong tries and cannot be reused. "Resend code" button with a 60 s cooldown. SMTP login is checked at start-up ("SMTP connection OK" or the exact error); supports port 587 (STARTTLS) and 465 (`EMAIL_SECURE=true`), `EMAIL_FROM`, plain-text + HTML e-mail. Codes are never printed to the server log. Tested end-to-end with a real SMTP server. | `services/authService.js`, `services/emailService.js`, `pages/LoginPage.jsx` |
| One account per e-mail | E-mails are trimmed + lower-cased, validated, and protected by a unique index on `lower(email)` (old rows normalised automatically). "Ali@Mail.com" and " ali@mail.com " are the same account; the sign-up form sends the user to Sign In. | `db/database.js`, `services/authService.js` |
| Stay logged in after restarts | Logins create a row in a new `sessions` table; the token carries the session id. Sessions survive page reloads and server restarts (8 h, or 30 days with "Keep me signed in"); Logout really ends the session. The database folder can be moved with `DATA_DIR`, and the start-up log shows the database path and number of accounts. | `services/authService.js`, `middleware/authMiddleware.js`, `components/Layout.jsx` |
| Expandable scan results | Every result row on Security Scans (and on Findings) expands to show the full message, rule, location, CWE/OWASP/CVE, package versions, code snippet, the tool's fix advice and references. "Expand all" and "Show all results" buttons. | `components/IssueDetails.jsx`, `pages/ScanPage.jsx` |

## Final report

| Request | What was done |
|---|---|
| Pipeline to track a project | **Pipeline** page: one click runs all tools, live stage status, run history. Each finding is fingerprinted and tracked across runs (New / Still open / Verified Fixed / Reopened). Single-tool scans are tracked too. |
| Mappings for ISO 27001, CIS, OWASP, NIST 800-53 | Every finding is mapped to NIST CSF 2.0, ISO 27001:2022, CIS v8, NIST SP 800-53, OWASP ASVS, ISO 27034, plus OWASP Top 10 and MITRE ATT&CK, with control titles. The report has a per-framework "controls affected" section. |
| RAG-based recommendations | Retrieval from the framework knowledge base (RAG service, or built-in BM25 retriever offline) + generation by Gemini (template if no key). The source is shown for every recommendation. |
| True positives / false negatives | Confidence score per finding (tool type, confirmed by another tool, test/vendor paths, quality rules). Analyst triage (False Positive / Accepted Risk) is remembered across rescans. Coverage table per weakness type shows where a missing tool could cause false negatives. |
| Fix plan for each finding | Step-by-step fix, code example, effort, priority (P1–P4), SLA due date, and how the fix is verified. |
| Risk owner and status | Owner (defaults to the project's business owner), status, due date and notes per finding, with a full history. |
| Code / file evidence | Code lines around the reported line, the manifest line for dependencies, or the URLs and evidence for ZAP alerts. |
| Asset and business context | Asset name/type, environment, data classification, criticality, internet-facing, owner, description. Used in the risk score and printed in the report. |
| Fix verification and rescan | Re-running the pipeline marks findings the tool no longer reports as *Verified Fixed*. The report lists fixes in the latest run, all verified fixes and the run history. |

Also fixed while testing: SonarQube results could be read before the new analysis was processed (now waits for this scan's own analysis), OWASP ZAP re-reported old alerts (each scan now starts a fresh ZAP session), the SonarQube scanner wrote a `.scannerwork` folder into the user's project (now uses a temp folder), and the fake demo `PipelinesPage` / unused `ViolationsPage` were removed.

## OTP delivery setting (`OTP_DELIVERY` in `backend/.env`)

| Value | What happens |
|---|---|
| `auto` (default) | E-mail the code when `EMAIL_USER`/`EMAIL_PASS` are set. If they are not set, or the e-mail fails, show the code on the login screen (like the original app). |
| `email` | E-mail only. Login fails if SMTP is not working. Use this on a public server. |
| `screen` | Always show the code on the login screen. Good for a demo/presentation. |
| `both` | E-mail the code and also show it on the screen. |

---

# Round 3 – Login, tools, frameworks, risk and fixes

| Requirement | What was done | Where |
|---|---|---|
| Login fully functional | Sign up (one account per e-mail), sign in with password + OTP, "Keep me signed in", sessions that survive restarts, logout. **New:** "Forgot password?" (reset code → new password, every session signed out) and **Change password** (🔑 button in the top bar, other devices signed out). The new routes are rate-limited like login. | `services/authService.js`, `routes/auth.js`, `pages/LoginPage.jsx`, `components/Layout.jsx` |
| OTP configuration | `OTP_DELIVERY` = `auto` (e-mail when SMTP is set, otherwise on screen) / `email` / `screen` / `both`. Login and reset codes are separate, hashed, expire in 5 min, single use, 5 tries, 60 s resend cooldown. | `backend/.env.example` |
| Pipeline for tracking projects | One-click pipeline over all tools, run history, finding lifecycle (New / Still open / Verified Fixed / Reopened), single-tool scans tracked as runs. | `pages/PipelinePage.jsx`, `services/pipelineService.js` |
| All security tools and all frameworks | **Risk Analysis, Compliance Mapping and the Compliance Report now use the open findings of every tool** (SonarQube, Semgrep, Snyk, Trivy, OWASP ZAP, Anchore), not only SonarQube. The Compliance Report scores all 6 frameworks (NIST CSF 2.0, ISO 27001, CIS v8, NIST SP 800-53, OWASP ASVS, ISO 27034). SonarQube's own rule explanation and "how to fix" text is imported for every SonarQube issue, and the SonarQube tab shows every issue (was limited to the first 100). | `services/projectIssues.js`, `routes/risk.js`, `routes/compliance.js`, `services/scanReportService.js` |
| Optimised tool results | Cross-tool **duplicates are merged** (same CVE/package or same weakness at the same place from several tools is counted once, "also found by …"), confidence per finding (tool type, corroboration, test paths, quality rules), remembered False Positive / Accepted Risk, and the finding's own CWE is used for risk instead of guessing from the text. | `services/findingService.js` |
| Risk management on all tools and frameworks | Risk score per finding = severity × CWE CVSS × exposure × business impact × confidence; Risk Analysis groups all tools' findings by CWE with OWASP Top 10, MITRE ATT&CK and CAPEC heatmaps; owner, status, SLA due date and history per finding. | `pages/RiskPage.jsx`, `pages/FindingsPage.jsx` |
| Recommended fixes and remediation | Every scan row, every finding and every report entry has a **Recommended fix**: why it matters, numbered steps, the tool's own advice, a code example, priority/effort/SLA and how the fix is verified. Code-quality issues get concrete steps too. | `components/FixPlan.jsx`, `services/remediationService.js` |
| Everything in the final report | The Final Report (screen + Word) now contains **every finding**: open security findings, code-quality issues, findings marked Fixed awaiting rescan, verified fixes (with evidence and how they were fixed), false positives / accepted risks (with notes), merged duplicates and a complete findings register. Every finding is an expandable card with Expand all / Collapse all; printing expands everything. | `services/reportService.js`, `services/reportDocx.js`, `pages/FinalReportPage.jsx` |

Tested end-to-end with real SonarQube, Semgrep, Trivy and OWASP ZAP: 57 findings → all 57 in the report, each with a fix; 27 verified fixed after the rescan; all 6 frameworks scored from all tools; full login / reset / change-password flow; UI checked in a browser with no errors.
