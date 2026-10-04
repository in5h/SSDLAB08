# 🛡️ Parabellum.io — AI-Powered Cybersecurity GRC Platform

Parabellum.io is a full-stack cybersecurity governance, risk, and compliance (GRC) platform designed to help teams prioritize security findings, map them to governance frameworks, and turn raw scanning output into actionable remediation guidance.

The system combines SonarQube vulnerability data, AI-assisted risk analysis, and a NIST CSF-aware retrieval layer to support modern DevSecOps workflows and compliance reporting.

---

## 🎯 Project Overview

This repository contains a complete FYP-style implementation of a cyber risk management platform built with:

- React + Vite frontend for dashboards, authentication, project views, and analysis workflows
- Express.js backend with REST APIs, project management, JWT auth, and scan orchestration
- SonarQube-based vulnerability ingestion and rule analysis
- CWE enrichment and risk scoring (CVSS, MITRE ATT&CK, OWASP Top 10, CAPEC) plus Gemini-generated fix advice
- GRC mapping across frameworks such as NIST CSF 2.0, ISO 27001, CIS Controls, OWASP ASVS, and NIST SP 800-53
- Python FastAPI RAG service using Sentence-Transformers and ChromaDB for control guidance
- Compliance report generation, remediation prioritization, and governance mapping
- SQLite-backed storage, file upload handling, email-based OTP flows, and admin/project tooling

---

## 🧩 Repository Structure

```text
Project/
├── backend/                     # Express.js API, services, and data layer
│   ├── src/
│   ├── data/
│   ├── uploads/
│   ├── package.json
│   └── .env.example
├── frontend/                    # React + Vite dashboard and UI
│   ├── src/
│   ├── public/
│   └── package.json
├── rag-service/                 # Python FastAPI RAG service for control guidance
│   ├── app.py
│   ├── rag_engine.py
│   └── requirements.txt
├── research/python-engine/      # Research-phase Python scripts (not used by the running app)
├── AI-Assisted Vulnerability Prioritization & Remediation Tool/
│   └── Supporting research and data-processing scripts
├── reports/                     # Example scan/export outputs
├── ARCHITECTURE_DIAGRAMS.md
├── IMPLEMENTATION_SUMMARY.md
├── PARABELLUM_CORE_ENGINE_EXPANSION.md
├── PARABELLUM_INTEGRATION_GUIDE.md
├── QUICK_NAVIGATION_GUIDE.md
├── NIST_CSF_SonarQube_Complete_Reference.md
├── README.md
├── package.json
└── LICENSE (if present in subfolders)
```

---

## 🚀 Core Features

### Security scanning & ingestion
- Integrates with SonarQube for project scans and vulnerability extraction
- Normalizes findings across multiple project reports
- Tracks imports, project metadata, and scan outputs

### Risk prioritization
- Maps SonarQube rules to CWE entries
- Enriches findings with CVSS, threat context, and attack patterns
- Computes composite risk scores and prioritization levels
- Identifies remediation urgency based on impact and exploitability

### Governance, risk, and compliance
- Maps vulnerabilities to NIST CSF 2.0 controls and related frameworks
- Supports control alignment across governance domains
- Generates risk reports and compliance summaries for stakeholders

### AI-guided remediation
- "Get AI fix advice" on the Risk Analysis page asks Gemini for plain-language remediation steps per CWE
- Provides RAG-based guidance for framework controls and policy interpretation
- Helps translate technical findings into business-focused recommendations

### Platform capabilities
- Authentication and authorization flow for users and admins
- Project-specific vulnerability analysis
- Report generation and dashboard-based visibility
- Support for upload-driven analysis and security workflows

---

## 🆕 Pipeline, findings tracking and final report

| Page | What it does |
|---|---|
| **Pipeline** | One click runs SonarQube → Semgrep → Snyk → Trivy → OWASP ZAP → Anchore on a project, shows each stage live, stores every finding and keeps a run history. Re-running it after a fix is the **fix verification**: findings the tool no longer reports become *Verified Fixed*, re-appearing ones *Reopened*. The asset & business context (type, environment, data classification, criticality, internet-facing, risk owner, app URL) is set here once per project. |
| **Findings** | All tools' findings in one list with risk (business-context score), confidence (true/false-positive estimate, cross-tool confirmation), owner, status and due date (SLA). Expand a row for the code evidence, framework mappings, RAG recommendation, fix plan and history. *False Positive* / *Accepted Risk* are remembered in later scans. |
| **Final Report** | Executive summary, asset context, pipeline coverage & accuracy (true positives / false negatives), every finding with evidence + mappings to NIST CSF 2.0, ISO 27001, CIS v8, NIST SP 800-53, OWASP ASVS, ISO 27034, OWASP Top 10 and MITRE ATT&CK, RAG recommendation, fix plan, remediation plan with owners/due dates, and fix verification across rescans. Print to PDF or download as Word. |

Recommendations use retrieval-augmented generation: the RAG service (or the built-in BM25 retriever when it is offline) retrieves the relevant controls, and Gemini writes the advice from them (a template is used when no `GEMINI_API_KEY` is set).

Logins: one account per e-mail address, OTP by e-mail (hashed, 5-minute expiry, 60-second resend cooldown, 5 tries), and saved sessions — you stay signed in across page reloads and server restarts (8 hours, or 30 days with "Keep me signed in") until you log out.

## 🏗️ Tech Stack

| Layer | Tools and Frameworks |
|---|---|
| Frontend | React 19, Vite 7, JavaScript (ESM), React Router DOM, ESLint |
| Backend API | Node.js, Express 4, CORS, dotenv, Axios, Multer |
| Authentication | JWT, bcryptjs, Nodemailer, email OTP / MFA flows |
| Database | SQLite via better-sqlite3 |
| Security Scanning | SonarQube, sonarqube-scanner, project scan orchestration |
| AI / LLM | Google Generative AI (Gemini), AI-based risk and remediation reasoning |
| RAG Service | Python, FastAPI, Uvicorn, Sentence-Transformers, ChromaDB, PyTorch |
| Data / Utilities | adm-zip, simple-git, file upload processing, scan report handling |
| Reporting / Governance | GRC mapping logic, NIST CSF mapping, compliance/risk report generation |
| Dev Workflow | npm, pip, Vite dev server, Node process management |

---

## 🔄 Typical Workflow

1. A user creates or selects a project in the platform.
2. The project is scanned with SonarQube or fed with an exported report.
3. Findings are normalized and mapped to vulnerability metadata and controls.
4. AI and GRC services score, prioritize, and contextualize the issues.
5. The platform produces compliance mappings, risk summaries, and remediation recommendations.
6. The user can review the findings through the dashboard and export reports.

---

## ✅ Getting Started

### Prerequisites

- Node.js 18+
- Python 3.10+
- npm
- pip
- SonarQube instance running locally or remotely
- Gemini API key for AI fix advice (optional)
- Optional scanners — see [Security tools setup](#-security-tools-setup)

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
```

### 2. Install everything (backend + frontend)

```bash
npm install
```

This one command also installs the `backend/` and `frontend/` packages.

> Login: sign up, then sign in with your password + the 6-digit code (shown on screen until SMTP is configured — see `OTP_DELIVERY`). "Forgot password?" on the login page and the 🔑 Password button in the top bar handle password reset/change. Then `npm run dev` starts the backend (Windows, macOS and Linux). The first start creates `backend/.env` from `.env.example` and generates a random `JWT_SECRET`; you still need to add your SMTP and SonarQube settings. The steps below are the manual way.

### 3. Backend setup

```bash
cd backend
npm install
```

Copy the sample environment file and configure your values:

```bash
copy .env.example .env
```

Then edit the environment file with your own credentials, including:

- `JWT_SECRET` — **required**, the backend refuses to start without a 16+ character secret
- `ADMIN_EMAIL` — your e-mail; that account becomes admin when it signs up
- SMTP e-mail config for OTP login (`EMAIL_USER` / `EMAIL_PASS`). Without it the login code is shown on the login screen. `OTP_DELIVERY` = `auto` (default) / `email` / `screen` / `both`
- Gemini API key
- SonarQube URL and token
- RAG service URL (`http://localhost:5000`)
- `PROJECTS_ROOT` — folder non-admin users may register local projects from (optional)

Start the backend:

```bash
npm start
```

The backend is expected to run at:

```text
http://localhost:4000
```

### 4. Frontend setup

```bash
cd ../frontend
npm install
npm run dev
```

The frontend is typically served at:

```text
http://localhost:5173
```

### 5. RAG service setup

```bash
cd ../rag-service
pip install -r requirements.txt
python app.py
```

The RAG service is served at:

```text
http://localhost:5000
```

> `RAG_SERVICE_URL` in `backend/.env` must match (default `http://localhost:5000`). Change the port with the `RAG_PORT` environment variable.
> The first start downloads the `all-MiniLM-L6-v2` embedding model, so it needs internet once. When the RAG service is offline the backend falls back to its built-in rule-based mapping.

### 6. Security tools setup

| Tool | What Parabellum runs | Setup |
|---|---|---|
| SonarQube | `sonarqube-scanner` + SonarQube Web API | `docker run -d -p 9000:9000 sonarqube:community`, create a token, set `SONARQUBE_URL` / `SONARQUBE_TOKEN` |
| Semgrep | `semgrep scan --config auto --json` | `pip install semgrep` (`--config auto` needs internet; set `SEMGREP_CONFIG` to a local rules folder for offline use) |
| Snyk | `snyk test --all-projects --json` | `npm install -g snyk`, then `snyk auth` (or `SNYK_TOKEN`) |
| Trivy | `trivy fs --scanners vuln,misconfig,secret --format json` | Install from https://trivy.dev (or set `TRIVY_PATH`) |
| OWASP ZAP | ZAP REST API: spider → passive (optional active) scan → alerts | `docker run -p 8090:8090 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.key=<key> -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true`, set `ZAP_URL` / `ZAP_API_KEY`, then enter the running app's URL on the ZAP tab |
| Anchore | Grype: `grype dir:<project> -o json` + STOP/WARN policy gate | Install Grype from https://github.com/anchore/grype (or set `GRYPE_PATH`) |

The Tools page shows **Connected** only when the real tool answers. If Trivy, ZAP or Grype is
missing, those tabs can still run Parabellum's small built-in checks; the results are clearly
labelled "built-in checks" with a warning, and are not a substitute for the real scanner.

---

## 🔐 Environment Variables

A full example is provided in [backend/.env.example](backend/.env.example).

Key variables include:

```env
PORT=4000
JWT_SECRET=your_jwt_secret_here
ADMIN_EMAIL=you@example.com
OTP_DELIVERY=auto
GEMINI_API_KEY=your_gemini_api_key_here
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_app_password_here
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=your_sonarqube_token_here
ZAP_URL=http://localhost:8090
RAG_SERVICE_URL=http://localhost:5000
```

---

## 📌 What Makes This Project Useful

This project serves as a practical cybersecurity decision-support system for:

- application security teams
- DevSecOps pipelines
- GRC and compliance stakeholders
- project owners who need risk-based prioritization
- academic or research environments building AI-assisted security tooling

It bridges technical code scanning data and governance-level decision making, turning isolated findings into a coherent prioritization and compliance narrative.

---

## 📚 Documentation

The repository includes several supporting documents that explain the architecture and implementation in more detail:

- [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md)
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)
- [PARABELLUM_CORE_ENGINE_EXPANSION.md](PARABELLUM_CORE_ENGINE_EXPANSION.md)
- [PARABELLUM_INTEGRATION_GUIDE.md](PARABELLUM_INTEGRATION_GUIDE.md)
- [QUICK_NAVIGATION_GUIDE.md](QUICK_NAVIGATION_GUIDE.md)
- [NIST_CSF_SonarQube_Complete_Reference.md](NIST_CSF_SonarQube_Complete_Reference.md)

---

## 🧠 Project Intent

The project demonstrates how vulnerability findings from code scanning tools can be converted into:

- prioritized remediation actions
- risk narratives for stakeholders
- compliance mapping against recognized frameworks
- AI-enabled guidance for secure engineering decisions

This makes it a strong example of applied cybersecurity engineering, governance automation, and AI-assisted security operations.

---

## 📜 License

This project is intended for academic and research use as part of a final-year project and security engineering prototype.

---

## 👤 Contribution

This repository is suitable for extension with additional scanners, new framework mappings, richer AI workflows, and expanded reporting modules.
