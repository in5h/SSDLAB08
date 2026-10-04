/**
 * database.js — SQLite database initialisation
 * Creates all tables for users, OTP, projects, scans, and compliance.
 */
import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Keep the database outside temporary/build folders so accounts and sessions
// survive restarts. Override with DATA_DIR in backend/.env if needed.
const DB_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "..", "..", "data");
const DB_PATH = path.join(DB_DIR, "parabellum.db");

fs.mkdirSync(DB_DIR, { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL for better concurrency
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// ── Schema ─────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT   NOT NULL,
    organization TEXT    DEFAULT '',
    role         TEXT    DEFAULT 'analyst',
    created_at   TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS otp_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code       TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    used       INTEGER DEFAULT 0,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS projects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    local_path   TEXT,
    sonar_key    TEXT,
    source_type  TEXT    DEFAULT 'upload',
    created_at   TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scan_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    quality_gate  TEXT,
    summary       TEXT,
    measures      TEXT,
    issues        TEXT,
    report_path   TEXT,
    yaml_path     TEXT,
    scanned_at    TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS compliance_scores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id         INTEGER REFERENCES scan_results(id) ON DELETE SET NULL,
    overall_score   REAL    DEFAULT 0,
    nist_govern     REAL    DEFAULT 0,
    nist_identify   REAL    DEFAULT 0,
    nist_protect    REAL    DEFAULT 0,
    nist_detect     REAL    DEFAULT 0,
    nist_respond    REAL    DEFAULT 0,
    nist_recover    REAL    DEFAULT 0,
    total_issues    INTEGER DEFAULT 0,
    blockers        INTEGER DEFAULT 0,
    criticals       INTEGER DEFAULT 0,
    majors          INTEGER DEFAULT 0,
    minors          INTEGER DEFAULT 0,
    infos           INTEGER DEFAULT 0,
    calculated_at   TEXT    DEFAULT (datetime('now'))
  );
`);

// ── Tables added for sessions, pipelines and unified findings ─────
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remember      INTEGER DEFAULT 0,
    user_agent    TEXT,
    ip            TEXT,
    created_at    TEXT    DEFAULT (datetime('now')),
    last_seen_at  TEXT    DEFAULT (datetime('now')),
    expires_at    TEXT    NOT NULL,
    revoked       INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS pipeline_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trigger      TEXT    DEFAULT 'pipeline',
    tools        TEXT,
    target_url   TEXT,
    status       TEXT    DEFAULT 'running',
    stages       TEXT,
    summary      TEXT,
    started_at   TEXT    DEFAULT (datetime('now')),
    finished_at  TEXT
  );

  CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id       INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint      TEXT    NOT NULL,
    tool             TEXT    NOT NULL,
    engine           TEXT,
    rule             TEXT,
    title            TEXT,
    message          TEXT,
    severity         TEXT,
    type             TEXT,
    cwe              TEXT,
    file             TEXT,
    line             INTEGER,
    package_name     TEXT,
    installed_version TEXT,
    fixed_version    TEXT,
    url              TEXT,
    evidence         TEXT,
    raw              TEXT,
    status           TEXT    DEFAULT 'Open',
    owner            TEXT,
    due_date         TEXT,
    triage_note      TEXT,
    first_seen_run   INTEGER,
    last_seen_run    INTEGER,
    fixed_run        INTEGER,
    fixed_at         TEXT,
    created_at       TEXT    DEFAULT (datetime('now')),
    updated_at       TEXT    DEFAULT (datetime('now')),
    UNIQUE (project_id, fingerprint)
  );

  CREATE TABLE IF NOT EXISTS finding_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    run_id      INTEGER,
    event       TEXT    NOT NULL,
    detail      TEXT,
    actor       TEXT,
    at          TEXT    DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
  CREATE INDEX IF NOT EXISTS idx_runs_project ON pipeline_runs(project_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

// ── Migrations for databases created by older versions ─────────────
function addColumns(table, columns) {
  const existing = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  for (const [name, def] of Object.entries(columns)) {
    if (!existing.includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
  }
}
addColumns("otp_codes", { attempts: "INTEGER DEFAULT 0", code_hash: "TEXT", purpose: "TEXT DEFAULT 'login'" });
// Cached framework mappings + RAG recommendation per finding
addColumns("findings", { mappings: "TEXT", recommendation: "TEXT", rec_source: "TEXT" });
// Asset & business context used by risk scoring and the final report
addColumns("projects", {
  asset_name: "TEXT",
  asset_type: "TEXT DEFAULT 'Web Application'",
  environment: "TEXT DEFAULT 'Development'",
  data_classification: "TEXT DEFAULT 'Internal'",
  business_owner: "TEXT",
  business_criticality: "TEXT DEFAULT 'Medium'",
  internet_facing: "INTEGER DEFAULT 0",
  description: "TEXT",
  target_url: "TEXT",
});

// One account per e-mail: normalise any old mixed-case rows, then enforce it in an index too
db.exec("UPDATE users SET email = lower(trim(email)) WHERE email != lower(trim(email))");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(lower(email))");

const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
console.log(`✅ SQLite database ready: ${DB_PATH} (${userCount} account${userCount === 1 ? "" : "s"})`);
export default db;
