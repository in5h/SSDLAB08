import express from "express";
import multer from "multer";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import AdmZip from "adm-zip";
import { fetchRepoSummary, cloneRepo, parseGithubUrl } from "../services/githubService.js";
import db from "../db/database.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const router = express.Router();

const UPLOADS_DIR = path.join(__dirname, "..", "uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB) || 200;
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.originalname.toLowerCase().endsWith(".zip")) cb(null, true);
    else cb(Object.assign(new Error("Only .zip files are allowed."), { status: 400 }));
  },
});

/** True if `child` is the same as or inside `parent` (after resolving ../ and symlinks). */
function isInside(parent, child) {
  const rel = path.relative(fs.realpathSync(parent), fs.realpathSync(child));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** Only folders the app created itself (ZIP uploads / GitHub clones) may be deleted from disk. */
function isAppOwnedCopy(localPath) {
  try { return isInside(UPLOADS_DIR, localPath) && path.resolve(localPath) !== path.resolve(UPLOADS_DIR); }
  catch { return false; }
}

// ─── Helper: get project and verify ownership ──────────────────────
function getOwnedProject(projectId, userId) {
  return db.prepare(
    "SELECT * FROM projects WHERE id = ? AND user_id = ?"
  ).get(projectId, userId);
}

// ─── Helper: build a project response object with latest compliance ─
function buildProjectResponse(row) {
  const compliance = db.prepare(
    "SELECT overall_score, nist_protect, nist_detect, total_issues, blockers, criticals FROM compliance_scores WHERE project_id = ? ORDER BY calculated_at DESC LIMIT 1"
  ).get(row.id);

  const lastScan = db.prepare(
    "SELECT quality_gate, scanned_at FROM scan_results WHERE project_id = ? ORDER BY scanned_at DESC LIMIT 1"
  ).get(row.id);

  return {
    id: String(row.id),
    name: row.name,
    localPath: row.local_path,
    sonarProjectKey: row.sonar_key,
    sourceType: row.source_type,
    createdAt: row.created_at,
    complianceScore: compliance?.overall_score ?? null,
    context: {
      assetName: row.asset_name || row.name,
      assetType: row.asset_type || "Web Application",
      environment: row.environment || "Development",
      dataClassification: row.data_classification || "Internal",
      businessOwner: row.business_owner || "",
      businessCriticality: row.business_criticality || "Medium",
      internetFacing: !!row.internet_facing,
      description: row.description || "",
      targetUrl: row.target_url || "",
    },
    lastScan: lastScan?.scanned_at ?? null,
    qualityGate: lastScan?.quality_gate ?? null,
  };
}

// ── POST /api/projects/github/import ──────────────────────────────
router.post("/github/import", async (req, res) => {
  try {
    const { repoUrl } = req.body;
    if (!repoUrl) return res.status(400).json({ error: "repoUrl is required" });

    const parsed = parseGithubUrl(repoUrl);
    if (!parsed) return res.status(400).json({ error: "Invalid GitHub URL" });

    const summary = await fetchRepoSummary(repoUrl, process.env.GITHUB_TOKEN);
    const localPath = path.join(UPLOADS_DIR, `github-${Date.now()}-${parsed.repo}`);

    console.log(`📥 Cloning ${parsed.owner}/${parsed.repo}...`);
    await cloneRepo(parsed.owner, parsed.repo, localPath, process.env.GITHUB_TOKEN);

    const result = db.prepare(
      "INSERT INTO projects (user_id, name, local_path, source_type) VALUES (?, ?, ?, ?)"
    ).run(req.user.userId, summary.full_name, localPath, "github");

    const project = getOwnedProject(result.lastInsertRowid, req.user.userId);
    res.json(buildProjectResponse(project));
  } catch (err) {
    console.error("❌ GitHub import error:", err);
    res.status(500).json({ error: err.message || "Failed to import GitHub repo" });
  }
});

// ── POST /api/projects/local ───────────────────────────────────────
// Register a local folder path on the server for scanning (no file upload needed)
router.post("/local", (req, res) => {
  const { name, localPath } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: "Project name is required." });
  if (!localPath || !localPath.trim()) return res.status(400).json({ error: "Local folder path is required." });

  const cleanPath = path.resolve(localPath.trim());

  // Verify the path exists on the server
  if (!fs.existsSync(cleanPath)) {
    return res.status(422).json({ error: `Path does not exist on server: ${cleanPath}` });
  }

  const stat = fs.statSync(cleanPath);
  if (!stat.isDirectory()) {
    return res.status(422).json({ error: `Path is not a directory: ${cleanPath}` });
  }

  // Server folders are sensitive: only allow folders inside PROJECTS_ROOT,
  // or any folder for admins when PROJECTS_ROOT is not configured.
  const projectsRoot = process.env.PROJECTS_ROOT;
  if (projectsRoot) {
    if (!fs.existsSync(projectsRoot) || !isInside(projectsRoot, cleanPath)) {
      return res.status(403).json({ error: `Local folders must be inside PROJECTS_ROOT (${projectsRoot}).` });
    }
  } else if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Registering server folders requires admin, or set PROJECTS_ROOT in backend/.env." });
  }

  const result = db.prepare(
    "INSERT INTO projects (user_id, name, local_path, source_type) VALUES (?, ?, ?, ?)"
  ).run(req.user.userId, name.trim(), cleanPath, "local");

  const project = getOwnedProject(result.lastInsertRowid, req.user.userId);
  console.log(`📁 Local project registered: ${name.trim()} → ${cleanPath}`);
  res.status(201).json(buildProjectResponse(project));
});

// ── POST /api/projects/upload ──────────────────────────────────────
router.post("/upload", (req, res, next) => {
  upload.single("project")(req, res, (err) => {
    if (!err) return next();
    const tooBig = err.code === "LIMIT_FILE_SIZE";
    res.status(tooBig ? 413 : err.status || 400).json({
      error: tooBig ? `File too large (max ${MAX_UPLOAD_MB} MB).` : err.message,
    });
  });
}, (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const isZip = req.file.mimetype.includes("zip") || req.file.originalname.toLowerCase().endsWith(".zip");
  let localPath = req.file.path;

  if (isZip) {
    try {
      const extractDir = path.join(UPLOADS_DIR, `upload-${Date.now()}`);
      fs.mkdirSync(extractDir, { recursive: true });
      const zip = new AdmZip(req.file.path);
      zip.extractAllTo(extractDir, true);
      fs.unlinkSync(req.file.path);
      localPath = extractDir;
      console.log(`📦 ZIP extracted → ${extractDir}`);
    } catch (err) {
      console.error("ZIP extraction failed:", err);
      return res.status(422).json({ error: "Failed to extract ZIP file" });
    }
  }

  const result = db.prepare(
    "INSERT INTO projects (user_id, name, local_path, source_type) VALUES (?, ?, ?, ?)"
  ).run(req.user.userId, req.file.originalname, localPath, "upload");

  const project = getOwnedProject(result.lastInsertRowid, req.user.userId);
  res.json(buildProjectResponse(project));
});

// ── GET /api/projects ─────────────────────────────────────────────
router.get("/", (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC"
  ).all(req.user.userId);
  res.json(rows.map(buildProjectResponse));
});

// ── GET /api/projects/:id ─────────────────────────────────────────
router.get("/:id", (req, res) => {
  const project = getOwnedProject(req.params.id, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found" });
  res.json(buildProjectResponse(project));
});

// ── DELETE /api/projects/:id ──────────────────────────────────────
router.delete("/:id", (req, res) => {
  const project = getOwnedProject(req.params.id, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found" });

  // Never delete a user's own folder (source_type "local") — only the copies
  // this app extracted/cloned into the uploads directory.
  if (project.local_path && project.source_type !== "local" && isAppOwnedCopy(project.local_path)) {
    try {
      fs.rmSync(project.local_path, { recursive: true, force: true });
    } catch (err) {
      console.error("Failed to delete local project files:", err);
    }
  }
  db.prepare("DELETE FROM projects WHERE id = ? AND user_id = ?").run(req.params.id, req.user.userId);
  res.json({ success: true, id: req.params.id });
});

// ── PUT /api/projects/:id/context ─────────────────────────────────
// Asset & business context used for risk scoring and the final report
const CONTEXT_CHOICES = {
  asset_type: ["Web Application", "API", "Mobile Backend", "Microservice", "Library", "Infrastructure", "Other"],
  environment: ["Development", "Test", "Staging", "Production"],
  data_classification: ["Public", "Internal", "Confidential", "Restricted"],
  business_criticality: ["Low", "Medium", "High", "Critical"],
};
router.get("/meta/context-options", (req, res) => res.json(CONTEXT_CHOICES));

router.put("/:id/context", (req, res) => {
  const project = getOwnedProject(req.params.id, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found" });
  const b = req.body || {};
  const v = {
    asset_name: String(b.assetName ?? project.asset_name ?? "").slice(0, 120),
    asset_type: b.assetType ?? project.asset_type,
    environment: b.environment ?? project.environment,
    data_classification: b.dataClassification ?? project.data_classification,
    business_owner: String(b.businessOwner ?? project.business_owner ?? "").slice(0, 120),
    business_criticality: b.businessCriticality ?? project.business_criticality,
    internet_facing: b.internetFacing === undefined ? project.internet_facing : (b.internetFacing ? 1 : 0),
    description: String(b.description ?? project.description ?? "").slice(0, 1000),
    target_url: String(b.targetUrl ?? project.target_url ?? "").trim().slice(0, 300),
  };
  for (const [k, choices] of Object.entries(CONTEXT_CHOICES)) {
    if (v[k] && !choices.includes(v[k])) return res.status(400).json({ error: `${k} must be one of: ${choices.join(", ")}` });
  }
  if (v.target_url && !/^https?:\/\//.test(v.target_url)) return res.status(400).json({ error: "Target URL must start with http:// or https://" });
  db.prepare(`UPDATE projects SET asset_name=@asset_name, asset_type=@asset_type, environment=@environment,
    data_classification=@data_classification, business_owner=@business_owner, business_criticality=@business_criticality,
    internet_facing=@internet_facing, description=@description, target_url=@target_url WHERE id=@id`).run({ ...v, id: project.id });
  // New default owner for findings that have none yet
  if (v.business_owner) db.prepare("UPDATE findings SET owner = ? WHERE project_id = ? AND (owner IS NULL OR owner = '')").run(v.business_owner, project.id);
  res.json(buildProjectResponse(getOwnedProject(project.id, req.user.userId)));
});

// ── GET /api/projects/:id/compliance ─────────────────────────────
router.get("/:id/compliance", (req, res) => {
  const project = getOwnedProject(req.params.id, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found" });

  const scores = db.prepare(`
        SELECT cs.*, sr.quality_gate, sr.summary, sr.measures, sr.issues, sr.report_path, sr.yaml_path, sr.scanned_at
        FROM compliance_scores cs
        LEFT JOIN scan_results sr ON sr.id = cs.scan_id
        WHERE cs.project_id = ?
        ORDER BY cs.calculated_at DESC LIMIT 1
    `).get(req.params.id);

  if (!scores) return res.status(404).json({ error: "No scan results yet. Run a scan first." });

  res.json({
    project: buildProjectResponse(project),
    compliance: {
      overall: scores.overall_score,
      nistScores: {
        govern: scores.nist_govern,
        identify: scores.nist_identify,
        protect: scores.nist_protect,
        detect: scores.nist_detect,
        respond: scores.nist_respond,
        recover: scores.nist_recover,
      },
      totalIssues: scores.total_issues,
      bySeverity: {
        BLOCKER: scores.blockers,
        CRITICAL: scores.criticals,
        MAJOR: scores.majors,
        MINOR: scores.minors,
        INFO: scores.infos,
      },
    },
    lastScan: {
      quality_gate: scores.quality_gate ? JSON.parse(scores.quality_gate) : null,
      measures: scores.measures ? JSON.parse(scores.measures) : null,
      scannedAt: scores.scanned_at,
      reportFile: scores.report_path ? path.basename(scores.report_path) : null,
      yamlFile: scores.yaml_path ? path.basename(scores.yaml_path) : null,
    },
  });
});

// Export helper for sonar route compatibility (now reads from DB)
export function getProjectById(projectId, userId) {
  return db.prepare("SELECT * FROM projects WHERE id = ? AND user_id = ?").get(projectId, userId);
}

/** Find a project by its SonarQube key, only if it belongs to this user. */
export function getOwnedProjectByKey(projectKey, userId) {
  return db.prepare("SELECT * FROM projects WHERE sonar_key = ? AND user_id = ? ORDER BY created_at DESC LIMIT 1").get(projectKey, userId);
}

export { db };
export default router;
