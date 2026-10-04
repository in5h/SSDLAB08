/**
 * admin.js — Admin-only routes for user management
 * All routes require a valid JWT with role === "admin"
 *
 * GET  /api/admin/users         — list all users
 * GET  /api/admin/users/:id     — get single user
 * DELETE /api/admin/users/:id   — delete a user
 * PATCH /api/admin/users/:id    — update role or name
 */

import express from "express";
import db from "../db/database.js";
import { requireAuth } from "../middleware/authMiddleware.js";

const router = express.Router();

// Middleware: must be authenticated + have admin role
function requireAdmin(req, res, next) {
    // Check the current role in the DB, not just the (up to 8h old) token
    const row = db.prepare("SELECT role FROM users WHERE id = ?").get(req.user?.userId);
    if (row?.role !== "admin") {
        return res.status(403).json({ error: "Admin access required." });
    }
    next();
}

router.use(requireAuth, requireAdmin);

// ── GET /api/admin/users ──────────────────────────────────────────────
router.get("/users", (req, res) => {
    const users = db.prepare(`
        SELECT u.id, u.name, u.email, u.organization, u.role, u.created_at,
               COUNT(DISTINCT p.id) AS project_count,
               COUNT(DISTINCT sr.id) AS scan_count
        FROM users u
        LEFT JOIN projects p ON p.user_id = u.id
        LEFT JOIN scan_results sr ON sr.project_id = p.id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    `).all();
    res.json({ total: users.length, users });
});

// ── GET /api/admin/users/:id ──────────────────────────────────────────
router.get("/users/:id", (req, res) => {
    const user = db.prepare(`
        SELECT id, name, email, organization, role, created_at FROM users WHERE id = ?
    `).get(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });

    const projects = db.prepare(
        "SELECT id, name, source_type, created_at FROM projects WHERE user_id = ? ORDER BY created_at DESC"
    ).all(req.params.id);

    res.json({ user, projects });
});

// ── PATCH /api/admin/users/:id ────────────────────────────────────────
router.patch("/users/:id", (req, res) => {
    const { name, role, organization } = req.body;
    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });

    const validRoles = ["admin", "analyst", "viewer"];
    if (role && !validRoles.includes(role)) {
        return res.status(400).json({ error: `Role must be one of: ${validRoles.join(", ")}` });
    }

    db.prepare(`
        UPDATE users SET
            name         = COALESCE(?, name),
            role         = COALESCE(?, role),
            organization = COALESCE(?, organization)
        WHERE id = ?
    `).run(name || null, role || null, organization || null, req.params.id);

    const updated = db.prepare(
        "SELECT id, name, email, organization, role, created_at FROM users WHERE id = ?"
    ).get(req.params.id);
    res.json({ message: "User updated.", user: updated });
});

// ── DELETE /api/admin/users/:id ───────────────────────────────────────
router.delete("/users/:id", (req, res) => {
    if (String(req.params.id) === String(req.user.userId)) {
        return res.status(400).json({ error: "You cannot delete your own account via admin." });
    }
    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });

    db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
    res.json({ success: true, deletedId: req.params.id });
});

// ── GET /api/admin/stats ──────────────────────────────────────────────
router.get("/stats", (req, res) => {
    const totalUsers  = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
    const totalProjects = db.prepare("SELECT COUNT(*) AS c FROM projects").get().c;
    const totalScans  = db.prepare("SELECT COUNT(*) AS c FROM scan_results").get().c;
    const recentUsers = db.prepare(
        "SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 5"
    ).all();
    res.json({ totalUsers, totalProjects, totalScans, recentUsers });
});

// ── GET /api/admin/all-projects ───────────────────────────────────────
// Returns every project across all users with owner info
router.get("/all-projects", (req, res) => {
    const projects = db.prepare(`
        SELECT p.id, p.name, p.source_type, p.created_at,
               u.id AS user_id, u.name AS user_name, u.email AS user_email,
               (SELECT COUNT(*) FROM scan_results sr WHERE sr.project_id = p.id) AS scan_count,
               (SELECT cs.overall_score FROM compliance_scores cs WHERE cs.project_id = p.id ORDER BY cs.calculated_at DESC LIMIT 1) AS compliance_score
        FROM projects p
        JOIN users u ON u.id = p.user_id
        ORDER BY p.created_at DESC
    `).all();
    res.json({ total: projects.length, projects });
});

// ── GET /api/admin/users/:id/projects ─────────────────────────────────
router.get("/users/:id/projects", (req, res) => {
    const user = db.prepare("SELECT id, name, email FROM users WHERE id = ?").get(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found." });

    const projects = db.prepare(`
        SELECT p.id, p.name, p.source_type, p.created_at,
               (SELECT COUNT(*) FROM scan_results sr WHERE sr.project_id = p.id) AS scan_count,
               (SELECT cs.overall_score FROM compliance_scores cs WHERE cs.project_id = p.id ORDER BY cs.calculated_at DESC LIMIT 1) AS compliance_score,
               (SELECT sr.quality_gate FROM scan_results sr WHERE sr.project_id = p.id ORDER BY sr.scanned_at DESC LIMIT 1) AS last_quality_gate,
               (SELECT sr.scanned_at FROM scan_results sr WHERE sr.project_id = p.id ORDER BY sr.scanned_at DESC LIMIT 1) AS last_scanned_at
        FROM projects p
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    `).all(req.params.id);

    res.json({ user, projects, total: projects.length });
});

export default router;
