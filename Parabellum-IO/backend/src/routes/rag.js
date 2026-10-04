/**
 * rag.js — Express router for the NIST CSF RAG endpoints
 *
 * POST  /api/rag/map          — map a single finding to NIST CSF controls
 * POST  /api/rag/map-batch    — map multiple findings at once
 * POST  /api/rag/feedback     — submit a confirmed human mapping
 * POST  /api/rag/retrain      — retrain the model with stored feedback
 * GET   /api/rag/stats        — index + feedback statistics
 * GET   /api/rag/health       — check if Python RAG service is online
 * GET   /api/rag/controls     — list all NIST CSF 2.0 controls
 * POST  /api/rag/map-issues   — map an array of SonarQube issue objects
 */

import express from "express";
import {
    mapFindingToNIST,
    mapFindingsBatch,
    submitFeedback,
    triggerRetrain,
    getRagStats,
    checkRagHealth,
    listNISTControls,
} from "../services/ragService.js";

const router = express.Router();

// ── GET /api/rag/health ────────────────────────────────────────────
router.get("/health", async (req, res) => {
    const health = await checkRagHealth();
    const status = health.online ? 200 : 503;
    res.status(status).json(health);
});

// ── GET /api/rag/stats ─────────────────────────────────────────────
router.get("/stats", async (req, res) => {
    try {
        const stats = await getRagStats();
        res.json(stats);
    } catch (err) {
        res.status(503).json({ error: "RAG service unreachable: " + err.message });
    }
});

// ── GET /api/rag/controls ──────────────────────────────────────────
router.get("/controls", async (req, res) => {
    try {
        const controls = await listNISTControls();
        res.json(controls);
    } catch (err) {
        res.status(503).json({ error: "RAG service unreachable: " + err.message });
    }
});

// ── POST /api/rag/map ──────────────────────────────────────────────
// Body: { finding: string, top_k?: number }
router.post("/map", async (req, res) => {
    const { finding, top_k = 5 } = req.body;
    if (!finding) {
        return res.status(400).json({ error: "finding is required" });
    }
    try {
        const controls = await mapFindingToNIST(finding, top_k);
        res.json({ finding, controls });
    } catch (err) {
        res.status(503).json({ error: "RAG mapping failed: " + err.message });
    }
});

// ── POST /api/rag/map-batch ────────────────────────────────────────
// Body: { findings: string[], top_k?: number }
router.post("/map-batch", async (req, res) => {
    const { findings, top_k = 3 } = req.body;
    if (!Array.isArray(findings) || findings.length === 0) {
        return res.status(400).json({ error: "findings must be a non-empty array of strings" });
    }
    try {
        const results = await mapFindingsBatch(findings, top_k);
        res.json({ total: findings.length, results });
    } catch (err) {
        res.status(503).json({ error: "Batch mapping failed: " + err.message });
    }
});

// ── POST /api/rag/map-issues ───────────────────────────────────────
// Accepts an array of SonarQube issue objects (from /api/sonar/issues)
// and maps each to NIST CSF controls.
// Body: { issues: [ { message, severity, type, rule, component, line }, ... ] }
router.post("/map-issues", async (req, res) => {
    const { issues, top_k = 3 } = req.body;
    if (!Array.isArray(issues) || issues.length === 0) {
        return res.status(400).json({ error: "issues must be a non-empty array" });
    }

    // Convert each SonarQube issue object into a descriptive string for embedding
    const findings = issues.map((issue) =>
        [
            `[${issue.severity || ""}]`,
            `[${issue.type || ""}]`,
            issue.message || "",
            issue.rule ? `(Rule: ${issue.rule})` : "",
            issue.component ? `File: ${issue.component}` : "",
            issue.line ? `Line: ${issue.line}` : "",
        ]
            .filter(Boolean)
            .join(" ")
    );

    try {
        const results = await mapFindingsBatch(findings, top_k);

        // Merge: attach original issue data alongside NIST mapping
        const mapped = results.map((r, i) => ({
            issue: issues[i],
            finding_text: r.finding,
            nist_controls: r.controls,
            error: r.error || null,
        }));

        res.json({
            total: issues.length,
            mapped,
        });
    } catch (err) {
        res.status(503).json({ error: "Issue mapping failed: " + err.message });
    }
});

// ── POST /api/rag/feedback ─────────────────────────────────────────
// Body: { finding_text: string, control_id: string, source?: "human"|"auto" }
router.post("/feedback", async (req, res) => {
    const { finding_text, control_id, source } = req.body;
    if (!finding_text || !control_id) {
        return res.status(400).json({ error: "finding_text and control_id are required" });
    }
    try {
        const result = await submitFeedback(finding_text, control_id, source);
        res.json(result);
    } catch (err) {
        res.status(503).json({ error: "Feedback failed: " + err.message });
    }
});

// ── POST /api/rag/retrain ──────────────────────────────────────────
router.post("/retrain", async (req, res) => {
    try {
        const result = await triggerRetrain();
        res.json(result);
    } catch (err) {
        res.status(503).json({ error: "Retrain failed: " + err.message });
    }
});

export default router;
