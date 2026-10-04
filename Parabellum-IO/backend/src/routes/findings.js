/**
 * findings.js — Unified findings from all tools
 * GET   /api/findings/:projectId                 — all findings (with confidence, risk, mappings)
 * GET   /api/findings/:projectId/:id/history     — lifecycle events of one finding
 * PATCH /api/findings/:projectId/:id             — { status?, owner?, due_date?, triage_note? }
 * POST  /api/findings/:projectId/refresh-mappings — recompute framework mappings + RAG recommendations
 */
import express from "express";
import db from "../db/database.js";
import { getProjectById } from "./projects.js";
import { listFindings, updateFinding, findingHistory, STATUSES } from "../services/findingService.js";
import { buildFixPlan } from "../services/remediationService.js";
import { refreshMappings } from "../services/pipelineService.js";

const router = express.Router();

function owned(req, res) {
  const project = getProjectById(req.params.projectId, req.user.userId);
  if (!project) res.status(404).json({ error: "Project not found." });
  return project;
}

router.get("/:projectId", (req, res) => {
  const project = owned(req, res); if (!project) return;
  const findings = listFindings(project.id).map(f => ({ ...f, fixPlan: buildFixPlan(f, f.risk) }));
  res.json({ statuses: STATUSES, findings });
});

router.get("/:projectId/:id/history", (req, res) => {
  const project = owned(req, res); if (!project) return;
  const f = db.prepare("SELECT id FROM findings WHERE id = ? AND project_id = ?").get(req.params.id, project.id);
  if (!f) return res.status(404).json({ error: "Finding not found." });
  res.json(findingHistory(f.id));
});

router.patch("/:projectId/:id", (req, res) => {
  const project = owned(req, res); if (!project) return;
  try {
    const f = updateFinding(project.id, req.params.id, req.body || {}, req.user.email);
    if (!f) return res.status(404).json({ error: "Finding not found." });
    res.json({ ok: true, finding: { id: f.id, status: f.status, owner: f.owner, due_date: f.due_date, triage_note: f.triage_note } });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.post("/:projectId/refresh-mappings", async (req, res) => {
  const project = owned(req, res); if (!project) return;
  try { res.json({ updated: await refreshMappings(project.id, { onlyMissing: false }) }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

export default router;
