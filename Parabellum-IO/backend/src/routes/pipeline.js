/**
 * pipeline.js — One-click security pipeline
 * POST /api/pipeline/run/:projectId   { tools?, targetUrl?, active? } → { runId }
 * GET  /api/pipeline/runs/:projectId  — run history (with per-stage status)
 * GET  /api/pipeline/run/:runId       — one run (poll while status = running)
 * GET  /api/pipeline/tools            — tool list in pipeline order
 */
import express from "express";
import db from "../db/database.js";
import { getProjectById } from "./projects.js";
import { startPipeline, listRuns, getRun, TOOL_ORDER } from "../services/pipelineService.js";

const router = express.Router();

router.get("/tools", (req, res) => res.json(TOOL_ORDER));

router.post("/run/:projectId", (req, res) => {
  const project = getProjectById(req.params.projectId, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found." });
  const { tools, targetUrl, active } = req.body || {};
  if (targetUrl) {
    try { const u = new URL(targetUrl); if (!["http:", "https:"].includes(u.protocol)) throw new Error(); }
    catch { return res.status(400).json({ error: "Target URL must start with http:// or https://" }); }
    db.prepare("UPDATE projects SET target_url = ? WHERE id = ?").run(targetUrl, project.id);
    project.target_url = targetUrl;
  }
  try {
    const runId = startPipeline(project, { userId: req.user.userId, tools, targetUrl, active: active === true });
    res.status(202).json({ runId });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.get("/runs/:projectId", (req, res) => {
  const project = getProjectById(req.params.projectId, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found." });
  res.json(listRuns(project.id));
});

router.get("/run/:runId", (req, res) => {
  const run = getRun(req.params.runId);
  if (!run || !getProjectById(run.project_id, req.user.userId)) return res.status(404).json({ error: "Run not found." });
  res.json(run);
});

export default router;
