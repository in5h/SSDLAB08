/**
 * report.js — Final security & compliance report
 * GET /api/report/:projectId        — full report as JSON (rendered by the Final Report page)
 * GET /api/report/:projectId/docx   — same report as a Word document
 */
import express from "express";
import { getProjectById } from "./projects.js";
import { buildReport } from "../services/reportService.js";
import { reportToDocx } from "../services/reportDocx.js";

const router = express.Router();

router.get("/:projectId", async (req, res) => {
  const project = getProjectById(req.params.projectId, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found." });
  try { res.json(await buildReport(project.id, req.user)); }
  catch (err) { console.error("❌ Report error:", err); res.status(500).json({ error: err.message }); }
});

router.get("/:projectId/docx", async (req, res) => {
  const project = getProjectById(req.params.projectId, req.user.userId);
  if (!project) return res.status(404).json({ error: "Project not found." });
  try {
    const report = await buildReport(project.id, req.user);
    const buf = await reportToDocx(report);
    const name = `${project.name.replace(/[^a-z0-9_.-]+/gi, "_")}_security_report.docx`;
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
    res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
    res.send(buf);
  } catch (err) { console.error("❌ Report DOCX error:", err); res.status(500).json({ error: err.message }); }
});

export default router;
