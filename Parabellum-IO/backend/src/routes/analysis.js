import express from "express";
import { mapFindingsToGRC } from "../services/grcMappingService.js";
import { generateRiskReport } from "../services/riskReportService.js";

const router = express.Router();

router.post("/grc-map", async (req, res) => {
  try {
    const { projectName, toolName, findingsText } = req.body;

    if (!findingsText || !toolName) {
      return res.status(400).json({ error: "toolName and findingsText are required" });
    }

    console.log("📩 /api/analysis/grc-map called for project:", projectName || "N/A");

    const mapping = await mapFindingsToGRC(toolName, findingsText);

    return res.json({
      projectName: projectName || "Demo Project",
      mapping,
    });
  } catch (err) {
    console.error("❌ Error in /api/analysis/grc-map:", err);
    return res.status(500).json({ error: "GRC mapping failed" });
  }
});

router.post("/risk-report", async (req, res) => {
  try {
    const { projectName, mapping } = req.body;

    if (!mapping) {
      return res.status(400).json({ error: "mapping is required" });
    }

    console.log("📩 /api/analysis/risk-report called for project:", projectName || "N/A");

    const report = await generateRiskReport(projectName || "Unnamed Project", mapping);

    return res.json({
      projectName: projectName || "Unnamed Project",
      report,
    });
  } catch (err) {
    console.error("❌ Error in /api/analysis/risk-report:", err);
    return res.status(500).json({ error: "Report generation failed" });
  }
});

export default router;
