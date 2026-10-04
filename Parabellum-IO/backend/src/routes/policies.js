import express from 'express';
import db from '../db/database.js';
import { createRequire } from 'node:module';
import { scanProject, POLICY_LIBRARY } from '../services/policyEngine.js';

const require = createRequire(import.meta.url);
const CONTROL_CATALOG = require("../data/controlCatalog.json");

const router = express.Router();

// Frameworks the Compliance Mapping page can analyse (all active)
const FRAMEWORKS = [
  { slug: "nist_csf",     name: "NIST CSF 2.0",    desc: "Cybersecurity framework for identifying, protecting, detecting, responding, and recovering from cyber threats." },
  { slug: "iso27001",     name: "ISO 27001:2022",  desc: "Annex A controls for an Information Security Management System (ISMS)." },
  { slug: "cis_controls", name: "CIS Controls v8", desc: "A prioritized set of safeguards (IG1/IG2) to mitigate the most common cyber attacks." },
  { slug: "iso27034",     name: "ISO 27034",       desc: "Application security controls integrated into the software development lifecycle." },
  { slug: "nist_sp800",   name: "NIST SP 800-53",  desc: "Security and privacy control catalogue for information systems." },
  { slug: "owasp_asvs",   name: "OWASP ASVS v4",   desc: "Application Security Verification Standard for testing web application security controls." },
];

/**
 * GET /api/policies/frameworks
 * Supported compliance frameworks with the number of controls in the local catalogue.
 */
router.get('/frameworks', (req, res) => {
  res.json(FRAMEWORKS.map(f => ({
    ...f,
    controls: Object.keys(CONTROL_CATALOG[f.slug] || {}).length,
    status: "Active",
  })));
});

/**
 * GET /api/policies/catalog
 * Returns all built-in policies.
 */
router.get('/catalog', (req, res) => {
  // Strip the check functions — only send the rule metadata
  res.json(POLICY_LIBRARY.map(({ check, ...meta }) => meta));
});

/**
 * POST /api/policies/scan
 * Scans a project and returns policy violations.
 * Body: { projectId }
 */
router.post('/scan', (req, res) => {
  const { projectId } = req.body;
  
  if (!projectId) {
    return res.status(400).json({ error: "projectId is required" });
  }

  // Only the owner may scan a project
  const project = db.prepare("SELECT * FROM projects WHERE id = ? AND user_id = ?").get(projectId, req.user.userId);
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }
  if (!project.local_path) {
    return res.status(422).json({ error: "Project has no local source path." });
  }
  const projectPath = project.local_path;

  try {
    const scanResults = scanProject(projectPath);
    
    // In a real app, we would save to policy_scan_results table here.
    return res.json({
      project: { id: project.id, name: project.name },
      results: scanResults
    });
  } catch (error) {
    console.error("Policy scan error:", error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
