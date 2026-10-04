import express from "express";
import db from "../db/database.js";
import { mapIssuesToGRC } from "../services/grcMappingService.js";
import { scanProject } from "../services/policyEngine.js";
import { getOwnedProjectByKey, getProjectById } from "./projects.js";
import { loadProjectIssues, grcFromMappings, analysableProjects } from "../services/projectIssues.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// Official control titles/groups for all 6 frameworks (generated from rag-service/*_data.py)
const CONTROL_CATALOG = require("../data/controlCatalog.json");
const RAG_BASE = process.env.RAG_SERVICE_URL || "http://localhost:5000";

const router = express.Router();

// ── Framework Registry ──────────────────────────────────────────────
// Defines the group field, display label, and known group values for each framework
const FRAMEWORK_REGISTRY = {
  nist_csf: {
    label: "NIST CSF 2.0",
    groupField: "function",
    groups: ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"],
    controlPrefix: ["GV.", "ID.", "PR.", "DE.", "RS.", "RC."],
  },
  iso27001: {
    label: "ISO 27001:2022",
    groupField: "domain",
    groups: ["Organizational Controls", "People Controls", "Physical Controls", "Technological Controls"],
    controlPrefix: ["A."],
  },
  iso27034: {
    label: "ISO 27034",
    groupField: "domain",
    groups: [
      "Application Security Design", "Authentication and Access Control",
      "Input Validation and Output Encoding", "Data Security",
      "Error Handling and Logging", "Configuration and Infrastructure Security",
      "Application Security Testing",
    ],
    controlPrefix: ["ISO27034-ASC-"],
  },
  nist_sp800: {
    label: "NIST SP 800-53",
    groupField: "family",
    groups: [
      "Access Control", "Audit and Accountability",
      "Assessment Authorization and Monitoring", "Configuration Management",
      "Identification and Authentication", "Incident Response",
      "Risk Assessment", "System and Communications Protection",
      "System and Information Integrity", "System and Services Acquisition",
    ],
    controlPrefix: ["AC-", "AU-", "CA-", "CM-", "IA-", "IR-", "RA-", "SC-", "SI-", "SA-"],
  },
  cis_controls: {
    label: "CIS Controls v8",
    groupField: "ig_level",
    groups: ["IG1", "IG2"],
    controlPrefix: ["CIS-"],
  },
  owasp_asvs: {
    label: "OWASP ASVS v4",
    groupField: "chapter",
    groups: [
      "Architecture, Design and Threat Modelling", "Authentication",
      "Session Management", "Access Control",
      "Validation, Sanitization and Encoding", "Stored Cryptography",
      "Error Handling and Logging", "Data Protection",
      "Communication", "Malicious Code", "Business Logic",
      "Files and Resources", "API and Web Service", "Configuration",
    ],
    controlPrefix: ["ASVS-"],
  },
};

// ── NIST CSF 2.0 Control Catalogue (kept for backward compat + local fallback) ──
const NIST_CATALOGUE = {
  // GOVERN
  "GV.OC-01": { fn:"GOVERN",   category:"Organizational Context", clause:"GV.OC-01", description:"The organizational mission is understood and informs cybersecurity risk management decisions." },
  "GV.RM-01": { fn:"GOVERN",   category:"Risk Management Strategy", clause:"GV.RM-01", description:"Risk management objectives are established and agreed to by organizational stakeholders." },
  "GV.SC-01": { fn:"GOVERN",   category:"Cybersecurity Supply Chain Risk", clause:"GV.SC-01", description:"A cybersecurity supply chain risk management program has been established." },
  // IDENTIFY
  "ID.AM-01": { fn:"IDENTIFY", category:"Asset Management", clause:"ID.AM-01", description:"Inventories of hardware managed by the organization are maintained." },
  "ID.AM-02": { fn:"IDENTIFY", category:"Asset Management", clause:"ID.AM-02", description:"Inventories of software, services, and systems managed by the organization are maintained." },
  "ID.RA-01": { fn:"IDENTIFY", category:"Risk Assessment", clause:"ID.RA-01", description:"Vulnerabilities in assets are identified, validated, and recorded." },
  "ID.RA-02": { fn:"IDENTIFY", category:"Risk Assessment", clause:"ID.RA-02", description:"Cyber threat intel is received from information‑sharing forums and sources." },
  // PROTECT
  "PR.AA-01": { fn:"PROTECT",  category:"Identity Management & Access Control", clause:"PR.AA-01", description:"Identities and credentials for authorized users, services, and hardware are managed." },
  "PR.AA-05": { fn:"PROTECT",  category:"Identity Management & Access Control", clause:"PR.AA-05", description:"Access permissions, entitlements, and authorizations are defined in a policy." },
  "PR.DS-01": { fn:"PROTECT",  category:"Data Security", clause:"PR.DS-01", description:"Data-at-rest is protected." },
  "PR.DS-02": { fn:"PROTECT",  category:"Data Security", clause:"PR.DS-02", description:"Data-in-transit is protected." },
  "PR.PS-01": { fn:"PROTECT",  category:"Platform Security", clause:"PR.PS-01", description:"Configuration management practices are established and applied." },
  "PR.PS-02": { fn:"PROTECT",  category:"Platform Security", clause:"PR.PS-02", description:"Software is maintained, replaced, and removed commensurate with risk." },
  // DETECT
  "DE.CM-01": { fn:"DETECT",   category:"Continuous Monitoring", clause:"DE.CM-01", description:"Networks and network services are monitored to find potentially adverse events." },
  "DE.AE-02": { fn:"DETECT",   category:"Adverse Event Analysis", clause:"DE.AE-02", description:"Potentially adverse events are analyzed to better characterize them." },
  // RESPOND
  "RS.MA-01": { fn:"RESPOND",  category:"Incident Management", clause:"RS.MA-01", description:"The incident response plan is executed in coordination with relevant third parties." },
  "RS.AN-03": { fn:"RESPOND",  category:"Incident Analysis", clause:"RS.AN-03", description:"Analysis is performed to establish what has taken place during an incident." },
  "RS.CO-02": { fn:"RESPOND",  category:"Incident Response Reporting", clause:"RS.CO-02", description:"Internal and external stakeholders are notified of incidents." },
  // RECOVER
  "RC.RP-01": { fn:"RECOVER",  category:"Incident Recovery Plan", clause:"RC.RP-01", description:"The recovery portion of the incident response plan is executed once initiated." },
  "RC.CO-03": { fn:"RECOVER",  category:"Recovery Communication", clause:"RC.CO-03", description:"Recovery activities and progress in restoring operational capabilities are communicated." },
  // CIS / ISO aliases (for local mapping fallback)
  "A.8.28":   { fn:"PROTECT",  category:"Secure Coding", clause:"A.8.28",  description:"ISO 27001 A.8.28 – Secure coding principles are applied." },
  "A.8.29":   { fn:"PROTECT",  category:"Security Testing", clause:"A.8.29", description:"ISO 27001 A.8.29 – Security testing in development and acceptance." },
  "A.8.24":   { fn:"PROTECT",  category:"Cryptography", clause:"A.8.24",   description:"ISO 27001 A.8.24 – Use of cryptography." },
  "A.12.6.1": { fn:"DETECT",   category:"Vulnerability Management", clause:"A.12.6.1", description:"ISO 27001 A.12.6.1 – Technical vulnerability management." },
  "A.14.2.8": { fn:"PROTECT",  category:"System Security Testing", clause:"A.14.2.8", description:"ISO 27001 A.14.2.8 – System security testing." },
  "A.8.1.1":  { fn:"IDENTIFY", category:"Asset Inventory", clause:"A.8.1.1", description:"ISO 27001 A.8.1.1 – Inventory of assets." },
};

function lookupControl(id) {
  if (NIST_CATALOGUE[id]) return NIST_CATALOGUE[id];
  const c = CONTROL_CATALOG.nist_csf[id];
  if (c) return { fn: c.group, category: c.title, clause: id, description: c.title };
  return { fn: guessFunction(id), category: id, clause: id, description: id };
}

// Same issue can be mapped to a control more than once (e.g. by rule + keyword) — count it once.
function violationKey(v) {
  return `${v.rule}|${v.message}|${v.component}|${v.line}`;
}
function pushUnique(list, v) {
  if (!list.some(x => violationKey(x) === violationKey(v))) list.push(v);
}

function guessFunction(id) {
  if (!id) return "IDENTIFY";
  const prefix = id.split(".")[0].split("-")[0];
  return { GV:"GOVERN", ID:"IDENTIFY", PR:"PROTECT", DE:"DETECT", RS:"RESPOND", RC:"RECOVER" }[prefix] || "IDENTIFY";
}

// ── Per-control severity scoring ──────────────────────────────────
const SEV_DEDUCT = { BLOCKER: 55, CRITICAL: 40, MAJOR: 20, MINOR: 8, INFO: 2 };

function scoreControl(violations) {
  let d = 0;
  for (const v of violations) {
    d += SEV_DEDUCT[(v.severity || 'MINOR').toUpperCase()] ?? 8;
  }
  return Math.max(0, 100 - d);
}

function calcOverallScore(failedControls, totalIssues) {
  if (totalIssues === 0) return { score: 100, grade: 'A', status: 'PASS' };
  if (!failedControls || failedControls.length === 0) {
    return { score: 100, grade: 'A', status: 'PASS' };
  }
  const scores = failedControls.map(c => scoreControl(c.violations));
  const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const grade = avg >= 90 ? 'A' : avg >= 75 ? 'B' : avg >= 60 ? 'C' : avg >= 40 ? 'D' : 'F';
  return { score: avg, grade, status: avg >= 70 ? 'PASS' : 'FAIL' };
}

// ── Build failed controls for NIST CSF (local fallback) ──────────
function buildFailedControlsNIST(mappedItems) {
  const controlMap = {};
  for (const item of mappedItems) {
    const controls = item.nist_controls || item.grc_mapping?.nist_csf || [];
    for (const ctrl of controls) {
      const id = typeof ctrl === "object" ? ctrl.control_id : ctrl;
      if (!id) continue;
      const meta = lookupControl(id);
      if (!controlMap[id]) {
        controlMap[id] = {
          control_id: id, function: meta.fn, category: meta.category,
          clause: meta.clause, description: meta.description,
          status: "FAIL", violations: [],
        };
      }
      pushUnique(controlMap[id].violations, {
        severity: item.issue?.severity || "MINOR",
        type: item.issue?.type || "",
        message: item.issue?.message || item.finding_text || "",
        component: item.issue?.component || "",
        line: item.issue?.line || null,
        rule: item.issue?.rule || "",
      });
    }
  }
  return Object.values(controlMap).sort((a, b) => {
    const maxSev = (list) => Math.max(...list.map(v => SEV_DEDUCT[(v.severity?.toUpperCase())] ?? 0));
    return maxSev(b.violations) - maxSev(a.violations);
  });
}

// ── Build failed controls from RAG multi-framework response ──────
function buildFailedControlsFromRAG(mappedItems, framework, groupField) {
  const controlMap = {};
  for (const item of mappedItems) {
    const controls = item.controls || [];
    for (const ctrl of controls) {
      const id = ctrl.control_id;
      if (!id) continue;
      const group = ctrl.group || ctrl[groupField] || "General";
      if (!controlMap[id]) {
        controlMap[id] = {
          control_id: id,
          [groupField]: group,
          function: group, // backward compat: 'function' key always present
          category: ctrl.title || "",
          clause: id,
          description: ctrl.title || "",
          status: "FAIL",
          violations: [],
        };
      }
      pushUnique(controlMap[id].violations, {
        severity: item.issue?.severity || "MINOR",
        type: item.issue?.type || "",
        message: item.issue?.message || item.finding_text || "",
        component: item.issue?.component || "",
        line: item.issue?.line || null,
        rule: item.issue?.rule || "",
      });
    }
  }
  return Object.values(controlMap).sort((a, b) => {
    const maxSev = (list) => Math.max(...list.map(v => SEV_DEDUCT[(v.severity?.toUpperCase())] ?? 0));
    return maxSev(b.violations) - maxSev(a.violations);
  });
}

// ── Build failed controls from local GRC mapping for non-NIST frameworks ──
function buildFailedControlsLocal(mappedItems, frameworkKey, framework, groupField) {
  const catalog = CONTROL_CATALOG[framework] || {};
  const controlMap = {};
  for (const item of mappedItems) {
    const controls = item.grc_mapping?.[frameworkKey] || [];
    for (const id of controls) {
      if (!id) continue;
      if (!controlMap[id]) {
        const meta = catalog[id] || {};
        controlMap[id] = {
          control_id: id,
          [groupField]: meta.group || "General",
          function: meta.group || "General",
          category: meta.title || id,
          clause: id,
          description: meta.title || id,
          status: "FAIL",
          violations: [],
        };
      }
      pushUnique(controlMap[id].violations, {
        severity: item.issue?.severity || "MINOR",
        type: item.issue?.type || "",
        message: item.issue?.message || "",
        component: item.issue?.component || "",
        line: item.issue?.line || null,
        rule: item.issue?.rule || "",
      });
    }
  }
  return Object.values(controlMap).sort((a, b) => {
    const maxSev = (list) => Math.max(...list.map(v => SEV_DEDUCT[(v.severity?.toUpperCase())] ?? 0));
    return maxSev(b.violations) - maxSev(a.violations);
  });
}

function buildFunctionBreakdown(failedControls, groupField, groups) {
  return groups.map(grp => {
    const grpControls = failedControls.filter(c => c[groupField] === grp || c.function === grp);
    if (grpControls.length === 0) {
      return { [groupField]: grp, function: grp, violations: 0, failedControls: [], score: 100, status: "PASS" };
    }
    const scores = grpControls.map(c => scoreControl(c.violations));
    const grpScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    const totalViolations = grpControls.reduce((a, c) => a + c.violations.length, 0);
    return {
      [groupField]: grp,
      function: grp,
      violations: totalViolations,
      failedControls: grpControls.map(c => c.control_id),
      score: grpScore,
      status: grpScore >= 80 ? "WARN" : "FAIL",
    };
  });
}

// ── POST /api/compliance/analyze ───────────────────────────────────
// Supports optional `framework` field: nist_csf (default), iso27001, iso27034, nist_sp800, cis_controls, owasp_asvs
router.post("/analyze", async (req, res) => {
  try {
    const { projectKey, projectId: bodyProjectId, projectName, framework = "nist_csf" } = req.body;
    if (!projectKey && !bodyProjectId) return res.status(400).json({ error: "projectId (or projectKey) is required" });

    // Only allow analysis of the caller's own projects
    const ownedProject = bodyProjectId ? getProjectById(bodyProjectId, req.user.userId) : getOwnedProjectByKey(projectKey, req.user.userId);
    if (!ownedProject) return res.status(404).json({ error: "Project not found." });
    const projectId = ownedProject.id;

    const fwMeta = FRAMEWORK_REGISTRY[framework];
    if (!fwMeta) return res.status(400).json({ error: `Unknown framework: ${framework}` });

    const groupField = fwMeta.groupField;
    const groups = fwMeta.groups;

    console.log(`\n🔬 Compliance analysis: ${ownedProject.name} → ${fwMeta.label}`);

    // 1. Open findings from all tools (or SonarQube issues if nothing is stored yet)
    let issues = [];
    let sources = { source: "none", tools: [] };
    try {
      const loaded = await loadProjectIssues(ownedProject);
      issues = loaded.issues;
      sources = { source: loaded.source, tools: loaded.tools };
      console.log(`   📋 ${issues.length} open issues from ${loaded.tools.join(", ") || "no tools"}`);
    } catch (err) {
      const status = err.response?.status;
      const errMsg = (err.response?.data?.errors?.[0]?.msg || err.message || "").toLowerCase();
      if (status === 404 || errMsg.includes("not found") || errMsg.includes("component")) {
        return res.status(422).json({
          error: `No scan results found for "${ownedProject.name}". Run the Pipeline (or any scan on Security Scans) first.`,
          notYetScanned: true, projectKey,
        });
      }
      return res.status(502).json({ error: `Could not load scan results: ${err.message}` });
    }

    let mappedItems = [];
    let ragOk = false;
    let usedRag = false;

    if (sources.source === "all-tools") {
      // Every finding was already mapped to all 6 frameworks by the pipeline
      // (RAG service or built-in retriever + rule mapping); code-quality items use the rule mapping.
      const fallback = mapIssuesToGRC(issues.filter(i => !i.mappings));
      const fbByKey = new Map(fallback.map(m => [m.issue.key, m.grc_mapping]));
      mappedItems = issues.map(issue => {
        const grc = grcFromMappings(issue.mappings) || fbByKey.get(issue.key);
        return { issue, grc_mapping: grc, nist_controls: (grc?.nist_csf || []).map(id => ({ control_id: id, confidence: 0.8 })) };
      });
      console.log(`   📊 Used stored mappings for ${mappedItems.length} findings`);
    } else if (issues.length > 0) {
      // 2a. Check if RAG service is online
      try {
        const ragRes = await fetch(`${RAG_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        ragOk = ragRes.ok;
      } catch { /* RAG offline */ }

      if (ragOk) {
        try {
          // For NIST CSF, use existing /map-issues endpoint (backward compat)
          // For other frameworks, map each issue individually via /map/{framework}
          if (framework === "nist_csf") {
            const ragBody = JSON.stringify({ issues, top_k: 3 });
            const ragRes = await fetch(`${RAG_BASE}/map-issues`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: ragBody,
              signal: AbortSignal.timeout(60000),
            });
            if (ragRes.ok) {
              const ragData = await ragRes.json();
              mappedItems = ragData.mapped || [];
              usedRag = true;
              console.log(`   ✅ RAG mapped ${mappedItems.length} issues (NIST CSF)`);
            }
          } else {
            // Map issues to the specific framework via /map/{framework}
            const findings = issues.map(issue =>
              [`[${issue.severity || ""}]`, `[${issue.type || ""}]`, issue.message || "",
               issue.rule ? `(Rule: ${issue.rule})` : "",
               issue.component ? `File: ${issue.component}` : ""].filter(Boolean).join(" ")
            );

            const batchResults = [];
            // Process in batches of 20 for performance
            for (let i = 0; i < findings.length; i += 20) {
              const batch = findings.slice(i, i + 20);
              const batchPromises = batch.map(async (finding, idx) => {
                try {
                  const ragRes = await fetch(`${RAG_BASE}/map/${framework}`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ finding, top_k: 3 }),
                    signal: AbortSignal.timeout(30000),
                  });
                  if (ragRes.ok) {
                    const data = await ragRes.json();
                    return {
                      issue: issues[i + idx],
                      finding_text: finding,
                      controls: data.controls || [],
                    };
                  }
                } catch { /* skip failed */ }
                return null;
              });
              const results = await Promise.all(batchPromises);
              batchResults.push(...results.filter(Boolean));
            }

            mappedItems = batchResults;
            usedRag = batchResults.length > 0;
            console.log(`   ✅ RAG mapped ${mappedItems.length} issues (${fwMeta.label})`);
          }
        } catch (err) { console.warn("⚠ RAG map failed:", err.message); }
      }

      // 2b. Fallback: local GRC mapping
      if (mappedItems.length === 0) {
        console.log("   ↩ Using local GRC mapping fallback (rule-based)");
        mappedItems = mapIssuesToGRC(issues);
        console.log(`   📊 Local mapping: ${mappedItems.length} items`);
      }
    }

    // 2c. Run Policy-as-Code Config Scanning (only for NIST CSF, as policies map to NIST controls)
    if (framework === "nist_csf") {
      try {
        const { violations } = ownedProject.local_path ? scanProject(ownedProject.local_path) : { violations: [] };
        if (violations && violations.length > 0) {
          console.log(`   🛠️ Policy Engine: Found ${violations.length} config/infra violations`);
          for (const v of violations) {
            mappedItems.push({
              finding_text: v.message,
              nist_controls: v.nistControls,
              issue: {
                severity: v.severity.toUpperCase(),
                type: "CONFIG",
                message: `[${v.policyId}] ${v.message}`,
                component: v.file,
                rule: v.policyId
              }
            });
          }
        }
      } catch (err) { console.warn("⚠ Policy scanning failed:", err.message); }
    }

    // 3. Build outputs
    let failedControls;

    if (usedRag && framework !== "nist_csf") {
      // RAG gave us per-framework controls
      failedControls = buildFailedControlsFromRAG(mappedItems, framework, groupField);
    } else if (framework === "nist_csf") {
      // NIST CSF — use existing logic
      failedControls = buildFailedControlsNIST(mappedItems);
    } else {
      // Local fallback for non-NIST frameworks
      // Map framework slug to grcMappingService keys
      const fwKeyMap = {
        iso27001: "iso_27001",
        cis_controls: "cis_controls",
        iso27034: "iso27034",
        nist_sp800: "nist_sp800",
        owasp_asvs: "owasp_asvs",
      };
      failedControls = buildFailedControlsLocal(mappedItems, fwKeyMap[framework] || framework, framework, groupField);
      // Add groupField to each control
      for (const ctrl of failedControls) {
        if (!ctrl[groupField]) {
          ctrl[groupField] = "General";
          ctrl.function = "General";
        }
      }
    }

    let overall = { score: 100, grade: 'A', status: 'PASS' };
    let breakdown = [];

    // Try RAG scoring first
    if (ragOk) {
      try {
        const scoreEndpoint = framework === "nist_csf"
          ? `${RAG_BASE}/score`
          : `${RAG_BASE}/score/${framework}`;
        const scoreRes = await fetch(scoreEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ total_issues: issues.length, failed_controls: failedControls }),
          signal: AbortSignal.timeout(10000),
        });
        if (scoreRes.ok) {
          const scoreData = await scoreRes.json();
          overall = scoreData.overall;
          breakdown = scoreData.breakdown;
          console.log(`   🧠 RAG Scoring: ${fwMeta.label} overall score ${overall.score}`);
        } else {
          throw new Error("RAG /score returned " + scoreRes.status);
        }
      } catch (e) {
        console.warn("   ⚠ RAG Scoring failed, falling back to local:", e.message);
        overall = calcOverallScore(failedControls, issues.length);
        breakdown = buildFunctionBreakdown(failedControls, groupField, groups);
      }
    } else {
      overall = calcOverallScore(failedControls, issues.length);
      breakdown = buildFunctionBreakdown(failedControls, groupField, groups);
    }

    // 4. Persist to DB (only for NIST CSF for backward compat)
    if (projectId && framework === "nist_csf") {
      try {
        db.prepare(`
          INSERT INTO compliance_scores
            (project_id, overall_score, nist_protect, nist_detect, total_issues, blockers, criticals)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          projectId,
          overall.score,
          breakdown.find(f => f.function === "PROTECT")?.score ?? 100,
          breakdown.find(f => f.function === "DETECT")?.score ?? 100,
          issues.length,
          issues.filter(i => i.severity === "BLOCKER").length,
          issues.filter(i => i.severity === "CRITICAL").length,
        );
      } catch (dbErr) { console.warn("⚠ DB insert skipped:", dbErr.message); }
    }

    res.json({
      projectKey: ownedProject.sonar_key || ownedProject.name,
      projectName: projectName || ownedProject.name,
      framework,
      frameworkLabel: fwMeta.label,
      groupField,
      groups,
      overall,
      breakdown,
      failedControls,
      totalIssues: issues.length,
      mappedCount: mappedItems.length,
      ...sources,
      generatedAt: new Date().toISOString(),
    });

  } catch (err) {
    console.error("❌ Compliance analyze error:", err.message);
    res.status(500).json({ error: err.message || "Compliance analysis failed" });
  }
});

// ── GET /api/compliance/projects ───────────────────────────────────
router.get("/projects", (req, res) => {
  res.json(analysableProjects(req.user.userId));
});

export default router;
