// src/services/riskReportService.js
// Local, LLM-free risk report generator based on mapping JSON.

function generateFallbackReport(projectName, mapping) {
  const name = projectName || "Unnamed Project";
  const items = Array.isArray(mapping.items) ? mapping.items : [];

  const total = items.length;
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

  for (const it of items) {
    const sev = (it.severity || "").toLowerCase();
    if (sev.includes("critical")) counts.Critical++;
    else if (sev.includes("high")) counts.High++;
    else if (sev.includes("medium")) counts.Medium++;
    else if (sev.includes("low")) counts.Low++;
  }

  const lines = [];

  lines.push(`1. Executive Summary`);
  lines.push(
    `The security assessment of "${name}" identified a total of ${total} mapped risk items.`
  );
  lines.push(
    `Overall, the current risk exposure is assessed as "${mapping.overall_risk_level || "Unknown"}".`
  );
  lines.push(
    `Breakdown by severity: Critical=${counts.Critical}, High=${counts.High}, Medium=${counts.Medium}, Low=${counts.Low}.`
  );
  lines.push("");

  lines.push(`2. Top Risks`);
  if (items.length === 0) {
    lines.push(`- No detailed risk items were provided in the mapping.`);
  } else {
    items.slice(0, 5).forEach((it, idx) => {
      lines.push(
        `2.${idx + 1} ${it.title || "Unnamed Risk"} [${it.severity || "N/A"}]`
      );
      if (it.description) {
        lines.push(`   • Description: ${it.description}`);
      }
      if (it.grc_mapping) {
        const gm = it.grc_mapping;
        if (gm.nist_csf && gm.nist_csf.length) {
          lines.push(`   • NIST CSF: ${gm.nist_csf.join(", ")}`);
        }
        if (gm.cis_controls && gm.cis_controls.length) {
          lines.push(`   • CIS Controls v8: ${gm.cis_controls.join(", ")}`);
        }
        if (gm.iso_27001 && gm.iso_27001.length) {
          lines.push(`   • ISO 27001: ${gm.iso_27001.join(", ")}`);
        }
      }
      lines.push("");
    });
  }

  lines.push(`3. Recommended Mitigation Plan`);
  lines.push(`   Short-term (0–2 weeks):`);
  lines.push(
    `   • Address all Critical and High-severity findings first, especially those on internet-facing endpoints and authentication flows.`
  );
  lines.push(
    `   • Implement quick configuration hardening and basic input validation where feasible.`
  );
  lines.push("");
  lines.push(`   Medium-term (2–8 weeks):`);
  lines.push(
    `   • Refactor vulnerable modules to use secure coding patterns (parameterised queries, centralised validation, secure session handling).`
  );
  lines.push(
    `   • Integrate security scans into CI/CD pipelines with clear quality gates.`
  );
  lines.push("");
  lines.push(`   Long-term (8+ weeks):`);
  lines.push(
    `   • Formalise secure SDLC practices, update development guidelines, and provide recurring security training for engineers.`
  );
  lines.push(
    `   • Continuously monitor for new vulnerabilities in dependencies, containers, and cloud configuration.`
  );
  lines.push("");

  lines.push(`4. GRC View`);
  lines.push(
    `The mapped issues primarily impact NIST CSF functions Protect (PR) and Detect (DE), covering areas such as secure configuration, vulnerability management, and continuous monitoring.`
  );
  lines.push(
    `From a CIS Controls v8 perspective, relevant practices include Control 4 (Secure Configuration), Control 7 (Vulnerability Management), and Control 16 (Application Software Security).`
  );
  lines.push(
    `In ISO 27001 terms, the findings relate to Annex A controls such as A.8.x (asset and information protection), A.12.x (operations security), and A.14.x (system acquisition, development, and maintenance).`
  );
  lines.push("");

  lines.push(`5. Suggested Next Steps for DevSecOps & Governance`);
  lines.push(
    `   • Prioritise remediation of the highest-severity items and track them formally in a risk register.`
  );
  lines.push(
    `   • Ensure CI/CD pipelines enforce security gates, using outputs from tools such as SonarQube, Snyk, and Trivy.`
  );
  lines.push(
    `   • Align remediation and monitoring activities with NIST CSF, CIS Controls v8, and ISO 27001 to demonstrate governance and compliance.`
  );
  lines.push(
    `   • Periodically review and update policies, baselines, and tool configurations as the system and threat landscape evolve.`
  );

  return lines.join("\n");
}

// For now, we only export the fallback; no LLM call.
export async function generateRiskReport(projectName, mapping) {
  return generateFallbackReport(projectName, mapping);
}
