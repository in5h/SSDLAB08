/**
 * reportDocx.js — Exports the final report (reportService.buildReport) as a Word document.
 */
import {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, LevelFormat, Footer, PageNumber,
} from "docx";

const W = 9638; // A4 content width (DXA) with ~2 cm margins
const FONT = "Calibri";
const RISK_FILL = { Critical: "F4CCCC", High: "FCE5CD", Medium: "FFF2CC", Low: "D9EAD3", Info: "EDEDED" };
const border = { style: BorderStyle.SINGLE, size: 4, color: "BFBFBF" };
const borders = { top: border, bottom: border, left: border, right: border };

const t = (text, o = {}) => new TextRun({ text: String(text ?? ""), ...o });
const P = (text, o = {}) => new Paragraph({ children: [t(text, o.run)], spacing: { after: 100 }, ...o.para });
const H1 = text => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [t(text)], pageBreakBefore: true });
const H2 = text => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [t(text)] });
const H3 = text => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [t(text)] });
const B = text => new Paragraph({ numbering: { reference: "bullets", level: 0 }, children: [t(text)], spacing: { after: 40 } });
const N = (text, ref) => new Paragraph({ numbering: { reference: ref, level: 0 }, children: [t(text)], spacing: { after: 40 } });
const KV = (k, v) => new Paragraph({ children: [t(`${k}: `, { bold: true }), t(v)], spacing: { after: 60 } });
const CODE = text => String(text || "").split("\n").map(line => new Paragraph({
  children: [t(line || " ", { font: "Consolas", size: 17 })],
  shading: { type: ShadingType.CLEAR, fill: "F2F2F2" }, spacing: { after: 0 },
}));

function table(head, rows, pct, riskCol = -1) {
  const widths = pct.map(p => Math.floor(W * p / 100));
  widths[widths.length - 1] += W - widths.reduce((a, b) => a + b, 0);
  const cell = (v, i, isHead) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA }, borders, margins: { top: 50, bottom: 50, left: 90, right: 90 },
    shading: isHead ? { type: ShadingType.CLEAR, fill: "3B3B3B" }
      : (i === riskCol && RISK_FILL[v]) ? { type: ShadingType.CLEAR, fill: RISK_FILL[v] } : undefined,
    children: [new Paragraph({ children: [t(v, isHead ? { bold: true, color: "FFFFFF", size: 18 } : { size: 18 })] })],
  });
  return new Table({
    width: { size: W, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: head.map((h, i) => cell(h, i, true)) }),
      ...rows.map(r => new TableRow({ children: r.map((v, i) => cell(v ?? "—", i, false)) }))],
  });
}
const gap = () => new Paragraph({ children: [], spacing: { after: 120 } });

export async function reportToDocx(r) {
  const C = [];
  let numRef = 0;
  const numbering = [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }];
  const newList = () => {
    const ref = `n${numRef++}`;
    numbering.push({ reference: ref, levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] });
    return ref;
  };

  // Cover
  C.push(new Paragraph({ spacing: { before: 2000 }, alignment: AlignmentType.CENTER, children: [t("Security & Compliance Report", { bold: true, size: 52 })] }));
  C.push(new Paragraph({ alignment: AlignmentType.CENTER, children: [t(r.asset.assetName, { size: 32, color: "6B4F2E" })] }));
  C.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [t(`Report ${r.meta.reportId} · ${new Date(r.meta.generatedAt).toLocaleString()} · prepared by ${r.meta.generatedBy}`, { size: 20, color: "555555" })] }));
  C.push(table(["Item", "Value"], [
    ["Security gate", r.executive.gate],
    ["Open security findings", String(r.executive.openSecurityFindings)],
    ["Critical / High / Medium / Low", `${r.executive.byRisk.Critical} / ${r.executive.byRisk.High} / ${r.executive.byRisk.Medium} / ${r.executive.byRisk.Low}`],
    ["Verified fixed", String(r.executive.verifiedFixed)],
    ["Code-quality issues", String(r.executive.codeQualityIssues)],
    ["All findings in this report", String(r.executive.totalFindings)],
    ["Tools used", r.executive.toolsUsed.join(", ") || "—"],
    ["Recommendation engine", r.meta.recommendationEngine],
  ], [35, 65]));

  // 1 Executive summary
  C.push(H1("1. Executive Summary"));
  C.push(P(`The ${r.asset.assetType || "application"} "${r.asset.assetName}" has ${r.executive.openSecurityFindings} open security findings ` +
    `(${r.executive.byRisk.Critical} Critical, ${r.executive.byRisk.High} High). The security gate result is ${r.executive.gate}. ` +
    `${r.executive.verifiedFixed} findings have been fixed and verified by a rescan; ${r.executive.overdue} are past their due date.`));
  C.push(H2("Top risks"));
  C.push(table(["Ref", "Finding", "Risk", "Location", "Owner", "Due"],
    r.executive.topRisks.map(x => [x.ref, x.title, x.risk, x.location, x.owner, x.due]), [8, 34, 10, 22, 14, 12], 2));
  C.push(H2("Compliance impact"));
  C.push(table(["Framework", "Controls affected"], r.executive.frameworksAffected.map(f => [f.label, String(f.controlsAffected)]), [60, 40]));

  // 2 Asset & business context
  C.push(H1("2. Asset and Business Context"));
  C.push(table(["Attribute", "Value"], [
    ["Asset", r.asset.assetName], ["Type", r.asset.assetType], ["Environment", r.asset.environment],
    ["Data classification", r.asset.dataClassification], ["Business criticality", r.asset.businessCriticality],
    ["Internet-facing", r.asset.internetFacing ? "Yes" : "No"], ["Business owner", r.asset.businessOwner],
    ["Target URL (DAST)", r.asset.targetUrl || "—"], ["Description", r.asset.description || "—"],
  ], [35, 65]));
  C.push(gap());
  C.push(P(r.methodology.riskFormula, { run: { italics: true, color: "555555" } }));

  // 3 Tools, coverage and accuracy
  C.push(H1("3. Scan Pipeline, Coverage and Accuracy"));
  const lr = r.fixVerification.latestRun;
  if (lr) {
    C.push(P(`Latest run #${lr.id} (${lr.trigger}) — ${lr.status}, started ${lr.startedAt}.`));
    C.push(table(["Stage", "Status", "Engine", "Findings", "New", "Fixed", "Note"],
      (lr.stages || []).map(s => [s.name, s.status, s.engine || "—", String(s.findings ?? "—"), String(s.counts?.new ?? "—"), String(s.counts?.fixed ?? "—"), (s.message || s.warning || "").slice(0, 120)]),
      [16, 10, 10, 10, 8, 8, 38]));
  }
  C.push(H2("True positives and false positives"));
  C.push(P(r.methodology.confidenceModel));
  C.push(table(["Measure", "Count"], [
    ["High confidence (likely true positive)", String(r.accuracy.confidence.High)],
    ["Medium confidence", String(r.accuracy.confidence.Medium)],
    ["Low confidence (likely false positive – review first)", String(r.accuracy.confidence.Low)],
    ["Confirmed by more than one tool", String(r.accuracy.corroborated)],
    ["Cross-tool duplicates merged (counted once)", String(r.accuracy.mergedDuplicates?.length || 0)],
    ["Marked False Positive by analysts (suppressed in rescans)", String(r.accuracy.triagedFalsePositives.length)],
  ], [75, 25]));
  if (r.accuracy.mergedDuplicates?.length) {
    C.push(H2("Duplicates merged across tools"));
    C.push(table(["Ref", "Finding", "Tool", "Location", "Merged into"], r.accuracy.mergedDuplicates.map(x => [x.ref, x.title, x.tool, x.location, x.mergedInto || "—"]), [8, 36, 14, 28, 14]));
  }
  C.push(H2("False negatives: coverage by weakness type"));
  C.push(table(["Weakness type", "Findings", "Found by", "Expected tools", "Gap"],
    r.accuracy.coverage.map(c => [c.category, String(c.findings), Object.entries(c.byTool).map(([k, v]) => `${k}: ${v}`).join(", ") || "—", c.expectedTools.join(", "), c.gap || "Covered"]),
    [22, 9, 22, 20, 27]));
  C.push(P(`Findings reported by only one tool: ${Object.entries(r.accuracy.uniqueToTool).map(([k, v]) => `${k} ${v}`).join(", ") || "none"} — running several tools reduces missed issues.`));

  // One finding, same layout everywhere. full = mappings + recommendation (open security findings)
  const textLines = text => String(text || "").split("\n").filter(l => l.trim()).map(l => P(l));
  const findingBlock = (f, { full = false, verified = false } = {}) => {
    C.push(H2(`${f.ref} · ${f.title}`));
    C.push(table(["Risk", "Severity", "Confidence", "Status", "Owner", "Due"],
      [[`${f.risk} (${f.riskScore})`, f.severity, f.confidence, f.status, f.owner, f.dueDate || "—"]], [18, 14, 16, 16, 20, 16]));
    C.push(gap());
    C.push(KV("Tool", `${f.tool}${f.corroboratedBy?.length ? ` (also found by ${f.corroboratedBy.join(", ")})` : ""} · rule ${f.rule}${f.ruleName ? ` – ${f.ruleName}` : ""}`));
    if (f.cwe) C.push(KV("Weakness", `${f.cwe} ${f.cweName || ""}`));
    C.push(KV("Location", f.location));
    if (f.package) C.push(KV("Package", `${f.package.name} ${f.package.installed} → fixed in ${f.package.fixed || "n/a"}`));
    C.push(KV("Finding", f.message));
    if (f.description) C.push(KV("Explanation", f.description.split("\n").filter(Boolean).slice(0, 4).join(" ")));
    if (full) C.push(KV("Business impact", f.businessImpact));
    if (f.note) C.push(KV("Analyst note", f.note));
    if (verified) C.push(KV("Verified fixed", `Not reported again in run #${f.fixedRun || "—"} (${f.fixedAt || "—"})`));
    if (f.evidence) { C.push(H3(verified ? "Evidence (when it was found)" : "Evidence")); C.push(...CODE(f.evidence)); }
    if (full) {
      C.push(H3("Framework mappings"));
      const rows = Object.values(f.mappings?.frameworks || {}).map(m => [m.label, m.controls.map(c => `${c.id} ${c.title}`).join("; ")]);
      if (f.mappings?.owaspTop10?.length) rows.push(["OWASP Top 10", f.mappings.owaspTop10.map(o => `${o.id} ${o.name}`).join("; ")]);
      if (f.mappings?.mitre?.length) rows.push(["MITRE ATT&CK", f.mappings.mitre.map(m => `${m.id} ${m.name}`).join("; ")]);
      if (rows.length) C.push(table(["Framework", "Controls"], rows, [22, 78]));
      C.push(H3("Recommendation (RAG)"));
      C.push(P(f.recommendation || "—"));
      C.push(P(`Source: ${f.recommendationSource || "—"}`, { run: { italics: true, size: 16, color: "777777" } }));
    }
    C.push(H3(verified ? "How it was fixed (fix plan)" : "Recommended fix"));
    if (f.fixPlan.why) C.push(P(f.fixPlan.why, { run: { italics: true, color: "555555" } }));
    const ref = newList();
    for (const st of f.fixPlan.steps) C.push(N(st, ref));
    if (f.fixPlan.toolAdvice) {
      C.push(P(`${f.fixPlan.toolAdviceSource} advice:`, { run: { bold: true } }));
      C.push(...textLines(f.fixPlan.toolAdvice.slice(0, 1200)));
    }
    if (f.fixPlan.example) C.push(...CODE(f.fixPlan.example));
    C.push(KV("Priority", `${f.fixPlan.priority} · effort ${f.fixPlan.effort} · SLA ${f.fixPlan.slaDays} days`));
    C.push(KV("Verification", f.fixPlan.verification));
    if (f.references?.length) C.push(KV("References", f.references.join("  ")));
  };

  // 4 Detailed security findings
  C.push(H1(`4. Detailed Security Findings (${r.findings.length})`));
  if (!r.findings.length) C.push(P("No open security findings."));
  for (const f of r.findings) findingBlock(f, { full: true });

  // 5 Code quality
  C.push(H1(`5. Code-Quality Issues (${r.codeQuality.length})`));
  C.push(P("Bugs and maintainability issues that are not security weaknesses. Each has the tool's explanation and a recommended fix."));
  if (!r.codeQuality.length) C.push(P("No open code-quality issues."));
  for (const f of r.codeQuality) findingBlock(f);

  // 6 Compliance mapping
  C.push(H1("6. Compliance Mapping by Framework"));
  for (const c of r.compliance) {
    C.push(H2(`${c.label} — ${c.controlsAffected} controls affected`));
    if (c.controls.length) C.push(table(["Control", "Title", "Group", "Worst risk", "Findings"],
      c.controls.map(x => [x.id, x.title, x.group || "—", x.worst, x.findings.join(", ")]), [13, 37, 20, 12, 18], 3));
  }
  if (r.owaspTop10.length) {
    C.push(H2("OWASP Top 10 (2021)"));
    C.push(table(["Category", "Findings"], r.owaspTop10.map(o => [`${o.id} ${o.name}`, o.findings.join(", ")]), [50, 50]));
  }

  // 7 Remediation plan
  C.push(H1("7. Remediation Plan"));
  C.push(P(r.methodology.sla));
  C.push(table(["Ref", "Finding", "Risk", "Priority", "Owner", "Due", "How to fix", "Status"],
    r.remediationPlan.map(x => [x.ref, x.title, x.risk, x.priority, x.owner, `${x.dueDate || "—"}${x.overdue ? " (overdue)" : ""}`, x.fix, x.status]),
    [7, 20, 8, 11, 11, 10, 25, 8], 2));

  // 8 Fix verification
  C.push(H1("8. Fix Verification and Rescan Results"));
  const fv = r.fixVerification;
  if (fv.previousRun) C.push(P(`Latest run #${fv.latestRun.id} compared with run #${fv.previousRun.id}: ${fv.fixedInLatest.length} fixed, ${fv.newInLatest} new.`));
  C.push(H2("Run history"));
  C.push(table(["Run", "Type", "Status", "Started", "New", "Fixed", "Open", "Gate"],
    fv.runs.map(x => [`#${x.id}`, x.trigger, x.status, x.startedAt, String(x.summary?.new ?? "—"), String(x.summary?.fixed ?? "—"), String(x.summary?.open ?? "—"), x.summary?.gate || "—"]),
    [8, 11, 13, 24, 9, 9, 9, 17]));
  if (r.awaitingVerification.length) {
    C.push(H2(`Marked fixed – waiting for the next rescan (${r.awaitingVerification.length})`));
    for (const f of r.awaitingVerification) findingBlock(f);
  }
  C.push(H2(`Verified fixes (${r.fixedFindings.length})`));
  if (!r.fixedFindings.length) C.push(P("No verified fixes yet — fix a finding and re-run the pipeline."));
  for (const f of r.fixedFindings) findingBlock(f, { verified: true });

  // 9 False positives & accepted risks
  C.push(H1(`9. False Positives and Accepted Risks (${r.suppressedFindings.length})`));
  C.push(P("Findings an analyst reviewed and suppressed. They stay suppressed in later scans; the note explains the decision."));
  if (!r.suppressedFindings.length) C.push(P("None."));
  for (const f of r.suppressedFindings) findingBlock(f);

  // Appendix – complete register
  C.push(H1(`Appendix – Complete Findings Register (${r.register.length})`));
  C.push(P("Every finding reported by every tool for this project, with its status and the fix in one line."));
  C.push(table(["Ref", "Finding", "Category", "Tool", "Location", "Risk", "Status", "How to fix"],
    r.register.map(x => [x.ref, x.title, x.category, x.tool, x.location, x.risk, x.status, x.fix]),
    [6, 18, 9, 9, 16, 7, 10, 25], 5));

  const doc = new Document({
    creator: "Parabellum IO", title: `Security & Compliance Report – ${r.asset.assetName}`,
    styles: {
      default: { document: { run: { font: FONT, size: 20 } } },
      paragraphStyles: [
        { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 32, bold: true, font: FONT, color: "6B4F2E" }, paragraph: { spacing: { before: 200, after: 160 }, outlineLevel: 0 } },
        { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 25, bold: true, font: FONT }, paragraph: { spacing: { before: 240, after: 100 }, outlineLevel: 1, keepNext: true } },
        { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 21, bold: true, font: FONT, color: "444444" }, paragraph: { spacing: { before: 140, after: 60 }, outlineLevel: 2, keepNext: true } },
      ],
    },
    numbering: { config: numbering },
    sections: [{
      properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t("Page ", { size: 16, color: "888888" }), new TextRun({ children: [PageNumber.CURRENT], size: 16, color: "888888" })] })] }) },
      children: C,
    }],
  });
  return Packer.toBuffer(doc);
}

