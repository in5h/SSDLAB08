import { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import FixPlan from '../components/FixPlan';

const RISK_BG = { Critical: '#f4cccc', High: '#fce5cd', Medium: '#fff2cc', Low: '#d9ead3', Info: '#ededed' };
const sec = { background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 12, padding: '20px 24px', marginBottom: 18, breakInside: 'avoid-page' };
const h2 = { margin: '0 0 12px', fontFamily: "'Playfair Display', serif", fontSize: 20 };
const h3 = { margin: '16px 0 6px', fontSize: 14 };
const pre = { margin: 0, fontFamily: 'Consolas, monospace', fontSize: 11.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: '#f6f4f0', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 10px' };
const td = { border: '1px solid #ddd', padding: '5px 8px', fontSize: 12, verticalAlign: 'top' };
const th = { ...td, background: '#3b3b3b', color: '#fff', textAlign: 'left' };

function T({ head, rows, riskCol = -1 }) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 8 }}>
      <thead><tr>{head.map(h => <th key={h} style={th}>{h}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => (
        <tr key={i}>{r.map((c, j) => <td key={j} style={{ ...td, background: j === riskCol ? RISK_BG[c] : undefined }}>{c ?? '—'}</td>)}</tr>
      ))}</tbody>
    </table>
  );
}
T.propTypes = { head: PropTypes.array.isRequired, rows: PropTypes.array.isRequired, riskCol: PropTypes.number };

// One finding as a card: the header row is always visible, details expand on click.
function FindingCard({ f, open, onToggle, full = false, verified = false }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 10, marginTop: 10, breakInside: 'avoid-page', overflow: 'hidden' }}>
      <div onClick={onToggle} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', padding: '10px 14px', cursor: 'pointer', background: open ? 'rgba(139,111,71,0.06)' : 'transparent' }}>
        <span className="no-print" style={{ color: 'var(--muted)', width: 12 }}>{open ? '▾' : '▸'}</span>
        <strong style={{ fontSize: 14, flex: 1, minWidth: 220 }}>{f.ref} · {f.title}</strong>
        <span className="badge" style={{ background: RISK_BG[f.risk], color: '#222' }}>{f.risk} {f.riskScore}</span>
        <span className="badge badge-neutral">{f.tool}</span>
        <span className="badge badge-neutral">{f.status}</span>
        <span style={{ fontSize: 11, color: 'var(--muted)', width: '100%', paddingLeft: 20 }}>{f.location}</span>
      </div>
      {open && (
        <div style={{ padding: '4px 16px 14px', borderTop: '1px solid var(--border)' }}>
          <div style={{ fontSize: 12.5, lineHeight: 1.6, marginTop: 8 }}>
            <div><strong>Tool:</strong> {f.tool}{f.corroboratedBy?.length ? ` (also ${f.corroboratedBy.join(', ')})` : ''} · <strong>Rule:</strong> {f.rule}{f.ruleName ? ` — ${f.ruleName}` : ''}{f.cwe ? <> · <strong>CWE:</strong> {f.cwe} {f.cweName}</> : null}</div>
            <div><strong>Severity:</strong> {f.severity} · <strong>Confidence:</strong> {f.confidence} · <strong>Owner:</strong> {f.owner} · <strong>Due:</strong> {f.dueDate || '—'}{f.overdue ? ' (overdue)' : ''}</div>
            {f.package && <div><strong>Package:</strong> {f.package.name} {f.package.installed} → fixed in {f.package.fixed || 'n/a'}</div>}
            <div style={{ marginTop: 6, fontSize: 13.5 }}>{f.message}</div>
            {f.description && <div style={{ marginTop: 6, whiteSpace: 'pre-wrap', color: 'var(--muted)' }}>{f.description}</div>}
            {full && <div style={{ marginTop: 6 }}><strong>Business impact:</strong> {f.businessImpact}</div>}
            {f.note && <div style={{ marginTop: 6 }}><strong>Analyst note:</strong> {f.note}</div>}
            {verified && <div style={{ marginTop: 6, color: 'var(--success)' }}><strong>✔ Verified fixed:</strong> not reported again in run #{f.fixedRun} ({f.fixedAt})</div>}
          </div>
          {f.evidence && <><div style={h3}>{verified ? 'Evidence (when it was found)' : 'Evidence'}</div><pre style={pre}>{f.evidence}</pre></>}
          {full && <>
            <div style={h3}>Framework mappings</div>
            <T head={['Framework', 'Controls']} rows={[
              ...Object.values(f.mappings?.frameworks || {}).map(m => [m.label, m.controls.map(c => `${c.id} ${c.title}`).join('; ')]),
              ...(f.mappings?.owaspTop10?.length ? [['OWASP Top 10', f.mappings.owaspTop10.map(o => `${o.id} ${o.name}`).join('; ')]] : []),
              ...(f.mappings?.mitre?.length ? [['MITRE ATT&CK', f.mappings.mitre.map(o => `${o.id} ${o.name}`).join('; ')]] : []),
            ]} />
            <div style={h3}>Recommendation (RAG)</div>
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>{f.recommendation}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Source: {f.recommendationSource}</div>
          </>}
          <FixPlan plan={f.fixPlan} title={verified ? 'How it was fixed' : 'Recommended fix'} verified={verified} />
          {f.references?.length > 0 && <div style={{ fontSize: 12, marginTop: 8 }}><strong>References:</strong> {f.references.map(u => <div key={u}><a href={u} target="_blank" rel="noreferrer">{u}</a></div>)}</div>}
        </div>
      )}
    </div>
  );
}
FindingCard.propTypes = { f: PropTypes.object.isRequired, open: PropTypes.bool, onToggle: PropTypes.func.isRequired, full: PropTypes.bool, verified: PropTypes.bool };

// A report section listing finding cards with its own Expand all / Collapse all
function FindingSection({ title, intro, items, openSet, setOpenSet, full, verified, empty }) {
  const allOpen = items.length > 0 && items.every(f => openSet.has(f.ref));
  const toggle = ref => setOpenSet(s => { const n = new Set(s); if (n.has(ref)) n.delete(ref); else n.add(ref); return n; });
  const setAll = on => setOpenSet(s => { const n = new Set(s); for (const f of items) { if (on) n.add(f.ref); else n.delete(f.ref); } return n; });
  return (
    <div style={sec}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h2 style={{ ...h2, margin: 0 }}>{title} ({items.length})</h2>
        {items.length > 0 && <button className="btn btn-ghost no-print" style={{ fontSize: 12 }} onClick={() => setAll(!allOpen)}>{allOpen ? 'Collapse all' : 'Expand all'}</button>}
      </div>
      {intro && <p style={{ fontSize: 12.5, color: 'var(--muted)', margin: '6px 0 0' }}>{intro}</p>}
      {!items.length && <p style={{ fontSize: 13, color: 'var(--muted)' }}>{empty}</p>}
      {items.map(f => <FindingCard key={f.ref} f={f} open={openSet.has(f.ref)} onToggle={() => toggle(f.ref)} full={full} verified={verified} />)}
    </div>
  );
}
FindingSection.propTypes = { title: PropTypes.string.isRequired, intro: PropTypes.string, items: PropTypes.array.isRequired, openSet: PropTypes.object.isRequired, setOpenSet: PropTypes.func.isRequired, full: PropTypes.bool, verified: PropTypes.bool, empty: PropTypes.string };


export default function FinalReportPage() {
  const [projects, setProjects] = useState([]);
  const [selId, setSelId] = useState('');
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [openSet, setOpenSet] = useState(() => new Set());
  const [printing, setPrinting] = useState(false);

  // Printing / saving as PDF shows every finding expanded
  useEffect(() => {
    const before = () => setPrinting(true);
    const after = () => setPrinting(false);
    window.addEventListener('beforeprint', before);
    window.addEventListener('afterprint', after);
    return () => { window.removeEventListener('beforeprint', before); window.removeEventListener('afterprint', after); };
  }, []);

  useEffect(() => {
    apiFetch('/api/projects').then(r => r.json()).then(d => {
      if (Array.isArray(d)) { setProjects(d); setSelId(s => s || (d[0] ? String(d[0].id) : '')); }
    });
  }, []);

  async function generate() {
    setLoading(true); setError(''); setReport(null);
    try {
      const r = await apiFetch(`/api/report/${selId}`);
      const d = await r.json();
      if (!r.ok) throw new Error(d.error);
      setReport(d);
      setOpenSet(new Set());
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }

  async function downloadWord() {
    const r = await apiFetch(`/api/report/${selId}/docx`);
    if (!r.ok) { setError('Word export failed'); return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'security_report.docx';
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const r = report;
  // While printing every card is open
  const shownOpen = printing ? new Set(r ? [...r.findings, ...r.codeQuality, ...r.awaitingVerification, ...r.fixedFindings, ...r.suppressedFindings].map(f => f.ref) : []) : openSet;
  return (
    <Layout title="Final Report">
      <style>{`@media print {
        .sidebar, .topbar, .no-print { display: none !important; }
        .app-shell, .main-area, .content-area { height: auto !important; overflow: visible !important; padding: 0 !important; }
        body { background: #fff; }
      }`}</style>
      <div className="card no-print" style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: 18 }}>
        <div className="field" style={{ flex: 1, minWidth: 260, margin: 0 }}>
          <label>Project</label>
          <select className="input" value={selId} onChange={e => { setSelId(e.target.value); setReport(null); }}>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
        <button className="btn btn-primary" onClick={generate} disabled={!selId || loading}>{loading ? <><span className="spinner" /> Building report…</> : '📘 Generate report'}</button>
        <button className="btn btn-secondary" onClick={() => setOpenSet(new Set(r ? [...r.findings, ...r.codeQuality, ...r.awaitingVerification, ...r.fixedFindings, ...r.suppressedFindings].map(f => f.ref) : []))} disabled={!r}>Expand all findings</button>
        <button className="btn btn-secondary" onClick={() => setOpenSet(new Set())} disabled={!r}>Collapse all</button>
        <button className="btn btn-secondary" onClick={() => window.print()} disabled={!r}>🖨 Print / PDF</button>
        <button className="btn btn-secondary" onClick={downloadWord} disabled={!r}>📄 Download Word</button>
      </div>
      {error && <div className="auth-error">⚠ {error}</div>}
      {!r && !loading && <div className="card" style={{ color: 'var(--muted)' }}>Run the <a href="/pipeline">Pipeline</a> for the project, then click Generate report. The report combines all tools, not only SonarQube.</div>}

      {r && <>
        <div style={{ ...sec, background: 'linear-gradient(135deg,#0f1f3d,#1e3a6b)', color: '#fff' }}>
          <div style={{ fontSize: 11, letterSpacing: '.2em', opacity: .7 }}>PARABELLUM IO — SECURITY &amp; COMPLIANCE REPORT</div>
          <div style={{ fontSize: 28, fontFamily: "'Playfair Display', serif", margin: '6px 0' }}>{r.asset.assetName}</div>
          <div style={{ fontSize: 13, opacity: .85 }}>{r.meta.reportId} · {new Date(r.meta.generatedAt).toLocaleString()} · prepared by {r.meta.generatedBy}</div>
          <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
            <span className="badge" style={{ background: r.executive.gate === 'PASS' ? '#2e7d32' : '#c62828', color: '#fff' }}>Gate {r.executive.gate}</span>
            {['Critical', 'High', 'Medium', 'Low'].map(k => <span key={k} className="badge" style={{ background: RISK_BG[k], color: '#222' }}>{r.executive.byRisk[k]} {k}</span>)}
            <span className="badge" style={{ background: '#d9ead3', color: '#222' }}>{r.executive.verifiedFixed} verified fixed</span>
          </div>
        </div>

        <div style={sec}>
          <h2 style={h2}>1. Executive summary</h2>
          <p style={{ fontSize: 14, lineHeight: 1.6 }}>
            <strong>{r.asset.assetName}</strong> ({r.asset.assetType}, {r.asset.environment}, {r.asset.internetFacing ? 'internet-facing' : 'internal'}) has
            <strong> {r.executive.openSecurityFindings} open security findings</strong> from {r.executive.toolsUsed.join(', ') || 'no tools yet'}.
            {' '}{r.executive.verifiedFixed} findings were fixed and verified by a rescan, {r.executive.overdue} are overdue,
            {' '}{r.executive.falsePositives} were triaged as false positives and {r.executive.codeQualityIssues} code-quality issues are listed separately.
          </p>
          <h3 style={h3}>Top risks</h3>
          <T head={['Ref', 'Finding', 'Risk', 'Location', 'Owner', 'Due']} rows={r.executive.topRisks.map(x => [x.ref, x.title, x.risk, x.location, x.owner, x.due])} riskCol={2} />
          <h3 style={h3}>Compliance impact</h3>
          <T head={['Framework', 'Controls affected']} rows={r.executive.frameworksAffected.map(f => [f.label, f.controlsAffected])} />
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>Recommendations: {r.meta.recommendationEngine}</div>
        </div>

        <div style={sec}>
          <h2 style={h2}>2. Asset and business context</h2>
          <T head={['Attribute', 'Value']} rows={[
            ['Asset', r.asset.assetName], ['Type', r.asset.assetType], ['Environment', r.asset.environment],
            ['Data classification', r.asset.dataClassification], ['Business criticality', r.asset.businessCriticality],
            ['Internet-facing', r.asset.internetFacing ? 'Yes' : 'No'], ['Business / risk owner', r.asset.businessOwner],
            ['Running app URL', r.asset.targetUrl || '—'], ['Description', r.asset.description || '—'],
          ]} />
          <div style={{ fontSize: 12, color: 'var(--muted)' }}>{r.methodology.riskFormula}</div>
        </div>

        <div style={sec}>
          <h2 style={h2}>3. Pipeline, coverage and accuracy</h2>
          {r.fixVerification.latestRun && <T head={['Stage', 'Status', 'Engine', 'Findings', 'New', 'Fixed', 'Note']}
            rows={r.fixVerification.latestRun.stages.map(s => [s.name, s.status, s.engine || '—', s.findings ?? '—', s.counts?.new ?? '—', s.counts?.fixed ?? '—', s.message || s.warning || ''])} />}
          <h3 style={h3}>True positives vs false positives</h3>
          <p style={{ fontSize: 12, color: 'var(--muted)' }}>{r.methodology.confidenceModel}</p>
          <T head={['Measure', 'Count']} rows={[
            ['High confidence (likely true positive)', r.accuracy.confidence.High],
            ['Medium confidence', r.accuracy.confidence.Medium],
            ['Low confidence (review first — likely false positive)', r.accuracy.confidence.Low],
            ['Confirmed by more than one tool', r.accuracy.corroborated],
            ['Cross-tool duplicates merged (counted once)', r.accuracy.mergedDuplicates?.length || 0],
            ['Triaged as False Positive (suppressed in rescans)', r.accuracy.triagedFalsePositives.length],
          ]} />
          {r.accuracy.mergedDuplicates?.length > 0 && <>
            <h3 style={h3}>Duplicates merged across tools</h3>
            <T head={['Ref', 'Finding', 'Tool', 'Location', 'Merged into']} rows={r.accuracy.mergedDuplicates.map(x => [x.ref, x.title, x.tool, x.location, x.mergedInto || '—'])} />
          </>}
          <h3 style={h3}>False negatives — coverage by weakness type</h3>
          <T head={['Weakness type', 'Findings', 'Found by', 'Expected tools', 'Gap']}
            rows={r.accuracy.coverage.map(c => [c.category, c.findings, Object.entries(c.byTool).map(([k, v]) => `${k}: ${v}`).join(', ') || '—', c.expectedTools.join(', '), c.gap || '✓ covered'])} />
        </div>

        <FindingSection title="4. Detailed security findings" items={r.findings} openSet={shownOpen} setOpenSet={setOpenSet} full
          intro="Open security findings from all tools, highest risk first. Click a finding for evidence, mappings, the RAG recommendation and the step-by-step fix."
          empty="No open security findings." />

        <FindingSection title="5. Code-quality issues" items={r.codeQuality} openSet={shownOpen} setOpenSet={setOpenSet}
          intro="Bugs and maintainability issues that are not security weaknesses, with the tool's explanation and a recommended fix."
          empty="No open code-quality issues." />

        <div style={sec}>
          <h2 style={h2}>6. Compliance mapping by framework</h2>
          {r.compliance.map(c => (
            <div key={c.key}>
              <h3 style={h3}>{c.label} — {c.controlsAffected} controls affected</h3>
              {c.controls.length > 0 && <T head={['Control', 'Title', 'Group', 'Worst risk', 'Findings']} rows={c.controls.map(x => [x.id, x.title, x.group || '—', x.worst, x.findings.join(', ')])} riskCol={3} />}
            </div>
          ))}
          {r.owaspTop10.length > 0 && <>
            <h3 style={h3}>OWASP Top 10 (2021)</h3>
            <T head={['Category', 'Findings']} rows={r.owaspTop10.map(o => [`${o.id} ${o.name}`, o.findings.join(', ')])} />
          </>}
        </div>

        <div style={sec}>
          <h2 style={h2}>7. Remediation plan</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)' }}>{r.methodology.sla} Every open finding (security and code quality) is listed with its fix.</p>
          <T head={['Ref', 'Finding', 'Risk', 'Priority', 'Risk owner', 'Due', 'How to fix', 'Status']}
            rows={r.remediationPlan.map(x => [x.ref, x.title, x.risk, x.priority, x.owner, `${x.dueDate || '—'}${x.overdue ? ' (overdue)' : ''}`, x.fix, x.status])} riskCol={2} />
        </div>

        <div style={sec}>
          <h2 style={h2}>8. Fix verification and rescan results</h2>
          {r.fixVerification.previousRun && <p style={{ fontSize: 13 }}>Latest run #{r.fixVerification.latestRun.id} vs run #{r.fixVerification.previousRun.id}: <strong>{r.fixVerification.fixedInLatest.length} fixed</strong>, {r.fixVerification.newInLatest} new.</p>}
          <h3 style={h3}>Run history</h3>
          <T head={['Run', 'Type', 'Status', 'Started', 'New', 'Fixed', 'Open', 'Gate']}
            rows={r.fixVerification.runs.map(x => [`#${x.id}`, x.trigger, x.status, x.startedAt, x.summary?.new ?? '—', x.summary?.fixed ?? '—', x.summary?.open ?? '—', x.summary?.gate || '—'])} />
        </div>
        {r.awaitingVerification.length > 0 && <FindingSection title="8a. Marked fixed — waiting for the next rescan" items={r.awaitingVerification} openSet={shownOpen} setOpenSet={setOpenSet}
          intro="Someone marked these as fixed. Re-run the pipeline: they become Verified Fixed if the tool no longer reports them." />}
        <FindingSection title="8b. Verified fixes" items={r.fixedFindings} openSet={shownOpen} setOpenSet={setOpenSet} verified
          intro="Findings the tools no longer report after a rescan, with the evidence from when they were found and how they were fixed."
          empty="No verified fixes yet — fix a finding and re-run the pipeline." />

        <FindingSection title="9. False positives and accepted risks" items={r.suppressedFindings} openSet={shownOpen} setOpenSet={setOpenSet}
          intro="Reviewed by an analyst and suppressed in later scans. The note explains each decision."
          empty="None." />

        <div style={sec}>
          <h2 style={h2}>Appendix — complete findings register ({r.register.length})</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)' }}>Every finding reported by every tool for this project, whatever its status, with the fix in one line.</p>
          <T head={['Ref', 'Finding', 'Category', 'Tool', 'Location', 'Risk', 'Status', 'How to fix']}
            rows={r.register.map(x => [x.ref, x.title, x.category, x.tool, x.location, x.risk, x.status, x.fix])} riskCol={5} />
        </div>
      </>}
    </Layout>
  );
}
