import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

const API = '/api/risk';

// ── Colour helpers ───────────────────────────────────────────────────────────
const SEV = {
  Critical: { bg:'#fef2f2', border:'#fca5a5', text:'#991b1b', pill:'#dc2626' },
  High:     { bg:'#fff7ed', border:'#fdba74', text:'#9a3412', pill:'#ea580c' },
  Medium:   { bg:'#fefce8', border:'#fde047', text:'#854d0e', pill:'#ca8a04' },
  Low:      { bg:'#f0fdf4', border:'#86efac', text:'#166534', pill:'#16a34a' },
};
function cvssColor(s) {
  if (s >= 9) return '#dc2626';
  if (s >= 7) return '#ea580c';
  if (s >= 4) return '#ca8a04';
  return '#16a34a';
}

const ATTACK_ICONS = {
  'Remote Code Execution':     { icon:'💥', color:'#dc2626' },
  'Data Leakage':              { icon:'📤', color:'#ea580c' },
  'Authentication Bypass':     { icon:'🔓', color:'#dc2626' },
  'Data Manipulation':         { icon:'✏️',  color:'#ea580c' },
  'Session Hijacking':         { icon:'🎭', color:'#dc2626' },
  'Credential Theft':          { icon:'🔑', color:'#dc2626' },
  'Phishing':                  { icon:'🎣', color:'#ea580c' },
  'Malware Distribution':      { icon:'☣️',  color:'#dc2626' },
  'Denial of Service':         { icon:'🚫', color:'#ea580c' },
  'Application Crash':         { icon:'💣', color:'#ca8a04' },
  'Privilege Escalation':      { icon:'⬆️',  color:'#dc2626' },
  'Arbitrary File Read':       { icon:'📂', color:'#ea580c' },
  'Arbitrary File Write':      { icon:'📝', color:'#dc2626' },
  'Man-in-the-Middle':         { icon:'🕵️',  color:'#ea580c' },
  'Memory Corruption':         { icon:'🧠', color:'#dc2626' },
  'Information Disclosure':    { icon:'👁️',  color:'#ca8a04' },
  'Unauthorized Access':       { icon:'🚪', color:'#dc2626' },
  'Forgery':                   { icon:'🖊️',  color:'#ea580c' },
  'Server-Side Request Forgery':{ icon:'🌐', color:'#dc2626' },
  'Internal Network Access':   { icon:'🏠', color:'#dc2626' },
  'Predictable Token Forgery': { icon:'🎲', color:'#ea580c' },
  'Data Corruption':           { icon:'💾', color:'#ea580c' },
  'Resource Exhaustion':       { icon:'⚡', color:'#ca8a04' },
  'Reconnaissance':            { icon:'🔭', color:'#ca8a04' },
};

function SevPill({ sev }) {
  const c = SEV[sev] || SEV.Medium;
  return (
    <span style={{ background:c.pill, color:'#fff', borderRadius:4,
      padding:'2px 8px', fontSize:11, fontWeight:700 }}>{sev}</span>
  );
}
SevPill.propTypes = { sev: PropTypes.string.isRequired };

function CvssTag({ score }) {
  return (
    <span style={{ background: cvssColor(score), color:'#fff',
      borderRadius:4, padding:'2px 8px', fontSize:12, fontWeight:800,
      fontFamily:'monospace', letterSpacing:.5 }}>{score?.toFixed(1)}</span>
  );
}
CvssTag.propTypes = { score: PropTypes.number.isRequired };

function AttackChip({ label }) {
  const meta = ATTACK_ICONS[label] || { icon:'⚠️', color:'#6b7280' };
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:4,
      background: meta.color + '18', color: meta.color,
      border: `1px solid ${meta.color}40`,
      borderRadius:20, padding:'3px 10px', fontSize:11, fontWeight:700,
      whiteSpace:'nowrap' }}>
      {meta.icon} {label}
    </span>
  );
}
AttackChip.propTypes = { label: PropTypes.string.isRequired };

// ── Summary cards ────────────────────────────────────────────────────────────
function SummaryCards({ s }) {
  const cards = [
    { label:'Critical CWEs', v:s.critical_cwes, c:'#dc2626', icon:'🔴' },
    { label:'High CWEs',     v:s.high_cwes,     c:'#ea580c', icon:'🟠' },
    { label:'Medium CWEs',   v:s.medium_cwes,   c:'#ca8a04', icon:'🟡' },
    { label:'Low CWEs',      v:s.low_cwes,      c:'#16a34a', icon:'🟢' },
  ];
  return (
    <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:14, marginBottom:22 }}>
      {cards.map(c => (
        <div key={c.label} style={{ background:'#fff', border:'1px solid #e5e7eb',
          borderLeft:`4px solid ${c.c}`, borderRadius:8, padding:'14px 18px' }}>
          <div style={{ fontSize:30, fontWeight:800, color:c.c }}>{c.v}</div>
          <div style={{ fontSize:12, color:'#6b7280', marginTop:2 }}>{c.icon} {c.label}</div>
        </div>
      ))}
    </div>
  );
}
SummaryCards.propTypes = {
  s: PropTypes.shape({
    critical_cwes: PropTypes.number,
    high_cwes: PropTypes.number,
    medium_cwes: PropTypes.number,
    low_cwes: PropTypes.number,
  }).isRequired,
};

// ── Attack panel shown in expanded row ───────────────────────────────────────
// ── Gemini remediation advice for one CWE ───────────────────────────────────
function AiAdvice({ finding }) {
  const [state, setState] = useState({ loading: false, advice: '', error: '' });

  async function ask() {
    setState({ loading: true, advice: '', error: '' });
    try {
      const r = await apiFetch(`${API}/ai-advice`, {
        method: 'POST',
        body: JSON.stringify({
          cweId: finding.cwe_id, name: finding.cwe_name, severity: finding.severity,
          cvss: finding.cvss_score, examples: (finding.issues || []).slice(0, 5),
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'AI advice failed');
      setState({ loading: false, advice: data.advice, error: '' });
    } catch (err) {
      setState({ loading: false, advice: '', error: err.message });
    }
  }

  return (
    <div style={{ marginTop:16, background:'#fff', borderRadius:8, padding:'14px 16px', border:'1px solid #c7d2fe' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:12 }}>
        <div style={{ fontWeight:700, fontSize:12, color:'#3730a3', textTransform:'uppercase', letterSpacing:.5 }}>
          🤖 AI Fix Advice (Gemini)
        </div>
        <button onClick={e => { e.stopPropagation(); ask(); }} disabled={state.loading}
          style={{ background:'#4f46e5', color:'#fff', border:'none', borderRadius:6, padding:'6px 14px',
            fontSize:12, fontWeight:700, cursor: state.loading ? 'wait' : 'pointer' }}>
          {state.loading ? 'Asking Gemini…' : state.advice ? 'Ask again' : 'Get AI fix advice'}
        </button>
      </div>
      {state.error && <div style={{ marginTop:10, fontSize:12, color:'#dc2626' }}>❌ {state.error}</div>}
      {state.advice && (
        <div style={{ marginTop:10, fontSize:13, color:'#374151', whiteSpace:'pre-wrap', lineHeight:1.6 }}>
          {state.advice}
        </div>
      )}
    </div>
  );
}
AiAdvice.propTypes = {
  finding: PropTypes.shape({
    cwe_id: PropTypes.string,
    cwe_name: PropTypes.string,
    severity: PropTypes.string,
    cvss_score: PropTypes.number,
    issues: PropTypes.array,
  }).isRequired,
};

function AttackPanel({ finding }) {
  const c = SEV[finding.severity] || SEV.Medium;
  return (
    <div style={{ padding:'18px 24px', background: c.bg, borderTop:`1px solid ${c.border}` }}>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20, marginBottom:16 }}>

        {/* Possible Attacks */}
        <div style={{ background:'#fff', borderRadius:8, padding:'14px 16px',
          border:`1px solid ${c.border}` }}>
          <div style={{ fontWeight:700, fontSize:12, color:c.text, marginBottom:10,
            textTransform:'uppercase', letterSpacing:.5 }}>
            ⚔️ Possible Attack Types
          </div>
          <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
            {(finding.attack_types || []).map(a => <AttackChip key={a} label={a} />)}
          </div>
          <div style={{ marginTop:10, fontSize:11, color:'#6b7280' }}>
            <span style={{ fontWeight:600 }}>Attack Vector:</span>{' '}
            <span style={{ background:'#f3f4f6', borderRadius:4, padding:'2px 8px', fontFamily:'monospace' }}>
              {finding.attack_vector}
            </span>
          </div>
        </div>

        {/* Risk Impact */}
        <div style={{ background:'#fff', borderRadius:8, padding:'14px 16px',
          border:`1px solid ${c.border}` }}>
          <div style={{ fontWeight:700, fontSize:12, color:'#991b1b', marginBottom:8,
            textTransform:'uppercase', letterSpacing:.5 }}>
            💥 Risk Impact
          </div>
          <div style={{ fontSize:12, color:'#374151', lineHeight:1.6 }}>{finding.risk_impact}</div>
        </div>
      </div>

      {/* Remediation */}
      <div style={{ background:'#f0fdf4', border:'1px solid #86efac', borderRadius:8,
        padding:'12px 16px', marginBottom:14 }}>
        <div style={{ fontWeight:700, fontSize:12, color:'#065f46', marginBottom:4,
          textTransform:'uppercase', letterSpacing:.5 }}>✅ Remediation Guidance</div>
        <div style={{ fontSize:12, color:'#374151', lineHeight:1.6 }}>{finding.remediation}</div>
      </div>

      {/* Threat Intelligence Tags */}
      {finding.threatMapping && (
        <div style={{ display:'flex', flexWrap:'wrap', gap:6, marginBottom:14 }}>
          {(finding.threatMapping.mitre || []).map(t => (
            <span key={t.id} style={{ display:'inline-flex', alignItems:'center', gap:4,
              background:'#eff6ff', border:'1px solid #bfdbfe', borderRadius:4,
              padding:'3px 8px', fontSize:10, fontWeight:700, color:'#1e40af' }}>
              ⚔️ {t.id} {t.name}
            </span>
          ))}
          {(finding.threatMapping.owasp || []).map(o => (
            <span key={o.id} style={{ display:'inline-flex', alignItems:'center', gap:4,
              background:'#f5f3ff', border:'1px solid #c4b5fd', borderRadius:4,
              padding:'3px 8px', fontSize:10, fontWeight:700, color:'#5b21b6' }}>
              🛡️ {o.id} {o.name}
            </span>
          ))}
          {(finding.threatMapping.capec || []).map(p => (
            <span key={p.id} style={{ display:'inline-flex', alignItems:'center', gap:4,
              background:'#fef2f2', border:'1px solid #fca5a5', borderRadius:4,
              padding:'3px 8px', fontSize:10, fontWeight:700, color:'#991b1b' }}>
              🎯 {p.id} {p.name}
            </span>
          ))}
        </div>
      )}

      {/* Meta stats */}
      <div style={{ display:'flex', gap:20, marginBottom:14, fontSize:12, color:'#6b7280' }}>
        <span><b>Risk Score:</b> {finding.risk_score}/10</span>
        <span><b>CVSS Base:</b> {finding.cvss_score}</span>
        <span><b>Issues:</b> {finding.issue_count}</span>
        <span><b>Files Affected:</b> {finding.affected_files}</span>
        <span><b>CWE Reference:</b>{' '}
          <a href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-','')}.html`}
            target="_blank" rel="noreferrer" style={{ color:'#1d4ed8' }}>{finding.cwe_id} ↗</a>
        </span>
      </div>

      {/* Individual SonarQube Issues */}
      <div style={{ fontWeight:700, fontSize:12, color:'#374151', marginBottom:6 }}>
        Findings ({finding.issues?.length || 0}):
      </div>
      <div style={{ maxHeight:200, overflowY:'auto', borderRadius:6, border:'1px solid #e5e7eb' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11 }}>
          <thead>
            <tr style={{ background:'#f9fafb', position:'sticky', top:0 }}>
              {['Severity','Rule','Message','File','Line'].map(h => (
                <th key={h} style={{ padding:'5px 10px', textAlign:'left', fontWeight:700,
                  color:'#6b7280', borderBottom:'1px solid #e5e7eb' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(finding.issues || []).map((iss, issIdx) => (
              <tr key={iss.key || `${iss.rule}-${iss.line}-${iss.component}`} style={{ borderBottom:'1px solid #f3f4f6',
                background: issIdx % 2 === 0 ? '#fff' : '#f9fafb' }}>
                <td style={{ padding:'5px 10px' }}>
                  <span style={{ fontSize:10, fontWeight:700,
                    color: getSonarSevColor(iss.severity) }}>
                    {iss.severity}
                  </span>
                </td>
                <td style={{ padding:'5px 10px', fontFamily:'monospace', color:'#4b5563', fontSize:10 }}>{iss.rule}</td>
                <td style={{ padding:'5px 10px', color:'#374151', maxWidth:280,
                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{iss.message}</td>
                <td style={{ padding:'5px 10px', color:'#9ca3af', fontFamily:'monospace', fontSize:10,
                  maxWidth:180, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                  {(iss.component || '').split('/').pop()}
                </td>
                <td style={{ padding:'5px 10px', color:'#9ca3af' }}>{iss.line || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <AiAdvice finding={finding} />
    </div>
  );
}
AttackPanel.propTypes = {
  finding: PropTypes.shape({
    severity: PropTypes.string,
    attack_types: PropTypes.arrayOf(PropTypes.string),
    attack_vector: PropTypes.string,
    risk_impact: PropTypes.string,
    remediation: PropTypes.string,
    risk_score: PropTypes.number,
    cvss_score: PropTypes.number,
    issue_count: PropTypes.number,
    affected_files: PropTypes.number,
    cwe_id: PropTypes.string,
    issues: PropTypes.array,
  }).isRequired,
};

function getSonarSevColor(severity) {
  if (['BLOCKER', 'CRITICAL'].includes(severity)) return '#dc2626';
  if (severity === 'MAJOR') return '#ea580c';
  return '#6b7280';
}

// ── CWE table row ────────────────────────────────────────────────────────────
function CWERow({ f, idx }) {
  const [open, setOpen] = useState(false);
  const c = SEV[f.severity] || SEV.Medium;
  return (
    <>
      <tr onClick={() => setOpen(o => !o)}
        style={{ background: idx % 2 === 0 ? '#fff' : '#f9fafb', cursor:'pointer' }}
        onMouseEnter={e => e.currentTarget.style.background = c.bg}
        onMouseLeave={e => e.currentTarget.style.background = idx % 2 === 0 ? '#fff' : '#f9fafb'}>
        <td style={{ padding:'11px 14px', fontFamily:'monospace', fontWeight:700, fontSize:13, color:'#1e40af' }}>
          <a href={`https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-','')}.html`}
            target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
            style={{ color:'#1e40af', textDecoration:'none' }}>{f.cwe_id}</a>
        </td>
        <td style={{ padding:'11px 14px', fontWeight:600, color:'#111827' }}>{f.cwe_name}</td>
        <td style={{ padding:'11px 14px', textAlign:'center' }}><CvssTag score={f.cvss_score} /></td>
        <td style={{ padding:'11px 14px', textAlign:'center' }}><SevPill sev={f.severity} /></td>
        <td style={{ padding:'11px 14px' }}>
          <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
            {(f.attack_types || []).slice(0,3).map(a => {
              const meta = ATTACK_ICONS[a] || { icon:'⚠️', color:'#6b7280' };
              return (
                <span key={a} style={{ display:'inline-flex', alignItems:'center', gap:3,
                  background: meta.color+'18', color: meta.color,
                  border:`1px solid ${meta.color}40`,
                  borderRadius:20, padding:'2px 8px', fontSize:10, fontWeight:700 }}>
                  {meta.icon} {a}
                </span>
              );
            })}
            {(f.attack_types||[]).length > 3 &&
              <span style={{ fontSize:10, color:'#9ca3af', alignSelf:'center' }}>
                +{f.attack_types.length-3} more
              </span>}
          </div>
        </td>
        <td style={{ padding:'11px 14px', textAlign:'center', fontWeight:700, color:'#374151' }}>{f.issue_count}</td>
        <td style={{ padding:'11px 14px', textAlign:'center', color:'#9ca3af', fontSize:16 }}>
          {open ? '▲' : '▼'}
        </td>
      </tr>
      {open && (
        <tr><td colSpan={7} style={{ padding:0, borderBottom:`2px solid ${c.border}` }}>
          <AttackPanel finding={f} />
        </td></tr>
      )}
    </>
  );
}
CWERow.propTypes = {
  f: PropTypes.shape({
    severity: PropTypes.string,
    cwe_id: PropTypes.string,
    cwe_name: PropTypes.string,
    cvss_score: PropTypes.number,
    attack_types: PropTypes.arrayOf(PropTypes.string),
    issue_count: PropTypes.number,
  }).isRequired,
  idx: PropTypes.number.isRequired,
};

// ── Main page ────────────────────────────────────────────────────────────────
export default function RiskPage() {
  const [projects, setProjects] = useState([]);
  const [selId, setSelId]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState('');

  useEffect(() => {
    apiFetch(`${API}/projects`)
      .then(r => r.json())
      .then(d => Array.isArray(d) && setProjects(d))
      .catch(() => {});
  }, []);

  const selProj = projects.find(p => String(p.id) === String(selId));

  const analyze = useCallback(async () => {
    if (!selProj || selProj.needsScan) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const r = await apiFetch(`${API}/analyze`, {
        method:'POST',
        body: JSON.stringify({ projectId: selProj.id }),
      });
      const data = await r.json();
      if (r.ok) {
        setResult(data);
      } else if (data.notYetScanned) {
        setError('__NOT_SCANNED__');
      } else {
        setError(data.error || 'Analysis failed');
      }
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }, [selProj]);

  return (
    <Layout title="Risk Analysis">
      {/* Toolbar */}
      <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:22,
        background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, padding:'14px 18px' }}>
        <span style={{ fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:1 }}>
          Select Project
        </span>
        <select value={selId}
          onChange={e => { setSelId(e.target.value); setResult(null); setError(''); }}
          style={{ flex:1, padding:'8px 12px', border:'1px solid #d1d5db',
            borderRadius:6, fontSize:13, background:'#f9fafb' }}>
          <option value="">— Choose a project —</option>
          {projects.map(p => (
            <option key={p.id} value={p.id} disabled={p.needsScan}>
              {p.name}{p.needsScan ? '  ⚠ Needs Scan First' : ` — ${p.openFindings} open findings${p.tools?.length ? ` (${p.tools.join(', ')})` : ''}`}
            </option>
          ))}
        </select>
        <button onClick={analyze} disabled={!selProj || selProj.needsScan || loading}
          style={{ padding:'9px 20px', borderRadius:6, border:'none', cursor:'pointer',
            fontWeight:700, fontSize:13, whiteSpace:'nowrap',
            background:(!selProj||selProj.needsScan||loading)?'#d1d5db':'#dc2626', color:'#fff' }}>
          {loading ? '⏳ Analyzing…' : '🎯 Run Risk Analysis'}
        </button>
      </div>

      {result && (
        <div style={{ background:'#f0f9ff', border:'1px solid #bae6fd', borderRadius:8, padding:'10px 16px', marginBottom:16, fontSize:13 }}>
          Risk is based on <strong>{result.toolFindings ?? result.riskSummary?.total_issues} open findings</strong> from{' '}
          <strong>{result.tools?.length ? result.tools.join(', ') : 'SonarQube'}</strong>
          {result.policyChecks > 0 ? <> plus <strong>{result.policyChecks} policy-as-code checks</strong> (Dockerfile / config rules)</> : null}
          {result.source === 'all-tools' ? ' (all tools, false positives and accepted risks excluded), mapped to CWE, OWASP Top 10, MITRE ATT&CK and CAPEC.' : ' (SonarQube only — run the Pipeline to include every tool).'}
        </div>
      )}

      {/* Errors */}
      {error === '__NOT_SCANNED__' && (
        <div style={{ background:'#fef2f2', border:'1px solid #fca5a5', borderRadius:8,
          padding:'14px 18px', marginBottom:20, display:'flex', gap:12, alignItems:'center' }}>
          <span style={{ fontSize:24 }}>⚠️</span>
          <div>
            <div style={{ fontWeight:700, color:'#991b1b' }}>Project Not Scanned</div>
            <div style={{ fontSize:13, color:'#7f1d1d', marginTop:2 }}>
              Run the Pipeline (or any scan on Security Scans) first.{' '}
              <a href="/pipeline" style={{ color:'#dc2626', fontWeight:700 }}>Go to Pipeline →</a>
            </div>
          </div>
        </div>
      )}
      {error && error !== '__NOT_SCANNED__' && (
        <div style={{ background:'#fef2f2', border:'1px solid #fca5a5', borderRadius:8,
          padding:14, marginBottom:20, color:'#991b1b', fontSize:13 }}>❌ {error}</div>
      )}

      {/* Empty state */}
      {!result && !loading && (
        <div style={{ textAlign:'center', padding:'80px 0', color:'#9ca3af' }}>
          <div style={{ fontSize:52, marginBottom:14 }}>🎯</div>
          <div style={{ fontSize:18, fontWeight:700, color:'#374151', marginBottom:8 }}>
            CWE Risk &amp; Attack Analysis
          </div>
          <div style={{ fontSize:13, maxWidth:500, margin:'0 auto', lineHeight:1.7 }}>
            Select a scanned project and click <strong>Run Risk Analysis</strong>.<br/>
            Every vulnerability is mapped to its <strong>CWE ID</strong>, <strong>CVSS score</strong>,
            and the <strong>attacks an attacker could perform</strong> — with remediation guidance.
          </div>
        </div>
      )}

      {loading && (
        <div style={{ textAlign:'center', padding:'80px 0', color:'#6b7280' }}>
          <div style={{ fontSize:48, marginBottom:14 }}>⏳</div>
          <div style={{ fontSize:14 }}>Mapping vulnerabilities to CWE + Attack database…</div>
        </div>
      )}

      {/* Results */}
      {result && (() => {
        const rs = result.riskSummary || {};
        const lvl = rs.overall_risk_level || 'Low';
        const c = SEV[lvl] || SEV.Low;
        const findings = result.cweFindings || [];
        return (
          <>
            {/* Risk level banner */}
            <div style={{ background:c.bg, border:`1px solid ${c.border}`, borderRadius:8,
              padding:'16px 22px', marginBottom:18, display:'flex', alignItems:'center', gap:20 }}>
              <div>
                <div style={{ fontSize:11, fontWeight:700, color:c.text,
                  textTransform:'uppercase', letterSpacing:1 }}>Overall Risk Level</div>
                <div style={{ fontSize:32, fontWeight:900, color:c.pill }}>{lvl}</div>
                <div style={{ fontSize:12, color:c.text }}>
                  Score {rs.overall_risk_score}/10 · {rs.total_issues} issues · {rs.unique_cwes} CWEs
                </div>
              </div>
              {(rs.top_risks||[]).map(r => (
                <div key={r.cwe_id} style={{ background:'#fff', border:`1px solid ${c.border}`,
                  borderRadius:6, padding:'8px 14px', minWidth:148 }}>
                  <div style={{ fontSize:11, fontWeight:700, color:c.text }}>{r.cwe_id}</div>
                  <div style={{ fontSize:12, fontWeight:600, color:'#111827' }}>{r.cwe_name}</div>
                  <div style={{ fontSize:11, color:'#6b7280' }}>CVSS {r.cvss_score}</div>
                  <div style={{ display:'flex', flexWrap:'wrap', gap:3, marginTop:4 }}>
                    {(r.attack_types||[]).map(a => {
                      const meta = ATTACK_ICONS[a]||{icon:'⚠️',color:'#6b7280'};
                      return <span key={a} style={{ fontSize:9, color:meta.color, fontWeight:700 }}>{meta.icon} {a}</span>;
                    })}
                  </div>
                </div>
              ))}
            </div>

            <SummaryCards s={rs} />

            {/* ═══ THREAT INTELLIGENCE HEATMAPS ═══ */}
            {result.heatmaps && (
              <div style={{ marginBottom:22 }}>
                <h3 style={{ margin:'0 0 14px', fontSize:15, fontWeight:700, color:'#111827' }}>
                  🗺️ Threat Intelligence Heatmaps
                </h3>
                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:16 }}>

                  {/* MITRE ATT&CK */}
                  <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, overflow:'hidden' }}>
                    <div style={{ background:'linear-gradient(135deg,#1e3a5f,#0f172a)', color:'#fff',
                      padding:'12px 16px', fontWeight:700, fontSize:13, letterSpacing:.3 }}>
                      ⚔️ MITRE ATT&CK Techniques
                    </div>
                    <div style={{ padding:14, maxHeight:280, overflowY:'auto' }}>
                      {(result.heatmaps.mitre || []).length === 0 && (
                        <div style={{ color:'#9ca3af', fontSize:12, textAlign:'center', padding:20 }}>No techniques mapped</div>
                      )}
                      {(result.heatmaps.mitre || []).map(t => {
                        const sevC = t.severity === 'Critical' ? '#dc2626' : t.severity === 'High' ? '#ea580c' : '#ca8a04';
                        const barW = Math.min(100, t.issues * 12 + 20);
                        return (
                          <div key={t.id} style={{ marginBottom:10 }}>
                            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:3 }}>
                              <span style={{ fontSize:12, fontWeight:700, color:'#111827' }}>
                                <span style={{ color:sevC, fontFamily:'monospace', fontSize:10 }}>{t.id}</span>{' '}
                                {t.name}
                              </span>
                              <span style={{ fontSize:10, color:'#6b7280' }}>{t.tactic}</span>
                            </div>
                            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                              <div style={{ flex:1, height:8, background:'#f3f4f6', borderRadius:4, overflow:'hidden' }}>
                                <div style={{ width:`${barW}%`, height:'100%', background:sevC, borderRadius:4,
                                  transition:'width 0.5s ease' }} />
                              </div>
                              <span style={{ fontSize:10, fontWeight:700, color:sevC, minWidth:42, textAlign:'right' }}>
                                {t.issues} issue{t.issues !== 1 ? 's' : ''}
                              </span>
                            </div>
                            <div style={{ fontSize:9, color:'#9ca3af', marginTop:2 }}>
                              CWEs: {t.cwes.join(', ')}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* OWASP Top 10 */}
                  <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, overflow:'hidden' }}>
                    <div style={{ background:'linear-gradient(135deg,#7c3aed,#4c1d95)', color:'#fff',
                      padding:'12px 16px', fontWeight:700, fontSize:13, letterSpacing:.3 }}>
                      🛡️ OWASP Top 10 / API Top 10
                    </div>
                    <div style={{ padding:14, maxHeight:280, overflowY:'auto' }}>
                      {(result.heatmaps.owasp || []).length === 0 && (
                        <div style={{ color:'#9ca3af', fontSize:12, textAlign:'center', padding:20 }}>No categories mapped</div>
                      )}
                      {(result.heatmaps.owasp || []).map(o => {
                        const sevC = o.severity === 'Critical' ? '#7c3aed' : o.severity === 'High' ? '#a855f7' : '#c084fc';
                        const barW = Math.min(100, o.issues * 12 + 20);
                        return (
                          <div key={o.id} style={{ marginBottom:10 }}>
                            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:3 }}>
                              <span style={{ fontSize:12, fontWeight:700, color:'#111827' }}>
                                <span style={{ background:sevC, color:'#fff', borderRadius:3, padding:'1px 5px',
                                  fontSize:9, fontWeight:800, marginRight:6 }}>{o.id}</span>
                                {o.name}
                              </span>
                              <span style={{ fontSize:10, fontWeight:700, color:sevC }}>{o.issues}</span>
                            </div>
                            <div style={{ height:8, background:'#f3f4f6', borderRadius:4, overflow:'hidden' }}>
                              <div style={{ width:`${barW}%`, height:'100%', background:sevC, borderRadius:4,
                                transition:'width 0.5s ease' }} />
                            </div>
                            <div style={{ fontSize:9, color:'#9ca3af', marginTop:2 }}>
                              CWEs: {o.cwes.join(', ')}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* CAPEC Attack Patterns — full width */}
                <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, overflow:'hidden', marginBottom:4 }}>
                  <div style={{ background:'linear-gradient(135deg,#b91c1c,#7f1d1d)', color:'#fff',
                    padding:'12px 16px', fontWeight:700, fontSize:13, letterSpacing:.3 }}>
                    🎯 CAPEC Attack Patterns
                  </div>
                  <div style={{ padding:14, display:'flex', flexWrap:'wrap', gap:10 }}>
                    {(result.heatmaps.capec || []).length === 0 && (
                      <div style={{ color:'#9ca3af', fontSize:12, textAlign:'center', width:'100%', padding:20 }}>No patterns mapped</div>
                    )}
                    {(result.heatmaps.capec || []).map(p => {
                      const bg = p.severity === 'Critical' ? '#fef2f2' : p.severity === 'High' ? '#fff7ed' : '#fefce8';
                      const bdr = p.severity === 'Critical' ? '#fca5a5' : p.severity === 'High' ? '#fdba74' : '#fde047';
                      const txt = p.severity === 'Critical' ? '#991b1b' : p.severity === 'High' ? '#9a3412' : '#854d0e';
                      return (
                        <div key={p.id} style={{ background:bg, border:`1px solid ${bdr}`, borderRadius:8,
                          padding:'10px 14px', minWidth:180, flex:'1 1 220px' }}>
                          <div style={{ fontSize:10, fontWeight:800, color:txt, fontFamily:'monospace' }}>{p.id}</div>
                          <div style={{ fontSize:12, fontWeight:700, color:'#111827', marginTop:2 }}>{p.name}</div>
                          <div style={{ display:'flex', justifyContent:'space-between', marginTop:6, fontSize:10 }}>
                            <span style={{ color:'#6b7280' }}>{p.issues} issue{p.issues !== 1 ? 's' : ''}</span>
                            <span style={{ color:txt, fontWeight:700 }}>{p.severity}</span>
                          </div>
                          <div style={{ fontSize:9, color:'#9ca3af', marginTop:3 }}>
                            {p.cwes.join(', ')}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* CWE Findings Table */}
            <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:8,
              overflow:'hidden', marginBottom:20 }}>
              <div style={{ padding:'14px 18px', borderBottom:'1px solid #e5e7eb',
                display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                <h3 style={{ margin:0, fontSize:15, fontWeight:700, color:'#111827' }}>
                  🔬 CWE Vulnerability &amp; Attack Findings
                </h3>
                <span style={{ fontSize:12, color:'#6b7280' }}>
                  {findings.length} unique weakness{findings.length === 1 ? '' : 'es'} · Click row to expand
                </span>
              </div>
              <div style={{ overflowX:'auto' }}>
                <table style={{ width:'100%', borderCollapse:'collapse' }}>
                  <thead>
                    <tr style={{ background:'#f9fafb', borderBottom:'1px solid #e5e7eb' }}>
                      {['CWE ID','Vulnerability Name','CVSS','Severity','Possible Attacks','Issues',''].map(h => (
                        <th key={h} style={{ padding:'9px 14px', textAlign:'left', fontSize:11,
                          fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:.5 }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => <CWERow key={f.cwe_id} f={f} idx={i} />)}
                    {findings.length === 0 && (
                      <tr><td colSpan={7} style={{ padding:'40px', textAlign:'center', color:'#9ca3af' }}>
                        ✅ No vulnerabilities found — project looks clean!
                      </td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Link to compliance report */}
            <div style={{ background:'linear-gradient(135deg,#1e3a5f,#1e40af)', borderRadius:8,
              padding:'18px 24px', display:'flex', alignItems:'center', justifyContent:'space-between', color:'#fff' }}>
              <div>
                <div style={{ fontWeight:700, fontSize:15 }}>📋 Generate Compliance Report</div>
                <div style={{ fontSize:12, opacity:.85, marginTop:3 }}>
                  Full NIST CSF 2.0 report with CWE findings and PDF export.
                </div>
              </div>
              <a href="/compliance-report" style={{ background:'#fff', color:'#1e40af',
                borderRadius:6, padding:'10px 18px', fontWeight:700, fontSize:13,
                textDecoration:'none', whiteSpace:'nowrap' }}>
                Generate Report →
              </a>
            </div>
          </>
        );
      })()}
    </Layout>
  );
}
