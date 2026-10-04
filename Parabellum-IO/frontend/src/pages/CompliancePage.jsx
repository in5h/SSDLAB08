import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

// ── Framework Definitions ─────────────────────────────────────────
// One issue can fail several controls — count each issue only once in the totals
function uniqueViolations(result) {
  const seen = new Map();
  for (const v of (result?.failedControls || []).flatMap(c => c.violations)) {
    seen.set(`${v.rule}|${v.message}|${v.component}|${v.line}`, v);
  }
  return [...seen.values()];
}

const FRAMEWORKS = [
  { slug: 'nist_csf',     label: 'NIST CSF 2.0',     icon: '🛡',  color: '#4A7C59' },
  { slug: 'iso27001',     label: 'ISO 27001',         icon: '📋',  color: '#1B6CA8' },
  { slug: 'iso27034',     label: 'ISO 27034',         icon: '🔐',  color: '#7B5EA7' },
  { slug: 'nist_sp800',   label: 'NIST SP 800-53',    icon: '🏛',  color: '#B5830A' },
  { slug: 'cis_controls', label: 'CIS Controls v8',   icon: '⚙',  color: '#9B2226' },
  { slug: 'owasp_asvs',   label: 'OWASP ASVS v4',    icon: '🕸',  color: '#5E6472' },
];

const SEV_COLOR = { BLOCKER:'danger', CRITICAL:'danger', MAJOR:'warning', MINOR:'neutral', INFO:'neutral' };

function ScoreGauge({ score, grade, status, accentColor }) {
  const r = 54, c = 2 * Math.PI * r;
  const color = accentColor || (score >= 70 ? 'var(--success)' : score >= 40 ? 'var(--warning)' : 'var(--danger)');
  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:10 }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        <circle cx={65} cy={65} r={r} fill="none" stroke="var(--border)" strokeWidth={10} />
        <circle cx={65} cy={65} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={c} strokeDashoffset={c - (score/100)*c}
          strokeLinecap="round" transform="rotate(-90 65 65)"
          style={{ transition:'stroke-dashoffset 1s ease' }} />
        <text x={65} y={60} textAnchor="middle" fontSize={26} fontWeight={800}
          fontFamily="Playfair Display,serif" fill={color}>{score}</text>
        <text x={65} y={78} textAnchor="middle" fontSize={11} fill="var(--muted)">/ 100</text>
      </svg>
      <div style={{ display:'flex', gap:8, alignItems:'center' }}>
        <span style={{ padding:'4px 16px', borderRadius:20, fontWeight:800, fontSize:14,
          background: status==='PASS' ? 'rgba(74,124,89,0.12)' : 'rgba(155,34,38,0.10)',
          color: status==='PASS' ? 'var(--success)' : 'var(--danger)' }}>
          {status==='PASS' ? '✅ PASS' : '❌ FAIL'}
        </span>
        <span style={{ fontFamily:'Playfair Display,serif', fontSize:22, fontWeight:700, color:'var(--primary)' }}>Grade {grade}</span>
      </div>
    </div>
  );
}

function FailedControlRow({ ctrl, groupField, accentColor, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen || false);
  const groupValue = ctrl[groupField] || ctrl.function || 'General';
  const worst = ctrl.violations.reduce((m, v) => {
    const w = {BLOCKER:5,CRITICAL:4,MAJOR:3,MINOR:2,INFO:1}[v.severity?.toUpperCase()] ?? 0;
    return w > m ? w : m;
  }, 0);
  const worstLabel = ['','INFO','MINOR','MAJOR','CRITICAL','BLOCKER'][worst] || 'MINOR';

  return (
    <div style={{ border:'1px solid var(--border)', borderRadius:10, overflow:'hidden',
      borderLeft:`4px solid ${accentColor}`, background:'var(--panel)', marginBottom:6 }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, padding:'10px 14px',
        cursor:'pointer', flexWrap:'wrap' }}
        role="button" tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && setOpen(o => !o)}
        onClick={() => setOpen(o => !o)}>
        <span style={{ fontFamily:'monospace', fontSize:13, fontWeight:800,
          color: accentColor, background: `${accentColor}14`,
          padding:'3px 10px', borderRadius:6, flexShrink:0 }}>
          {ctrl.control_id}
        </span>
        <span style={{ fontSize:11, fontWeight:600, color: accentColor,
          background: `${accentColor}14`, padding:'2px 8px', borderRadius:12, flexShrink:0 }}>
          {groupValue}
        </span>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontWeight:600, fontSize:13, color:'var(--text)',
            overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
            {ctrl.category || ctrl.description}
          </div>
          <div style={{ fontSize:11, color:'var(--muted)', overflow:'hidden',
            textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
            {ctrl.description}
          </div>
        </div>
        <span className={`badge badge-${SEV_COLOR[worstLabel] || 'neutral'}`} style={{ flexShrink:0 }}>
          {worstLabel}
        </span>
        <span style={{ fontSize:12, color:'var(--muted)', flexShrink:0 }}>
          {ctrl.violations.length} violation{ctrl.violations.length !== 1 ? 's' : ''}
        </span>
        <span style={{ color:'var(--muted)', fontSize:12, flexShrink:0 }}>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div style={{ borderTop:'1px solid var(--border-light)', background:'var(--bg)', padding:'12px 14px' }}>
          <table className="table" style={{ marginBottom:0 }}>
            <thead><tr>
              <th>Severity</th><th>Type</th><th>Issue</th><th>Rule</th><th>File & Line</th>
            </tr></thead>
            <tbody>
              {ctrl.violations.map((v, i) => (
                <tr key={i}>
                  <td><span className={`badge badge-${SEV_COLOR[v.severity?.toUpperCase()] || 'neutral'}`}>{v.severity}</span></td>
                  <td><span className="badge badge-neutral">{v.type || '—'}</span></td>
                  <td style={{ maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontSize:13 }}>{v.message}</td>
                  <td><code style={{ fontSize:11, color:'var(--muted)' }}>{v.rule || '—'}</code></td>
                  <td style={{ fontSize:11, color:'var(--muted)', maxWidth:180,
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {v.component}{v.line ? `:${v.line}` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function CompliancePage() {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [frameworkTab, setFrameworkTab] = useState('nist_csf');
  const [results, setResults] = useState({});       // { slug: data }
  const [loading, setLoading] = useState({});        // { slug: bool }
  const [errors, setErrors] = useState({});          // { slug: string }
  const [ragOnline, setRagOnline] = useState(null);
  const [subTab, setSubTab] = useState('controls');  // 'controls' | 'breakdown'
  const [fnFilter, setFnFilter] = useState('');

  useEffect(() => { loadProjects(); checkRag(); }, []);

  async function loadProjects() {
    try {
      const r = await apiFetch('/api/compliance/projects');
      const d = await r.json();
      setProjects(Array.isArray(d) ? d : []);
    } catch { /* silent */ }
  }

  async function checkRag() {
    try {
      const r = await apiFetch('/api/rag/health');
      const d = await r.json();
      setRagOnline(d.online);
    } catch { setRagOnline(false); }
  }

  async function analyze(fw) {
    const slug = fw || frameworkTab;
    if (!selectedProject) { setErrors(e => ({...e, [slug]: 'Please select a scanned project.'})); return; }
    if (selectedProject.needsScan) { setErrors(e => ({...e, [slug]: '__NOT_SCANNED__'})); return; }

    setErrors(e => ({...e, [slug]: ''}));
    setLoading(l => ({...l, [slug]: true}));
    try {
      const res = await apiFetch('/api/compliance/analyze', {
        method: 'POST',
        body: JSON.stringify({
          projectId: selectedProject.id,
          projectName: selectedProject.name,
          framework: slug,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.notYetScanned) {
          setErrors(e => ({...e, [slug]: '__NOT_SCANNED__'}));
        } else {
          throw new Error(data.error || 'Analysis failed');
        }
        return;
      }
      setResults(r => ({...r, [slug]: data}));
      setSubTab('controls');
    } catch (err) {
      setErrors(e => ({...e, [slug]: err.message}));
    } finally {
      setLoading(l => ({...l, [slug]: false}));
    }
  }

  const fw = FRAMEWORKS.find(f => f.slug === frameworkTab) || FRAMEWORKS[0];
  const result = results[frameworkTab];
  const isLoading = loading[frameworkTab];
  const error = errors[frameworkTab];

  // Determine groups and group field from result or framework metadata
  const groupField = result?.groupField || 'function';
  const groups = result?.groups || [];

  const filteredControls = result?.failedControls?.filter(c =>
    !fnFilter || c[groupField] === fnFilter || c.function === fnFilter
  ) ?? [];

  const innerTab = (id, label, count) => (
    <button onClick={() => setSubTab(id)} style={{
      padding:'8px 18px', borderRadius:20, border:'none', cursor:'pointer', fontSize:13, fontWeight:700,
      background: subTab===id ? 'var(--primary)' : 'transparent',
      color: subTab===id ? '#fff' : 'var(--muted)',
      transition:'all .15s',
    }}>
      {label}{count !== undefined ? ` (${count})` : ''}
    </button>
  );

  return (
    <Layout title="Compliance Mapping">
      <div className="content-grid">

        {/* ═══ Framework Tab Bar ═══ */}
        <div className="col-12" style={{ display:'flex', gap:4, background:'var(--panel)',
          padding:6, borderRadius:16, border:'1px solid var(--border)', flexWrap:'wrap' }}>
          {FRAMEWORKS.map(f => (
            <button key={f.slug} onClick={() => { setFrameworkTab(f.slug); setSubTab('controls'); setFnFilter(''); }}
              style={{
                padding:'10px 18px', borderRadius:12, border:'none', cursor:'pointer',
                fontSize:13, fontWeight:700, display:'flex', alignItems:'center', gap:6,
                background: frameworkTab===f.slug ? fw.color : 'transparent',
                color: frameworkTab===f.slug ? '#fff' : 'var(--muted)',
                transition:'all .2s',
                boxShadow: frameworkTab===f.slug ? `0 2px 12px ${f.color}40` : 'none',
              }}>
              <span style={{ fontSize:16 }}>{f.icon}</span> {f.label}
              {results[f.slug] && <span style={{
                width:8, height:8, borderRadius:'50%', marginLeft:4,
                background: frameworkTab===f.slug ? '#fff' : 'var(--success)',
              }} />}
            </button>
          ))}
        </div>

        {/* ═══ Control Bar ═══ */}
        <div className="card col-12" style={{ display:'flex', gap:14, alignItems:'flex-end', flexWrap:'wrap' }}>
          <div className="field" style={{ flex:1, minWidth:220, margin:0 }}>
            <label>Select Scanned Project</label>
            <select className="input" value={selectedProject?.id || ''} onChange={e => {
              const p = projects.find(p => String(p.id) === e.target.value);
              setSelectedProject(p || null); setResults({}); setErrors({});
            }}>
              <option value="">— Choose a project —</option>
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  {p.type === 'github' ? '🐙' : p.type === 'local' ? '📂' : '📦'} {p.name}
                  {p.needsScan ? ' — ⚠ Needs Scan First' : ` — ${p.openFindings} open findings${p.tools?.length ? ` (${p.tools.join(', ')})` : ''}`}
                </option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" onClick={() => analyze()}
            disabled={isLoading || !selectedProject || selectedProject?.needsScan}
            style={{ height:42, background: fw.color, borderColor: fw.color }}>
            {isLoading ? <><span className="spinner" /> Analyzing…</> : `${fw.icon} Run ${fw.label} Analysis`}
          </button>
          <div style={{ display:'flex', alignItems:'center', gap:6, height:42 }}>
            <span style={{ width:8, height:8, borderRadius:'50%', flexShrink:0,
              background: ragOnline===null ? 'var(--muted)' : ragOnline ? 'var(--success)' : 'var(--warning)' }} />
            <span style={{ fontSize:12, color:'var(--muted)' }}>
              {ragOnline===null ? 'Checking RAG…' : ragOnline ? 'RAG Model Online' : 'Using local GRC mapping'}
            </span>
          </div>
        </div>

        {/* ═══ Error States ═══ */}
        {error && error !== '__NOT_SCANNED__' && (
          <div className="col-12" style={{ background:'rgba(155,34,38,0.08)',
            border:'1px solid rgba(155,34,38,0.2)', color:'var(--danger)',
            padding:'12px 16px', borderRadius:10, fontSize:13 }}>⚠ {error}</div>
        )}

        {(error === '__NOT_SCANNED__' || selectedProject?.needsScan) && (
          <div className="col-12" style={{
            background:'rgba(181,131,10,0.08)', border:'1px solid rgba(181,131,10,0.25)',
            color:'var(--text)', padding:'14px 18px', borderRadius:10,
            display:'flex', gap:12, alignItems:'center', flexWrap:'wrap',
          }}>
            <span style={{ fontSize:22 }}>⚠</span>
            <div style={{ flex:1 }}>
              <strong>{selectedProject?.name || 'This project'}</strong> has no scan results yet.
              Run the Pipeline (all tools) or any scan on Security Scans first.
            </div>
            <a href="/pipeline" style={{
              padding:'8px 16px', borderRadius:8, background:'var(--primary)',
              color:'#fff', fontWeight:700, fontSize:13, textDecoration:'none', flexShrink:0,
            }}>🚦 Go to Pipeline →</a>
          </div>
        )}

        {result && (
          <div className="col-12" style={{ background:'rgba(27,108,168,0.06)', border:'1px solid rgba(27,108,168,0.2)', padding:'10px 16px', borderRadius:10, fontSize:13 }}>
            Based on <strong>{result.totalIssues} open findings</strong> from <strong>{result.tools?.length ? result.tools.join(', ') : 'SonarQube'}</strong>
            {result.source === 'all-tools' ? ' — every tool, each finding mapped to this framework by the pipeline (RAG / retriever + rules).' : ' — SonarQube only. Run the Pipeline to include every tool.'}
          </div>
        )}

        {/* ═══ Empty State ═══ */}
        {!result && !isLoading && (
          <div className="col-12" style={{ textAlign:'center', padding:'60px 20px', color:'var(--muted)' }}>
            <div style={{ fontSize:60, opacity:0.12, marginBottom:16 }}>{fw.icon}</div>
            <div style={{ fontFamily:'Playfair Display,serif', fontSize:22, color:'var(--text)', marginBottom:8 }}>
              {fw.label} Compliance Analysis
            </div>
            <div style={{ fontSize:14 }}>
              Select a scanned project and click <strong>Run {fw.label} Analysis</strong>.<br />
              Every vulnerability is mapped to {fw.label} controls — failed controls show exactly which clause failed and why.
            </div>
          </div>
        )}

        {/* ═══ Loading ═══ */}
        {isLoading && (
          <div className="col-12" style={{ textAlign:'center', padding:'60px 20px', color:'var(--muted)' }}>
            <div style={{ fontSize:40, marginBottom:12 }}>⏳</div>
            <div style={{ fontSize:14 }}>Mapping vulnerabilities to {fw.label} controls…<br />This may take a moment.</div>
          </div>
        )}

        {/* ═══ Results ═══ */}
        {result && (
          <>
            {/* Score + summary stats */}
            <div className="card col-4" style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:12 }}>
              <h3 style={{ margin:0, alignSelf:'flex-start' }}>Overall {fw.label} Score</h3>
              <ScoreGauge score={result.overall.score} grade={result.overall.grade}
                status={result.overall.status} accentColor={fw.color} />
              <div style={{ fontSize:12, color:'var(--muted)', textAlign:'center' }}>
                {result.totalIssues} total issues · {result.failedControls?.length || 0} controls failed
              </div>
              <div style={{ width:'100%', display:'flex', flexDirection:'column', gap:6 }}>
                {[
                  { label:'Blocker/Critical', count: uniqueViolations(result).filter(v=>['BLOCKER','CRITICAL'].includes(v.severity?.toUpperCase())).length, color:'danger' },
                  { label:'Major',            count: uniqueViolations(result).filter(v=>v.severity?.toUpperCase()==='MAJOR').length,   color:'warning' },
                  { label:'Minor / Info',     count: uniqueViolations(result).filter(v=>['MINOR','INFO'].includes(v.severity?.toUpperCase())).length, color:'neutral' },
                ].map(({label,count,color}) => (
                  <div key={label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                    padding:'6px 10px', borderRadius:8, background:'var(--bg)', border:'1px solid var(--border)' }}>
                    <span style={{ fontSize:12, color:'var(--text)' }}>{label}</span>
                    <span style={{ fontWeight:700, color:`var(--${color})` }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Group breakdown */}
            <div className="card col-8">
              <h3>{fw.label} Group Breakdown</h3>
              <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                {(result.breakdown || []).map(grp => {
                  const grpName = grp[groupField] || grp.function || 'General';
                  const score = grp.score ?? 100;
                  const barColor = grp.status === 'PASS' ? 'var(--success)'
                    : grp.status === 'WARN' ? 'var(--warning)' : fw.color;
                  return (
                    <div key={grpName} style={{ display:'grid', gridTemplateColumns:'32px 1fr 50px 60px',
                      gap:8, alignItems:'center', padding:'8px 10px', borderRadius:8,
                      background: grp.violations ? `${fw.color}08` : 'transparent',
                      border: grp.violations ? `1px solid ${fw.color}30` : '1px solid transparent' }}>
                      <span style={{ fontSize:18 }}>{fw.icon}</span>
                      <div>
                        <div style={{ fontWeight:700, fontSize:12, color:'var(--text)' }}>{grpName}</div>
                        <div style={{ height:5, background:'var(--border)', borderRadius:4, marginTop:3, overflow:'hidden' }}>
                          <div style={{ width:`${score}%`, height:'100%', background:barColor, borderRadius:4, transition:'width .6s' }} />
                        </div>
                      </div>
                      <div style={{ fontFamily:'Playfair Display,serif', fontSize:15, fontWeight:700,
                        color: barColor, textAlign:'right' }}>{score}%</div>
                      <div style={{ textAlign:'right' }}>
                        <span style={{ fontSize:11, color: grp.violations ? 'var(--danger)' : 'var(--success)',
                          fontWeight:600 }}>
                          {grp.violations ? `⚠ ${grp.violations} fail` : '✅ PASS'}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Inner tab bar */}
            <div className="col-12" style={{ display:'flex', gap:6, background:'var(--panel)',
              padding:'6px', borderRadius:24, border:'1px solid var(--border)', width:'fit-content' }}>
              {innerTab('controls', '❌ Failed Controls', result.failedControls?.length)}
              {innerTab('breakdown', '🌐 By Group')}
            </div>

            {/* TAB: Failed Controls */}
            {subTab === 'controls' && (
              <div className="card col-12">
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                  marginBottom:14, gap:10, flexWrap:'wrap' }}>
                  <h3 style={{ margin:0 }}>
                    Failed {fw.label} Controls — {filteredControls.length} control{filteredControls.length !== 1 ? 's' : ''} failed
                  </h3>
                  <select className="input" style={{ width:'auto', fontSize:13 }}
                    value={fnFilter} onChange={e => setFnFilter(e.target.value)}>
                    <option value="">All Groups</option>
                    {groups.map(g => <option key={g} value={g}>{g}</option>)}
                  </select>
                </div>

                {filteredControls.length === 0 ? (
                  <div style={{ textAlign:'center', padding:'40px', color:'var(--muted)', fontSize:14 }}>
                    {result.failedControls?.length === 0
                      ? `✅ All ${fw.label} controls passed — no violations found!`
                      : 'No controls match the current filter.'}
                  </div>
                ) : (
                  <div>
                    {filteredControls.map((ctrl, i) => (
                      <FailedControlRow key={ctrl.control_id + i} ctrl={ctrl}
                        groupField={groupField} accentColor={fw.color} defaultOpen={i < 2} />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB: By Group */}
            {subTab === 'breakdown' && (
              <div className="col-12" style={{ display:'grid',
                gridTemplateColumns:'repeat(auto-fill,minmax(340px,1fr))', gap:14 }}>
                {(result.breakdown || []).map(grp => {
                  const grpName = grp[groupField] || grp.function || 'General';
                  const grpControls = result.failedControls?.filter(c =>
                    c[groupField] === grpName || c.function === grpName
                  ) || [];
                  return (
                    <div key={grpName} className="card" style={{ padding:18,
                      borderTop:`4px solid ${fw.color}`, background:'var(--panel)' }}>
                      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:10 }}>
                        <div>
                          <div style={{ fontWeight:700, fontSize:15, display:'flex', gap:6 }}>
                            <span>{fw.icon}</span> {grpName}
                          </div>
                        </div>
                        <div style={{ textAlign:'right' }}>
                          <div style={{ fontFamily:'Playfair Display,serif', fontSize:22,
                            fontWeight:700, color: fw.color }}>{grp.score ?? 100}%</div>
                          <div style={{ fontSize:11, color: grpControls.length ? 'var(--danger)' : 'var(--success)', fontWeight:600 }}>
                            {grpControls.length ? `${grpControls.length} failed` : '✅ All passed'}
                          </div>
                        </div>
                      </div>

                      {grpControls.length > 0 ? (
                        <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                          {grpControls.map(ctrl => (
                            <div key={ctrl.control_id} style={{ padding:'8px 10px', borderRadius:8,
                              background: `${fw.color}08`, border:`1px solid ${fw.color}30` }}>
                              <div style={{ display:'flex', justifyContent:'space-between', gap:6 }}>
                                <div>
                                  <span style={{ fontFamily:'monospace', fontWeight:800,
                                    fontSize:12, color: fw.color }}>{ctrl.control_id}</span>
                                  <span style={{ fontSize:11, color:'var(--muted)', marginLeft:6 }}>{ctrl.category}</span>
                                </div>
                                <span style={{ fontSize:11, fontWeight:600, color:'var(--danger)', flexShrink:0 }}>
                                  {ctrl.violations.length} ×
                                </span>
                              </div>
                              <div style={{ fontSize:11, color:'var(--muted)', marginTop:3 }}>
                                <em>{ctrl.description}</em>
                              </div>
                              {ctrl.violations[0] && (
                                <div style={{ fontSize:11, marginTop:5, padding:'4px 8px',
                                  background:'rgba(0,0,0,0.04)', borderRadius:6,
                                  overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
                                  color:'var(--text)' }}>
                                  ↳ {ctrl.violations[0].message}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div style={{ fontSize:12, color:'var(--muted)', textAlign:'center', padding:'12px 0' }}>
                          ✅ No violations in this group
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}
