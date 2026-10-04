import { useCallback, useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import { toolState } from '../services/toolStatus';

const TOOL_KEYS = { 'SonarQube': 'sonarqube', 'Semgrep': 'semgrep', 'Snyk': 'snyk', 'Trivy': 'trivy', 'OWASP ZAP': 'zap', 'Anchore': 'anchore' };
const STAGE_COLOR = { pending: 'neutral', running: 'info', done: 'success', failed: 'danger', skipped: 'warning' };
const STAGE_ICON = { pending: '○', running: '◌', done: '✓', failed: '✗', skipped: '–' };

function StageList({ stages }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {stages.map(s => (
        <div key={s.name} className={`scan-stage ${s.status === 'running' ? 'active' : s.status === 'done' ? 'done' : s.status === 'failed' ? 'failed' : ''}`}>
          <span className={`badge badge-${STAGE_COLOR[s.status] || 'neutral'}`} style={{ minWidth: 76, justifyContent: 'center' }}>
            {STAGE_ICON[s.status]} {s.status}
          </span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>
              {s.name}
              {s.engine === 'built-in' && <span className="badge badge-warning" style={{ marginLeft: 8 }}>built-in checks</span>}
              {s.seconds !== undefined && <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}> · {s.seconds}s</span>}
            </div>
            {s.findings !== undefined && (
              <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                {s.findings} findings
                {s.counts && ` · ${s.counts.new} new · ${s.counts.stillOpen} still open · ${s.counts.fixed} fixed · ${s.counts.reopened} reopened`}
                {s.extra?.qualityGate && ` · quality gate ${s.extra.qualityGate}`}
              </div>
            )}
            {(s.message || s.warning) && <div style={{ fontSize: 12, color: s.status === 'failed' ? 'var(--danger)' : '#b45309', marginTop: 2 }}>{s.message || s.warning}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
StageList.propTypes = { stages: PropTypes.array.isRequired };

function ContextForm({ project, options, onSaved }) {
  const [form, setForm] = useState(project.context);
  const [msg, setMsg] = useState('');
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  async function save() {
    setMsg('Saving…');
    const r = await apiFetch(`/api/projects/${project.id}/context`, { method: 'PUT', body: JSON.stringify(form) });
    const d = await r.json();
    if (!r.ok) { setMsg('❌ ' + d.error); return; }
    setMsg('✅ Saved — used for risk scoring and the report');
    onSaved(d);
  }
  const sel = (k, label, opts) => (
    <div className="field" style={{ margin: 0 }}>
      <label>{label}</label>
      <select className="input" value={form[k] || ''} onChange={e => set(k, e.target.value)}>
        {(opts || []).map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="field" style={{ margin: 0 }}><label>Asset name</label><input className="input" value={form.assetName || ''} onChange={e => set('assetName', e.target.value)} /></div>
        {sel('assetType', 'Asset type', options.asset_type)}
        {sel('environment', 'Environment', options.environment)}
        {sel('dataClassification', 'Data classification', options.data_classification)}
        {sel('businessCriticality', 'Business criticality', options.business_criticality)}
        <div className="field" style={{ margin: 0 }}><label>Risk / business owner</label><input className="input" placeholder="e.g. Ali Khan (Team Lead)" value={form.businessOwner || ''} onChange={e => set('businessOwner', e.target.value)} /></div>
        <div className="field" style={{ margin: 0, gridColumn: '1 / -1' }}><label>Business description</label><input className="input" placeholder="What does this application do / who uses it?" value={form.description || ''} onChange={e => set('description', e.target.value)} /></div>
        <div className="field" style={{ margin: 0 }}><label>Running app URL (for OWASP ZAP)</label><input className="input" placeholder="http://localhost:3000" value={form.targetUrl || ''} onChange={e => set('targetUrl', e.target.value)} /></div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginTop: 22 }}>
          <input type="checkbox" checked={!!form.internetFacing} onChange={e => set('internetFacing', e.target.checked)} /> Internet-facing
        </label>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 14 }}>
        <button className="btn btn-secondary" onClick={save}>💾 Save context</button>
        <span style={{ fontSize: 12, color: msg.startsWith('❌') ? 'var(--danger)' : 'var(--muted)' }}>{msg}</span>
      </div>
    </div>
  );
}
ContextForm.propTypes = { project: PropTypes.object.isRequired, options: PropTypes.object.isRequired, onSaved: PropTypes.func.isRequired };

export default function PipelinePage() {
  const [projects, setProjects] = useState([]);
  const [selId, setSelId] = useState('');
  const [options, setOptions] = useState({});
  const [toolStatus, setToolStatus] = useState(null);
  const [tools, setTools] = useState(Object.keys(TOOL_KEYS));
  const [active, setActive] = useState(false);
  const [run, setRun] = useState(null);
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState('');
  const poll = useRef(null);

  const project = projects.find(p => String(p.id) === String(selId));

  const loadProjects = useCallback(() => apiFetch('/api/projects').then(r => r.json())
    .then(d => { if (Array.isArray(d)) { setProjects(d); setSelId(s => s || (d[0] ? String(d[0].id) : '')); } }), []);

  useEffect(() => {
    loadProjects();
    apiFetch('/api/projects/meta/context-options').then(r => r.json()).then(setOptions).catch(() => {});
    apiFetch('/api/tools/status').then(r => r.json()).then(setToolStatus).catch(() => {});
    return () => clearInterval(poll.current);
  }, [loadProjects]);

  const loadRuns = useCallback(() => {
    if (!selId) return;
    apiFetch(`/api/pipeline/runs/${selId}`).then(r => r.json()).then(d => {
      if (!Array.isArray(d)) return;
      setRuns(d);
      const running = d.find(x => x.status === 'running');
      if (running) watch(running.id); else setRun(r => (r && r.project_id === Number(selId) ? r : d[0] || null));
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selId]);

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { setRun(null); loadRuns(); }, [loadRuns]);

  function watch(runId) {
    clearInterval(poll.current);
    const tick = () => apiFetch(`/api/pipeline/run/${runId}`).then(r => r.json()).then(d => {
      setRun(d);
      if (d.status !== 'running') { clearInterval(poll.current); loadRuns(); }
    });
    tick();
    poll.current = setInterval(tick, 2000);
  }

  async function start() {
    setError('');
    const r = await apiFetch(`/api/pipeline/run/${selId}`, {
      method: 'POST', body: JSON.stringify({ tools, targetUrl: project?.context?.targetUrl || undefined, active }),
    });
    const d = await r.json();
    if (!r.ok) { setError(d.error); return; }
    watch(d.runId);
  }

  const running = run?.status === 'running';
  const toggleTool = t => setTools(ts => (ts.includes(t) ? ts.filter(x => x !== t) : [...ts, t]));

  return (
    <Layout title="Security Pipeline">
      <div className="content-grid">
        <div className="card col-12" style={{ display: 'flex', gap: 14, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="field" style={{ flex: 1, minWidth: 260, margin: 0 }}>
            <label>Project</label>
            <select className="input" value={selId} onChange={e => setSelId(e.target.value)}>
              {projects.length === 0 && <option value="">— add a project on the Import page first —</option>}
              {projects.map(p => <option key={p.id} value={p.id}>{p.name} (ID {p.id})</option>)}
            </select>
          </div>
          {project && <Link to="/findings" className="btn btn-secondary">🧾 Findings</Link>}
          {project && <Link to="/final-report" className="btn btn-secondary">📘 Final Report</Link>}
        </div>

        {project && (
          <div className="card col-6">
            <h3>Asset &amp; business context</h3>
            <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 0 }}>Set once per project. Used to rate each finding&apos;s business risk, assign the risk owner and fill the report.</p>
            <ContextForm key={project.id} project={project} options={options} onSaved={() => loadProjects()} />
          </div>
        )}

        {project && (
          <div className="card col-6">
            <h3>Run the pipeline</h3>
            <p style={{ fontSize: 13, color: 'var(--muted)', marginTop: 0 }}>
              One click runs every selected tool on <strong>{project.name}</strong>, stores all findings, maps them to all frameworks and
              compares them with the previous run (fix verification).
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 12 }}>
              {Object.entries(TOOL_KEYS).map(([t, key]) => {
                const st = toolState(toolStatus ? toolStatus[key] : null);
                return (
                  <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                    <input type="checkbox" checked={tools.includes(t)} onChange={() => toggleTool(t)} disabled={running} />
                    {t} <span className={`badge badge-${st.color}`} style={{ fontSize: 10 }}>{st.kind === 'builtin' ? 'basic checks' : st.label}</span>
                  </label>
                );
              })}
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>
              OWASP ZAP target: {project.context?.targetUrl || <em>not set — set &quot;Running app URL&quot; in the context form</em>}
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginBottom: 14 }}>
              <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} disabled={running} />
              ZAP active scan (attack payloads — only for apps you own)
            </label>
            <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', padding: 12 }} disabled={running || !tools.length} onClick={start}>
              {running ? <><span className="spinner" /> Pipeline running…</> : runs.length ? '🔁 Re-run pipeline (verify fixes)' : '🚦 Run pipeline'}
            </button>
            {error && <div className="auth-error" style={{ marginTop: 12 }}>⚠ {error}</div>}
          </div>
        )}

        {run && (
          <div className="card col-12">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Run #{run.id} <span className={`badge badge-${run.status === 'completed' ? 'success' : run.status === 'running' ? 'info' : 'danger'}`}>{run.status}</span></h3>
              {run.summary && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <span className="badge badge-info">{run.summary.new} new</span>
                  <span className="badge badge-success">{run.summary.fixed} fixed &amp; verified</span>
                  <span className="badge badge-neutral">{run.summary.stillOpen} still open</span>
                  {run.summary.reopened > 0 && <span className="badge badge-danger">{run.summary.reopened} reopened</span>}
                  {run.summary.gate && <span className={`badge badge-${run.summary.gate === 'PASS' ? 'success' : 'danger'}`}>Gate {run.summary.gate}</span>}
                </div>
              )}
            </div>
            <StageList stages={run.stages || []} />
          </div>
        )}

        {runs.length > 0 && (
          <div className="card col-12">
            <h3>Run history</h3>
            <table className="table">
              <thead><tr><th>Run</th><th>Type</th><th>Status</th><th>Started</th><th>Tools</th><th>New</th><th>Fixed</th><th>Still open</th><th>Open security</th><th>Gate</th></tr></thead>
              <tbody>
                {runs.map(r => (
                  <tr key={r.id} onClick={() => setRun(r)} style={{ cursor: 'pointer' }}>
                    <td>#{r.id}</td>
                    <td>{r.trigger === 'single' ? 'single tool' : 'pipeline'}</td>
                    <td><span className={`badge badge-${r.status === 'completed' ? 'success' : r.status === 'running' ? 'info' : 'danger'}`}>{r.status}</span></td>
                    <td style={{ fontSize: 12 }}>{r.started_at}</td>
                    <td style={{ fontSize: 12 }}>{r.tools.join(', ')}</td>
                    <td>{r.summary?.new ?? '—'}</td>
                    <td>{r.summary?.fixed ?? '—'}</td>
                    <td>{r.summary?.stillOpen ?? '—'}</td>
                    <td>{r.summary?.open ?? '—'}</td>
                    <td>{r.summary?.gate ? <span className={`badge badge-${r.summary.gate === 'PASS' ? 'success' : 'danger'}`}>{r.summary.gate}</span> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Layout>
  );
}
