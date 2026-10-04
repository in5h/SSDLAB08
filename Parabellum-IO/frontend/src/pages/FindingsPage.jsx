import { useCallback, useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import FixPlan from '../components/FixPlan';

const RISK_BADGE = { Critical: 'danger', High: 'danger', Medium: 'warning', Low: 'neutral', Info: 'neutral' };
const STATUS_BADGE = { 'Open': 'danger', 'In Progress': 'warning', 'Fixed': 'info', 'Verified Fixed': 'success', 'Accepted Risk': 'neutral', 'False Positive': 'neutral' };
const CONF_BADGE = { High: 'success', Medium: 'warning', Low: 'neutral' };
const pre = { margin: 0, fontFamily: 'Consolas, monospace', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px' };
const h4 = { margin: '14px 0 6px', fontSize: 13, textTransform: 'uppercase', letterSpacing: '.04em', color: 'var(--muted)' };

function Details({ f, projectId, statuses, onSaved }) {
  const [form, setForm] = useState({ status: f.status, owner: f.owner || '', due_date: f.due_date || '', triage_note: f.triage_note || '' });
  const [msg, setMsg] = useState('');
  const [history, setHistory] = useState([]);
  useEffect(() => {
    apiFetch(`/api/findings/${projectId}/${f.id}/history`).then(r => r.json()).then(d => Array.isArray(d) && setHistory(d)).catch(() => {});
  }, [projectId, f.id]);

  async function save() {
    setMsg('Saving…');
    const body = { ...form };
    if (body.due_date === f.due_date) delete body.due_date;   // keep the SLA date unless it was changed
    const r = await apiFetch(`/api/findings/${projectId}/${f.id}`, { method: 'PATCH', body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) { setMsg('❌ ' + d.error); return; }
    setMsg('✅ Saved');
    onSaved();
  }

  return (
    <div style={{ padding: '16px 18px', background: 'rgba(139,111,71,0.04)', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 22 }}>
        <div>
          <div style={{ fontSize: 14, lineHeight: 1.5, marginBottom: 8 }}>{f.message}</div>
          <div style={{ fontSize: 13, color: 'var(--muted)' }}>
            <div><strong>Tool:</strong> {f.tool}{f.corroboratedBy?.length ? ` — also found by ${f.corroboratedBy.join(', ')}` : ''} · <strong>Rule:</strong> {f.rule}{f.ruleName ? ` — ${f.ruleName}` : ''}</div>
            <div><strong>Weakness:</strong> {f.cwe} {f.cweName}</div>
            <div><strong>Location:</strong> {f.url || `${f.file || '—'}${f.line ? `:${f.line}` : ''}`}</div>
            {f.package_name && <div><strong>Package:</strong> {f.package_name} {f.installed_version} → fixed in {f.fixed_version || 'n/a'}</div>}
            <div><strong>Confidence:</strong> {f.confidence} ({f.confidenceScore}) — {f.confidenceReasons.join('; ')}</div>
            <div><strong>Risk:</strong> {f.risk} ({f.riskScore}/10, severity {f.severity})</div>
          </div>
          {f.description && <><div style={h4}>Explanation</div><div style={{ fontSize: 13, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{f.description}</div></>}
          {f.evidence && <><div style={h4}>Code evidence</div><pre style={pre}>{f.evidence}</pre></>}
          {f.recommendation && <>
            <div style={h4}>Recommendation (RAG)</div>
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>{f.recommendation}</div>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 4 }}>Source: {f.rec_source}</div>
          </>}
          <FixPlan plan={f.fixPlan} title={f.status === 'Verified Fixed' ? 'Fix (verified by rescan)' : 'Recommended fix'} verified={f.status === 'Verified Fixed'} />
          {f.references?.length > 0 && <div style={{ fontSize: 12, marginTop: 8 }}><strong>References:</strong> {f.references.map(r => <div key={r}><a href={r} target="_blank" rel="noreferrer">{r}</a></div>)}</div>}
          {f.mappings && <>
            <div style={h4}>Framework mappings</div>
            <table className="table" style={{ fontSize: 12 }}>
              <tbody>
                {Object.values(f.mappings.frameworks).map(m => (
                  <tr key={m.label}><td style={{ width: 130, fontWeight: 600 }}>{m.label}</td><td>{m.controls.map(c => `${c.id} ${c.title}`).join(' · ')}</td></tr>
                ))}
                {f.mappings.owaspTop10?.length > 0 && <tr><td style={{ fontWeight: 600 }}>OWASP Top 10</td><td>{f.mappings.owaspTop10.map(o => `${o.id} ${o.name}`).join(' · ')}</td></tr>}
                {f.mappings.mitre?.length > 0 && <tr><td style={{ fontWeight: 600 }}>MITRE ATT&amp;CK</td><td>{f.mappings.mitre.map(o => `${o.id} ${o.name}`).join(' · ')}</td></tr>}
              </tbody>
            </table>
            <div style={{ fontSize: 11, color: 'var(--muted)' }}>Retrieved with: {f.mappings.retrieval}</div>
          </>}
        </div>
        <div>
          <div style={h4}>Triage &amp; ownership</div>
          <div className="field"><label>Status</label>
            <select className="input" value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
              {statuses.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="field"><label>Risk owner</label><input className="input" value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })} /></div>
          <div className="field"><label>Due date {f.dueDateSource === 'SLA' ? '(from SLA)' : '(set manually)'}</label><input className="input" type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })} /></div>
          <div className="field"><label>Note (why False Positive / Accepted Risk, fix details…)</label>
            <textarea className="input" rows={3} value={form.triage_note} onChange={e => setForm({ ...form, triage_note: e.target.value })} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button className="btn btn-primary" onClick={save}>Save</button>
            <span style={{ fontSize: 12, color: 'var(--muted)' }}>{msg}</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 8 }}>
            &quot;False Positive&quot; and &quot;Accepted Risk&quot; are remembered: the finding stays suppressed in later scans.
            Mark it &quot;Fixed&quot; after you change the code — the next pipeline run verifies it.
          </div>
          <div style={h4}>History</div>
          <div style={{ fontSize: 12 }}>
            {history.map((h, i) => (
              <div key={i} style={{ borderLeft: '2px solid var(--border)', paddingLeft: 8, marginBottom: 6 }}>
                <strong>{h.event}</strong>{h.run_id ? ` · run #${h.run_id}` : ''} · {h.at}<br />
                <span style={{ color: 'var(--muted)' }}>{h.detail}{h.actor && h.actor !== 'pipeline' ? ` (${h.actor})` : ''}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
Details.propTypes = { f: PropTypes.object.isRequired, projectId: PropTypes.string.isRequired, statuses: PropTypes.array.isRequired, onSaved: PropTypes.func.isRequired };

export default function FindingsPage() {
  const [projects, setProjects] = useState([]);
  const [selId, setSelId] = useState('');
  const [data, setData] = useState({ findings: [], statuses: [] });
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(() => new Set());
  const toggle = id => setOpen(s => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const [filters, setFilters] = useState({ status: 'active', risk: '', tool: '', confidence: '', category: 'Security', q: '', hideDup: true });

  useEffect(() => {
    apiFetch('/api/projects').then(r => r.json()).then(d => {
      if (Array.isArray(d)) { setProjects(d); setSelId(s => s || (d[0] ? String(d[0].id) : '')); }
    });
  }, []);

  const load = useCallback(() => {
    if (!selId) return;
    setLoading(true);
    apiFetch(`/api/findings/${selId}`).then(r => r.json()).then(d => { if (d.findings) setData(d); }).finally(() => setLoading(false));
  }, [selId]);
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => data.findings
    .filter(f => filters.status === 'active' ? ['Open', 'In Progress'].includes(f.status) : !filters.status || f.status === filters.status)
    .filter(f => !filters.risk || f.risk === filters.risk)
    .filter(f => !filters.tool || f.tool === filters.tool)
    .filter(f => !filters.confidence || f.confidence === filters.confidence)
    .filter(f => !filters.category || f.category === filters.category)
    .filter(f => !filters.hideDup || !f.duplicateOf)
    .filter(f => !filters.q || `${f.title} ${f.message} ${f.file} ${f.cwe} ${f.package_name}`.toLowerCase().includes(filters.q.toLowerCase()))
    .sort((a, b) => b.riskScore - a.riskScore), [data, filters]);

  const tools = [...new Set(data.findings.map(f => f.tool))];
  const count = (pred) => data.findings.filter(pred).length;
  const setF = (k, v) => setFilters(f => ({ ...f, [k]: v }));

  return (
    <Layout title="Findings">
      <div className="content-grid">
        <div className="card col-12" style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="field" style={{ minWidth: 240, margin: 0 }}>
            <label>Project</label>
            <select className="input" value={selId} onChange={e => { setSelId(e.target.value); setOpen(new Set()); }}>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </div>
          <div className="field" style={{ margin: 0 }}><label>Status</label>
            <select className="input" value={filters.status} onChange={e => setF('status', e.target.value)}>
              <option value="active">Open + In Progress</option><option value="">All</option>
              {data.statuses.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="field" style={{ margin: 0 }}><label>Risk</label>
            <select className="input" value={filters.risk} onChange={e => setF('risk', e.target.value)}>
              <option value="">All</option>{['Critical', 'High', 'Medium', 'Low', 'Info'].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div className="field" style={{ margin: 0 }}><label>Tool</label>
            <select className="input" value={filters.tool} onChange={e => setF('tool', e.target.value)}>
              <option value="">All</option>{tools.map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div className="field" style={{ margin: 0 }}><label>Confidence</label>
            <select className="input" value={filters.confidence} onChange={e => setF('confidence', e.target.value)}>
              <option value="">All</option>{['High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div className="field" style={{ margin: 0 }}><label>Category</label>
            <select className="input" value={filters.category} onChange={e => setF('category', e.target.value)}>
              <option value="">All</option><option>Security</option><option>Code Quality</option>
            </select>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--muted)', height: 40 }}>
            <input type="checkbox" checked={filters.hideDup} onChange={e => setF('hideDup', e.target.checked)} /> Merge duplicates across tools
          </label>
          <div className="field" style={{ flex: 1, minWidth: 160, margin: 0 }}><label>Search</label>
            <input className="input" placeholder="title, file, CWE, package…" value={filters.q} onChange={e => setF('q', e.target.value)} />
          </div>
        </div>

        <div className="card col-12">
          <div className="stat-grid">
            {[
              ['Open security', count(f => f.category === 'Security' && ['Open', 'In Progress'].includes(f.status) && !f.duplicateOf), 'danger'],
              ['High confidence', count(f => f.category === 'Security' && ['Open', 'In Progress'].includes(f.status) && f.confidence === 'High'), 'primary'],
              ['Confirmed by 2+ tools', count(f => ['Open', 'In Progress'].includes(f.status) && f.corroboratedBy.length > 0 && !f.duplicateOf), 'info'],
              ['Duplicates merged', count(f => !!f.duplicateOf), 'muted'],
              ['Verified fixed', count(f => f.status === 'Verified Fixed'), 'success'],
              ['False positives', count(f => f.status === 'False Positive'), 'muted'],
            ].map(([l, n, c]) => (
              <div key={l} className="stat-card"><div className="stat-num" style={{ color: `var(--${c})` }}>{n}</div><div className="stat-label">{l}</div></div>
            ))}
          </div>
        </div>

        <div className="card col-12">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>{rows.length} findings {loading && <span className="spinner" style={{ borderTopColor: 'var(--primary)' }} />}</h3>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>Click a row for evidence, explanation, mappings, recommended fix and history.</span>
              <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => setOpen(open.size ? new Set() : new Set(rows.slice(0, 50).map(f => f.id)))}>{open.size ? 'Collapse all' : 'Expand all'}</button>
            </div>
          </div>
          {data.findings.length === 0 && !loading && (
            <p style={{ color: 'var(--muted)' }}>No findings yet — run the <a href="/pipeline">Pipeline</a> or a scan on the Security Scans page.</p>
          )}
          <table className="table" style={{ marginTop: 10 }}>
            <thead><tr><th></th><th>Risk</th><th>Finding</th><th>Tool</th><th>Location</th><th>Confidence</th><th>Owner</th><th>Status</th><th>Due</th></tr></thead>
            <tbody>
              {rows.map(f => [
                <tr key={f.id} onClick={() => toggle(f.id)} style={{ cursor: 'pointer', background: open.has(f.id) ? 'rgba(139,111,71,0.06)' : undefined }}>
                  <td style={{ color: 'var(--muted)' }}>{open.has(f.id) ? '▾' : '▸'}</td>
                  <td><span className={`badge badge-${RISK_BADGE[f.risk]}`}>{f.risk}</span></td>
                  <td style={{ maxWidth: 340, ...(open.has(f.id) ? {} : { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }) }}>{f.title}</td>
                  <td style={{ fontSize: 12 }}>{f.tool}{f.corroboratedBy.length ? ` +${f.corroboratedBy.length}` : ''}{f.duplicateOf ? <span className="badge badge-neutral" style={{ marginLeft: 4 }}>duplicate</span> : null}</td>
                  <td style={{ fontSize: 11, color: 'var(--muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.url || f.package_name || `${f.file || '—'}${f.line ? `:${f.line}` : ''}`}</td>
                  <td><span className={`badge badge-${CONF_BADGE[f.confidence]}`}>{f.confidence}</span></td>
                  <td style={{ fontSize: 12 }}>{f.owner || '—'}</td>
                  <td><span className={`badge badge-${STATUS_BADGE[f.status]}`}>{f.status}</span></td>
                  <td style={{ fontSize: 12, color: f.due_date && f.due_date < new Date().toISOString().slice(0, 10) && ['Open', 'In Progress'].includes(f.status) ? 'var(--danger)' : 'var(--muted)' }}>{f.due_date || '—'}</td>
                </tr>,
                open.has(f.id) && (
                  <tr key={`${f.id}-d`}><td colSpan={9} style={{ padding: 0 }}>
                    <Details f={f} projectId={selId} statuses={data.statuses} onSaved={load} />
                  </td></tr>
                ),
              ])}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
