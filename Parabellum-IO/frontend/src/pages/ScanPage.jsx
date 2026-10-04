import { useState, useEffect, useCallback } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import { toolState } from '../services/toolStatus';
import IssueDetails from '../components/IssueDetails';

// ── Shared Components ─────────────────────────────────────────────
function StageRow({ state, label, msg }) {
  return (
    <div className={`scan-stage ${state}`}>
      <div className="stage-dot" />
      <div>
        <div style={{fontWeight:600,fontSize:'13px'}}>{label}</div>
        <div style={{fontSize:'12px',color:'var(--muted)',marginTop:'2px'}}>{msg}</div>
      </div>
    </div>
  );
}

function ProjectSelector({ projects, selectedId, setSelectedId, loading }) {
  return (
    <div className="field">
      <label>Select Project</label>
      <select className="input" value={selectedId} onChange={e=>setSelectedId(e.target.value)} disabled={loading}>
        <option value="">— Choose a project —</option>
        {projects.map(p => (
          <option key={p.id} value={p.id}>
            {p.sourceType==='github'?'🐙':p.sourceType==='local'?'📂':'📦'} {p.name} (ID: {p.id})
          </option>
        ))}
      </select>
    </div>
  );
}

function IssuesTable({ issues, title, columns }) {
  const [sevFilter, setSevFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [open, setOpen] = useState(() => new Set());
  const [showAll, setShowAll] = useState(false);
  const filtered = issues.filter(i =>
    (!sevFilter || i.severity === sevFilter) && (!typeFilter || i.type === typeFilter)
  );
  const sevs = [...new Set(issues.map(i=>i.severity))].sort();
  const types = [...new Set(issues.map(i=>i.type))].sort();
  const toggle = k => setOpen(s => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const shown = showAll ? filtered : filtered.slice(0, 100);
  const cols = columns || ['Severity','Type','Message','File','Line'];

  return (
    <div className="card col-12">
      <div style={{display:'flex',gap:'10px',alignItems:'center',marginBottom:'14px',flexWrap:'wrap'}}>
        <h3 style={{margin:0,flex:1}}>{title} ({issues.length})</h3>
        <button className="btn btn-ghost" style={{fontSize:12}} onClick={() => setOpen(open.size ? new Set() : new Set(shown.map((iss,i)=>iss.key||i)))}>
          {open.size ? 'Collapse all' : 'Expand all'}
        </button>
        <select className="input" style={{width:'auto'}} value={sevFilter} onChange={e=>setSevFilter(e.target.value)}>
          <option value="">All Severities</option>
          {sevs.map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input" style={{width:'auto'}} value={typeFilter} onChange={e=>setTypeFilter(e.target.value)}>
          <option value="">All Types</option>
          {types.map(t=><option key={t} value={t}>{t}</option>)}
        </select>
      </div>
      <div style={{fontSize:12,color:'var(--muted)',marginBottom:8}}>Click a row to see the full finding, code evidence and the recommended fix. All results are also saved to Findings and the Final Report.</div>
      <table className="table">
        <thead><tr><th style={{width:24}}></th>{cols.map(h=><th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {shown.map((iss,i)=>{
            const k = iss.key||i;
            const isOpen = open.has(k);
            return [
              <tr key={k} onClick={()=>toggle(k)} style={{cursor:'pointer',background:isOpen?'rgba(139,111,71,0.06)':undefined}} title="Click to expand">
                <td style={{color:'var(--muted)',fontSize:12}}>{isOpen?'▾':'▸'}</td>
                <td><span className={`badge badge-${['CRITICAL','BLOCKER'].includes(iss.severity)?'danger':iss.severity==='MAJOR'?'warning':'neutral'}`}>{iss.severity}</span></td>
                <td><span className="badge badge-neutral">{iss.type}</span></td>
                <td style={{maxWidth:'360px',...(isOpen?{whiteSpace:'normal'}:{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'})}}>{iss.message}</td>
                <td style={{fontSize:'11px',color:'var(--muted)',maxWidth:180,...(isOpen?{whiteSpace:'normal',wordBreak:'break-all'}:{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'})}}>{iss.component}</td>
                <td style={{fontSize:'11px',color:'var(--muted)'}}>{iss.line||'—'}</td>
              </tr>,
              isOpen && (
                <tr key={`${k}-d`}><td colSpan={cols.length + 1} style={{padding:0}}><IssueDetails issue={iss} /></td></tr>
              ),
            ];
          })}
        </tbody>
      </table>
      {filtered.length > 100 && !showAll && (
        <div style={{textAlign:'center',padding:'12px'}}>
          <button className="btn btn-ghost" onClick={()=>setShowAll(true)}>Show all {filtered.length} results</button>
        </div>
      )}
    </div>
  );
}

function StatCards({ items }) {
  return (
    <div style={{display:'grid',gridTemplateColumns:`repeat(${items.length},1fr)`,gap:'8px'}}>
      {items.map(({label,count,color})=>(
        <div key={label} style={{background:'var(--bg)',borderRadius:'10px',padding:'12px',textAlign:'center',border:'1px solid var(--border)'}}>
          <div style={{fontSize:'22px',fontWeight:800,color}}>{count}</div>
          <div style={{fontSize:'11px',color:'var(--muted)',marginTop:'2px'}}>{label}</div>
        </div>
      ))}
    </div>
  );
}

// ── SonarQube Tab ─────────────────────────────────────────────────
function SonarQubeTab({ projects, selectedId, setSelectedId }) {
  const [localName, setLocalName] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [localStatus, setLocalStatus] = useState('');
  const [scanning, setScanning] = useState(false);
  const [stages, setStages] = useState({ create:{state:'',msg:'Waiting…'}, scan:{state:'',msg:'Waiting…'}, results:{state:'',msg:'Waiting…'} });
  const [issues, setIssues] = useState([]);
  const [qualityGate, setQualityGate] = useState(null);
  const [lastProjectKey, setLastProjectKey] = useState('');

  function setStage(id, state, msg) { setStages(s => ({...s, [id]:{state,msg}})); }

  async function registerLocal() {
    if (!localName||!localPath) { setLocalStatus('⚠ Enter both.'); return; }
    setLocalStatus('⏳ Checking…');
    try {
      const res = await apiFetch('/api/projects/local', {method:'POST',body:JSON.stringify({name:localName,localPath})});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setLocalStatus(`✅ Registered: ${data.name}`);
      setLocalName(''); setLocalPath('');
      setSelectedId(String(data.id));
      window.dispatchEvent(new Event('projects-changed'));
    } catch (err) { setLocalStatus('❌ '+err.message); }
  }

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setIssues([]); setQualityGate(null); setLastProjectKey('');
    ['create','scan','results'].forEach(s => setStage(s, '', 'Waiting…'));
    setStage('create','active','Creating SonarQube project…');
    setStage('scan','active','Running sonar-scanner (1–3 min)…');
    try {
      const res = await apiFetch(`/api/sonar/scan/${selectedId}`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) { setStage('scan','failed', data.error||'Scan failed'); return; }
      setStage('create','done','✅ Project ready'); setStage('scan','done','✅ Scan completed');
      setStage('results','active','Fetching issues…');
      // The scan response already contains every issue with rule guidance and a recommended fix
      let all = data.issues;
      if (!Array.isArray(all)) {
        const issRes = await apiFetch(`/api/sonar/issues/${data.projectKey}?pageSize=500`);
        all = (await issRes.json()).issues || [];
      }
      const qgRes = await apiFetch(`/api/sonar/quality-gate/${data.projectKey}`);
      const qgData = qgRes.ok ? await qgRes.json() : null;
      setIssues(all); setQualityGate(qgData); setLastProjectKey(data.projectKey);
      setStage('results','done',`✅ ${all.length} issues found — click a row for the explanation and recommended fix`);
    } catch (err) { setStage('scan','failed', err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'18px'}}>
        <div>
          <h3>📂 Register Local Project Folder</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'10px'}}>Enter a folder path on this server to scan it directly.</p>
          <div className="local-panel">
            <div style={{display:'flex',flexDirection:'column',gap:'8px'}}>
              <input className="input" placeholder="Project name" value={localName} onChange={e=>setLocalName(e.target.value)} />
              <input className="input" placeholder={`Full path (e.g. D:\\Projects\\my-app)`} value={localPath} onChange={e=>setLocalPath(e.target.value)} />
              <div style={{display:'flex',gap:'8px',alignItems:'center'}}>
                <button className="btn btn-secondary" onClick={registerLocal}>+ Register &amp; Select</button>
                {localStatus && <span style={{fontSize:'12px',color:localStatus.startsWith('✅')?'var(--success)':localStatus.startsWith('❌')?'var(--danger)':'var(--muted)'}}>{localStatus}</span>}
              </div>
            </div>
          </div>
        </div>
        <div>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px'}}>
            {scanning ? <><span className="spinner"/> Scanning…</> : '🔍 Start SonarQube Scan'}
          </button>
        </div>
        <div>
          <div style={{fontSize:'11px',textTransform:'uppercase',letterSpacing:'.05em',color:'var(--muted)',fontWeight:600,marginBottom:'10px'}}>Pipeline Progress</div>
          <div style={{display:'flex',flexDirection:'column',gap:'8px'}}>
            <StageRow {...stages.create} label="1. Create Project" />
            <StageRow {...stages.scan} label="2. Run Scanner" />
            <StageRow {...stages.results} label="3. Fetch Results" />
          </div>
        </div>
      </div>
      <div className="card col-4" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>Quality Gate</h3>
          {qualityGate ? (
            <div style={{textAlign:'center',padding:'16px 0'}}>
              <div style={{fontSize:'22px',fontWeight:800,color:qualityGate.status==='OK'?'var(--success)':'var(--danger)'}}>
                {qualityGate.status==='OK'?'✅ PASSED':'❌ FAILED'}
              </div>
            </div>
          ) : (
            <div style={{textAlign:'center',padding:'30px 0',color:'var(--muted)',fontSize:'13px'}}>
              <div style={{fontSize:'40px',opacity:.2}}>🛡</div>Run a scan to see results
            </div>
          )}
        </div>
        <StatCards items={[
          {label:'Bugs',count:issues.filter(i=>i.type==='BUG').length,color:'var(--danger)'},
          {label:'Vulns',count:issues.filter(i=>i.type==='VULNERABILITY').length,color:'var(--warning)'},
          {label:'Smells',count:issues.filter(i=>i.type==='CODE_SMELL').length,color:'var(--muted)'},
        ]} />
        {lastProjectKey && (
          <div style={{background:'rgba(139,111,71,0.06)',border:'1px solid var(--border)',borderRadius:10,padding:'12px',fontSize:'13px',textAlign:'center'}}>
            <a href="/compliance" style={{color:'var(--primary)',fontWeight:600,textDecoration:'none'}}>📊 Open Compliance Mapping →</a>
          </div>
        )}
      </div>
      {issues.length > 0 && <IssuesTable issues={issues} title="SonarQube Issues" />}
    </div>
  );
}

// ── Semgrep Tab ───────────────────────────────────────────────────
function SemgrepTab({ projects, selectedId, setSelectedId }) {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setResult(null); setError('');
    try {
      const res = await apiFetch(`/api/tools/semgrep/scan/${selectedId}`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Semgrep scan failed');
      setResult(data);
    } catch (err) { setError(err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>🔎 Semgrep SAST Scan</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            Semgrep performs static analysis using pattern-matching rules to find security vulnerabilities, bugs, and anti-patterns in your source code.
          </p>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px',background:'#6366f1',borderColor:'#6366f1'}}>
            {scanning ? <><span className="spinner"/> Running Semgrep…</> : '🔎 Run Semgrep Scan'}
          </button>
        </div>
        {scanning && (
          <div style={{textAlign:'center',padding:'30px',color:'var(--muted)'}}>
            <div style={{fontSize:'36px',marginBottom:'10px'}}>⏳</div>
            <div>Running Semgrep analysis… This may take 1–5 minutes depending on project size.</div>
          </div>
        )}
        {error && <div style={{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#dc2626',padding:'14px',borderRadius:10,fontSize:'13px'}}>❌ {error}</div>}
        {result?.warning && <div style={{background:'rgba(245,158,11,0.08)',border:'1px solid rgba(245,158,11,0.35)',color:'#b45309',padding:'14px',borderRadius:10,fontSize:'13px'}}>⚠️ {result.warning}</div>}
      </div>
      <div className="card col-4">
        <h3>About Semgrep</h3>
        <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:1.8}}>
          <div><strong>Type:</strong> SAST (Static Analysis)</div>
          <div><strong>Languages:</strong> JS, Python, Java, Go, Ruby, C, etc.</div>
          <div><strong>Rules:</strong> Auto-config (2000+ community rules)</div>
          <div style={{marginTop:'12px',padding:'10px',background:'rgba(99,102,241,0.06)',borderRadius:8,border:'1px solid rgba(99,102,241,0.15)'}}>
            Semgrep finds bugs and security issues using lightweight pattern-matching — no compilation required.
          </div>
        </div>
        {result && (
          <div style={{marginTop:'16px'}}>
            <StatCards items={[
              {label:'Total',count:result.total,color:'var(--primary)'},
              {label:'Critical',count:result.summary?.CRITICAL||0,color:'var(--danger)'},
              {label:'Major',count:result.summary?.MAJOR||0,color:'var(--warning)'},
            ]} />
          </div>
        )}
      </div>
      {result?.issues?.length > 0 && <IssuesTable issues={result.issues} title="Semgrep Findings" />}
    </div>
  );
}

// ── Snyk Tab ──────────────────────────────────────────────────────
function SnykTab({ projects, selectedId, setSelectedId }) {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setResult(null); setError('');
    try {
      const res = await apiFetch(`/api/tools/snyk/scan/${selectedId}`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Snyk scan failed');
      setResult(data);
    } catch (err) { setError(err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>📦 Snyk SCA Scan</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            Snyk scans your project dependencies for known vulnerabilities (CVEs), license issues, and provides fix recommendations.
          </p>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px',background:'#8b5cf6',borderColor:'#8b5cf6'}}>
            {scanning ? <><span className="spinner"/> Running Snyk…</> : '📦 Run Snyk Scan'}
          </button>
        </div>
        {scanning && (
          <div style={{textAlign:'center',padding:'30px',color:'var(--muted)'}}>
            <div style={{fontSize:'36px',marginBottom:'10px'}}>⏳</div>
            <div>Running Snyk dependency analysis… This may take 1–3 minutes.</div>
          </div>
        )}
        {error && <div style={{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#dc2626',padding:'14px',borderRadius:10,fontSize:'13px'}}>❌ {error}</div>}
        {result?.warning && <div style={{background:'rgba(245,158,11,0.08)',border:'1px solid rgba(245,158,11,0.35)',color:'#b45309',padding:'14px',borderRadius:10,fontSize:'13px'}}>⚠️ {result.warning}</div>}
      </div>
      <div className="card col-4">
        <h3>About Snyk</h3>
        <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:1.8}}>
          <div><strong>Type:</strong> SCA (Software Composition Analysis)</div>
          <div><strong>Scans:</strong> package.json, pom.xml, requirements.txt</div>
          <div><strong>Database:</strong> Snyk Vulnerability DB (CVE/CWE)</div>
        </div>
        {result && (
          <div style={{marginTop:'16px'}}>
            <StatCards items={[
              {label:'Vulns',count:result.total,color:'var(--danger)'},
              {label:'Fixable',count:result.summary?.fixableCount||0,color:'var(--success)'},
              {label:'Packages',count:result.summary?.uniquePackages||0,color:'var(--primary)'},
            ]} />
          </div>
        )}
      </div>
      {result?.issues?.length > 0 && <IssuesTable issues={result.issues} title="Snyk Vulnerabilities" />}
    </div>
  );
}

// ── Trivy Tab ─────────────────────────────────────────────────────
function TrivyTab({ projects, selectedId, setSelectedId }) {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setResult(null); setError('');
    try {
      const res = await apiFetch(`/api/tools/trivy/scan/${selectedId}`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Trivy scan failed');
      setResult(data);
    } catch (err) { setError(err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>🐳 Trivy Container &amp; FS Scan</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            Trivy scans Dockerfiles, OS base images, and project filesystems for container misconfigurations and CVE vulnerabilities.
          </p>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px',background:'#0284c7',borderColor:'#0284c7'}}>
            {scanning ? <><span className="spinner"/> Running Trivy…</> : '🐳 Run Trivy Scan'}
          </button>
        </div>
        {scanning && (
          <div style={{textAlign:'center',padding:'30px',color:'var(--muted)'}}>
            <div style={{fontSize:'36px',marginBottom:'10px'}}>⏳</div>
            <div>Analyzing container layers and filesystem security…</div>
          </div>
        )}
        {error && <div style={{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#dc2626',padding:'14px',borderRadius:10,fontSize:'13px'}}>❌ {error}</div>}
        {result?.warning && <div style={{background:'rgba(245,158,11,0.08)',border:'1px solid rgba(245,158,11,0.35)',color:'#b45309',padding:'14px',borderRadius:10,fontSize:'13px'}}>⚠️ {result.warning}</div>}
      </div>
      <div className="card col-4">
        <h3>About Trivy</h3>
        <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:1.8}}>
          <div><strong>Type:</strong> Container &amp; FS Security</div>
          <div><strong>Targets:</strong> Dockerfiles, OS Layers, Lockfiles</div>
          <div><strong>Focus:</strong> Base image CVEs &amp; root execution</div>
        </div>
        {result && (
          <div style={{marginTop:'16px'}}>
            <StatCards items={[
              {label:'Total',count:result.total,color:'var(--primary)'},
              {label:'Critical',count:result.summary?.CRITICAL||0,color:'var(--danger)'},
              {label:'Major',count:result.summary?.MAJOR||0,color:'var(--warning)'},
            ]} />
          </div>
        )}
      </div>
      {result?.issues?.length > 0 && <IssuesTable issues={result.issues} title="Trivy Container & FS Findings" />}
    </div>
  );
}

// ── OWASP ZAP Tab ─────────────────────────────────────────────────
function ZapTab({ projects, selectedId, setSelectedId }) {
  const [scanning, setScanning] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [active, setActive] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setResult(null); setError('');
    try {
      const res = await apiFetch(`/api/tools/zap/scan/${selectedId}`, {method:'POST', body:JSON.stringify({targetUrl:targetUrl.trim(), active})});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'OWASP ZAP scan failed');
      setResult(data);
    } catch (err) { setError(err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>🌐 OWASP ZAP DAST Scan</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            OWASP ZAP crawls the running web application and reports missing security headers, cookie flags, CSRF, XSS and more. Start the app first and enter its URL.
          </p>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <div className="field">
            <label>Target URL (running app)</label>
            <input className="input" placeholder="http://localhost:3000" value={targetUrl} onChange={e=>setTargetUrl(e.target.value)} disabled={scanning} />
          </div>
          <label style={{display:'flex',gap:8,alignItems:'center',fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            <input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)} disabled={scanning} />
            Also run an active scan (sends attack payloads — only for apps you own; slower)
          </label>
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px',background:'#059669',borderColor:'#059669'}}>
            {scanning ? <><span className="spinner"/> Running OWASP ZAP…</> : '🌐 Run OWASP ZAP Scan'}
          </button>
        </div>
        {scanning && (
          <div style={{textAlign:'center',padding:'30px',color:'var(--muted)'}}>
            <div style={{fontSize:'36px',marginBottom:'10px'}}>⏳</div>
            <div>ZAP is crawling and scanning the target… (can take several minutes)</div>
          </div>
        )}
        {error && <div style={{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#dc2626',padding:'14px',borderRadius:10,fontSize:'13px'}}>❌ {error}</div>}
        {result?.warning && <div style={{background:'rgba(245,158,11,0.08)',border:'1px solid rgba(245,158,11,0.35)',color:'#b45309',padding:'14px',borderRadius:10,fontSize:'13px'}}>⚠️ {result.warning}</div>}
      </div>
      <div className="card col-4">
        <h3>About OWASP ZAP</h3>
        <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:1.8}}>
          <div><strong>Type:</strong> DAST (Dynamic Security Testing)</div>
          <div><strong>Needs:</strong> ZAP daemon running (ZAP_URL in backend/.env)</div>
          <div><strong>Focus:</strong> Headers, Cookies, CSRF, XSS, Injection</div>
          <div><strong>Standard:</strong> OWASP Top 10 Web / API</div>
        </div>
        {result && (
          <div style={{marginTop:'16px'}}>
            <StatCards items={[
              {label:'Alerts',count:result.total,color:'var(--primary)'},
              {label:'Critical',count:result.summary?.CRITICAL||0,color:'var(--danger)'},
              {label:'Major',count:result.summary?.MAJOR||0,color:'var(--warning)'},
            ]} />
          </div>
        )}
      </div>
      {result?.issues?.length > 0 && <IssuesTable issues={result.issues} title="OWASP ZAP DAST Alerts" />}
    </div>
  );
}

// ── Anchore Tab ───────────────────────────────────────────────────
function AnchoreTab({ projects, selectedId, setSelectedId }) {
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function startScan() {
    if (!selectedId) { alert('Select a project first.'); return; }
    setScanning(true); setResult(null); setError('');
    try {
      const res = await apiFetch(`/api/tools/anchore/scan/${selectedId}`, {method:'POST'});
      const data = await res.json();
      if (!res.ok) throw new Error(data.error||'Anchore scan failed');
      setResult(data);
    } catch (err) { setError(err.message); }
    finally { setScanning(false); }
  }

  return (
    <div className="content-grid">
      <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'16px'}}>
        <div>
          <h3>🛡️ Anchore Policy Engine</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>
            Anchore evaluates container images and repository configurations against security policies (CIS Docker Benchmarks &amp; Default Security Gates).
          </p>
          <ProjectSelector projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} loading={scanning} />
          <button className="btn btn-primary" onClick={startScan} disabled={scanning} style={{width:'100%',justifyContent:'center',padding:'12px',background:'#dc2626',borderColor:'#dc2626'}}>
            {scanning ? <><span className="spinner"/> Running Anchore…</> : '🛡️ Run Anchore Policy Scan'}
          </button>
        </div>
        {scanning && (
          <div style={{textAlign:'center',padding:'30px',color:'var(--muted)'}}>
            <div style={{fontSize:'36px',marginBottom:'10px'}}>⏳</div>
            <div>Evaluating container image policies &amp; compliance gates…</div>
          </div>
        )}
        {error && <div style={{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#dc2626',padding:'14px',borderRadius:10,fontSize:'13px'}}>❌ {error}</div>}
        {result?.warning && <div style={{background:'rgba(245,158,11,0.08)',border:'1px solid rgba(245,158,11,0.35)',color:'#b45309',padding:'14px',borderRadius:10,fontSize:'13px'}}>⚠️ {result.warning}</div>}
      </div>
      <div className="card col-4">
        <h3>About Anchore</h3>
        <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:1.8}}>
          <div><strong>Type:</strong> Container Policy Enforcement</div>
          <div><strong>Gates:</strong> Dockerfile, Base Image, Root User</div>
          <div><strong>Standard:</strong> CIS Benchmarks &amp; Policy Gates</div>
        </div>
        {result && (
          <div style={{marginTop:'16px'}}>
            <StatCards items={[
              {label:'Policy',count:result.summary?.policyStatus||'PASS',color:result.summary?.policyStatus?.includes('FAIL')?'var(--danger)':'var(--success)'},
              {label:'Stops',count:result.summary?.stopRulesTriggered||0,color:'var(--danger)'},
              {label:'Warnings',count:result.summary?.warnRulesTriggered||0,color:'var(--warning)'},
            ]} />
          </div>
        )}
      </div>
      {result?.issues?.length > 0 && <IssuesTable issues={result.issues} title="Anchore Policy Triggers" />}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────
const TABS = [
  { id:'sonarqube', label:'SonarQube', icon:'🔍', desc:'SAST', color:'#e97627' },
  { id:'semgrep',   label:'Semgrep',   icon:'🔎', desc:'SAST', color:'#6366f1' },
  { id:'snyk',      label:'Snyk',      icon:'📦', desc:'SCA',  color:'#8b5cf6' },
  { id:'trivy',     label:'Trivy',     icon:'🐳', desc:'Container', color:'#0284c7' },
  { id:'zap',       label:'OWASP ZAP', icon:'🌐', desc:'DAST', color:'#059669' },
  { id:'anchore',   label:'Anchore',   icon:'🛡️', desc:'Policy', color:'#dc2626' },
];

export default function ScanPage() {
  const [activeTab, setActiveTab] = useState('sonarqube');
  const [projects, setProjects] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [toolStatus, setToolStatus] = useState({});

  const loadProjects = useCallback(async () => {
    try {
      const res = await apiFetch('/api/projects');
      const data = await res.json();
      setProjects(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error('Failed to load projects:', err);
    }
  }, []);

  const loadToolStatus = useCallback(async () => {
    try {
      const res = await apiFetch('/api/tools/status');
      const data = await res.json();
      setToolStatus(data || {});
    } catch (err) {
      console.error('Failed to load tool status:', err);
    }
  }, []);

  useEffect(() => {
    /* eslint-disable-next-line react-hooks/set-state-in-effect */
    loadProjects();
    loadToolStatus();
  }, [loadProjects, loadToolStatus]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const pid = params.get('projectId');
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (pid) setSelectedId(pid);
  }, []);

  useEffect(() => {
    const handler = () => loadProjects();
    window.addEventListener('projects-changed', handler);
    return () => window.removeEventListener('projects-changed', handler);
  }, [loadProjects]);

  return (
    <Layout title="Security Scans">
      {/* ═══ Tab Bar ═══ */}
      <div style={{display:'flex',gap:4,background:'var(--panel)',padding:6,borderRadius:16,border:'1px solid var(--border)',marginBottom:20,flexWrap:'wrap'}}>
        {TABS.map(t => {
          const st = toolState(toolStatus[t.id]);
          return (
            <button key={t.id} onClick={()=>setActiveTab(t.id)} style={{
              padding:'10px 18px',borderRadius:12,border:'none',cursor:'pointer',
              fontSize:13,fontWeight:700,display:'flex',alignItems:'center',gap:6,
              background:activeTab===t.id?t.color:'transparent',
              color:activeTab===t.id?'#fff':'var(--muted)',
              transition:'all .2s',
              boxShadow:activeTab===t.id?`0 2px 12px ${t.color}40`:'none',
            }}>
              <span style={{fontSize:16}}>{t.icon}</span>
              {t.label}
              <span style={{fontSize:10,opacity:.8,padding:'2px 6px',borderRadius:8,
                background:activeTab===t.id?'rgba(255,255,255,0.2)':'rgba(0,0,0,0.06)'}}>{t.desc}</span>
              <span title={st.label} style={{width:8,height:8,borderRadius:'50%',
                background:st.dot,
                boxShadow:st.kind==='connected'?'0 0 6px #22c55e40':'none',
              }} />
            </button>
          );
        })}
      </div>

      {/* ═══ Tab Content ═══ */}
      {activeTab === 'sonarqube' && <SonarQubeTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
      {activeTab === 'semgrep' && <SemgrepTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
      {activeTab === 'snyk' && <SnykTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
      {activeTab === 'trivy' && <TrivyTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
      {activeTab === 'zap' && <ZapTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
      {activeTab === 'anchore' && <AnchoreTab projects={projects} selectedId={selectedId} setSelectedId={setSelectedId} />}
    </Layout>
  );
}
