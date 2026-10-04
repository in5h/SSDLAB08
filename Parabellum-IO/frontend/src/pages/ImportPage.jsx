import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

export default function ImportPage() {
  const [projects, setProjects] = useState([]);
  const [repoUrl, setRepoUrl] = useState('');
  const [zipFile, setZipFile] = useState(null);
  const [localName, setLocalName] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [status, setStatus] = useState({ github:'', zip:'', local:'' });
  const [loading, setLoading] = useState({github:false,zip:false,local:false});

  useEffect(() => { loadProjects(); }, []);

  async function loadProjects() {
    try {
      const res = await apiFetch('/api/projects');
      const data = await res.json();
      setProjects(Array.isArray(data) ? data : []);
    } catch (err) { console.error(err); }
  }

  async function importGithub() {
    if (!repoUrl.trim()) { setStatus(s=>({...s,github:'⚠ Please enter a repo URL.'})); return; }
    setLoading(l=>({...l,github:true}));
    setStatus(s=>({...s,github:'⏳ Cloning repository…'}));
    try {
      const res = await apiFetch('/api/projects/github/import', { method:'POST', body: JSON.stringify({repoUrl}) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus(s=>({...s,github:`✅ Imported: ${data.name} (ID: ${data.id})`}));
      setRepoUrl('');
      loadProjects();
    } catch (err) { setStatus(s=>({...s,github:'❌ '+err.message})); }
    finally { setLoading(l=>({...l,github:false})); }
  }

  async function uploadZip(e) {
    e.preventDefault();
    if (!zipFile) { setStatus(s=>({...s,zip:'⚠ Select a ZIP file first.'})); return; }
    setLoading(l=>({...l,zip:true}));
    setStatus(s=>({...s,zip:'⏳ Uploading…'}));
    const fd = new FormData();
    fd.append('project', zipFile);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('/api/projects/upload', { method:'POST', headers: token ? {Authorization:'Bearer '+token}:{}, body:fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus(s=>({...s,zip:`✅ Uploaded: ${data.name} (ID: ${data.id})`}));
      setZipFile(null);
      loadProjects();
    } catch (err) { setStatus(s=>({...s,zip:'❌ '+err.message})); }
    finally { setLoading(l=>({...l,zip:false})); }
  }

  async function registerLocal() {
    if (!localName || !localPath) { setStatus(s=>({...s,local:'⚠ Enter both name and path.'})); return; }
    setLoading(l=>({...l,local:true}));
    setStatus(s=>({...s,local:'⏳ Checking path…'}));
    try {
      const res = await apiFetch('/api/projects/local', { method:'POST', body: JSON.stringify({name:localName,localPath}) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setStatus(s=>({...s,local:`✅ Registered: ${data.name} (ID: ${data.id})`}));
      setLocalName(''); setLocalPath('');
      loadProjects();
    } catch (err) { setStatus(s=>({...s,local:'❌ '+err.message})); }
    finally { setLoading(l=>({...l,local:false})); }
  }

  async function deleteProject(id) {
    if (!confirm('Remove this project and its scan results? Uploaded/cloned copies are deleted; registered local folders on your disk are NOT touched.')) return;
    await apiFetch(`/api/projects/${id}`, { method:'DELETE' });
    loadProjects();
  }

  return (
    <Layout title="Project Import">
      <div className="content-grid">
        <div className="card col-8" style={{display:'flex',flexDirection:'column',gap:'20px'}}>
          <div>
            <h3>Import from GitHub</h3>
            <div style={{display:'flex',gap:'8px',marginTop:'12px'}}>
              <input className="input" style={{flex:1}} placeholder="https://github.com/owner/repo-name" value={repoUrl} onChange={e=>setRepoUrl(e.target.value)} />
              <button className="btn btn-primary" onClick={importGithub} disabled={loading.github}>
                {loading.github ? <><span className="spinner"/> Cloning…</> : '🐙 Import'}
              </button>
            </div>
            {status.github && <div style={{marginTop:'8px',fontSize:'13px',color: status.github.startsWith('✅') ? 'var(--success)' : status.github.startsWith('❌') ? 'var(--danger)' : 'var(--muted)'}}>{status.github}</div>}
          </div>

          <hr style={{border:'none',borderTop:'1px solid var(--border)'}} />

          <div>
            <h3>Upload ZIP Archive</h3>
            <form onSubmit={uploadZip} style={{display:'flex',gap:'8px',alignItems:'center',marginTop:'12px'}}>
              <label style={{flex:1,padding:'10px 14px',borderRadius:'10px',border:'1.5px dashed var(--border)',cursor:'pointer',fontSize:'13px',color:'var(--muted)',textAlign:'center',background:'var(--bg)'}}>
                <input type="file" accept=".zip" style={{display:'none'}} onChange={e=>setZipFile(e.target.files[0])} />
                {zipFile ? `📦 ${zipFile.name}` : '📁 Click to choose a ZIP file'}
              </label>
              <button className="btn btn-primary" type="submit" disabled={loading.zip}>
                {loading.zip ? <><span className="spinner"/> Uploading…</> : 'Upload'}
              </button>
            </form>
            {status.zip && <div style={{marginTop:'8px',fontSize:'13px',color: status.zip.startsWith('✅') ? 'var(--success)' : status.zip.startsWith('❌') ? 'var(--danger)' : 'var(--muted)'}}>{status.zip}</div>}
          </div>

          <hr style={{border:'none',borderTop:'1px solid var(--border)'}} />

          <div>
            <h3>📂 Register Local Server Folder</h3>
            <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'12px'}}>Enter a folder path on this server machine to register it without uploading.</p>
            <div className="local-panel">
              <div style={{display:'flex',flexDirection:'column',gap:'8px'}}>
                <input className="input" placeholder="Project name (e.g. my-api)" value={localName} onChange={e=>setLocalName(e.target.value)} />
                <input className="input" placeholder="Full folder path (e.g. D:\Projects\my-api)" value={localPath} onChange={e=>setLocalPath(e.target.value)} />
                <div style={{display:'flex',gap:'8px',alignItems:'center'}}>
                  <button className="btn btn-secondary" onClick={registerLocal} disabled={loading.local}>
                    {loading.local ? <><span className="spinner" style={{borderTopColor:'var(--text)'}}/> Registering…</> : '+ Register & Add to List'}
                  </button>
                  {status.local && <span style={{fontSize:'13px',color: status.local.startsWith('✅') ? 'var(--success)' : status.local.startsWith('❌') ? 'var(--danger)' : 'var(--muted)'}}>{status.local}</span>}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card col-4">
          <h3>How It Works</h3>
          <div style={{fontSize:'13px',color:'var(--muted)',lineHeight:'2'}}>
            <div>🔗 <strong>GitHub URL</strong> — metadata fetched via GitHub API, repo shallow-cloned for scanning.</div>
            <br/>
            <div>📦 <strong>ZIP Upload</strong> — archive extracted server-side. No code leaves your environment.</div>
            <br/>
            <div>📂 <strong>Local Path</strong> — for projects already on the server, register the path directly.</div>
            <br/>
            <div style={{padding:'12px',background:'rgba(139,111,71,0.07)',borderRadius:'10px',border:'1px solid var(--border)'}}>
              After importing, go to <a href="/scan" style={{color:'var(--primary)',fontWeight:600}}>SonarQube Scan →</a> to run a security analysis.
            </div>
          </div>
        </div>

        <div className="card col-12">
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'14px'}}>
            <h3 style={{margin:0}}>Imported Projects</h3>
            <button className="btn btn-ghost" onClick={loadProjects} style={{fontSize:'13px'}}>↻ Refresh</button>
          </div>
          {projects.length === 0 ? (
            <div style={{textAlign:'center',padding:'40px',color:'var(--muted)',fontSize:'14px'}}>
              No projects yet. Import one above.
            </div>
          ) : (
            <table className="table">
              <thead><tr><th>Project</th><th>Type</th><th>Imported</th><th>Actions</th></tr></thead>
              <tbody>
                {projects.map(p => (
                  <tr key={p.id}>
                    <td><strong>{p.name}</strong><div style={{fontSize:'11px',color:'var(--muted)'}}>ID: {p.id}</div></td>
                    <td><span className="badge badge-neutral">{p.sourceType === 'github' ? '🐙 GitHub' : p.sourceType === 'local' ? '📂 Local' : '📦 Upload'}</span></td>
                    <td style={{color:'var(--muted)',fontSize:'12px'}}>{p.createdAt ? new Date(p.createdAt).toLocaleString() : '—'}</td>
                    <td>
                      <a href={`/scan?projectId=${p.id}`} className="btn btn-primary" style={{fontSize:'12px',marginRight:'6px',textDecoration:'none'}}>🔍 Scan</a>
                      <button className="btn btn-danger" style={{fontSize:'12px'}} onClick={()=>deleteProject(p.id)}>🗑</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Layout>
  );
}
