import { useState, useEffect, useCallback } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [stats, setStats] = useState(null);
  const [editUser, setEditUser] = useState(null);
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState('');
  const [showAllProjects, setShowAllProjects] = useState(false);
  const [allProjects, setAllProjects] = useState([]);
  const [expandedUser, setExpandedUser] = useState(null);
  const [userProjects, setUserProjects] = useState([]);

  const loadData = useCallback(async () => {
    const [sr, ur] = await Promise.all([
      apiFetch('/api/admin/stats'),
      apiFetch('/api/admin/users'),
    ]);
    const sd = await sr.json(); const ud = await ur.json();
    setStats(sd); setUsers(ud.users||[]);
  }, []);

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => { loadData(); }, [loadData]);

  function showToast(msg) { setToast(msg); setTimeout(()=>setToast(''),3000); }

  async function deleteUser(id, name) {
    if (!confirm(`Delete user "${name}"? This deletes all their data.`)) return;
    await apiFetch(`/api/admin/users/${id}`, {method:'DELETE'});
    showToast('User deleted.');
    loadData();
  }

  async function saveEdit() {
    if (!editUser) return;
    const res = await apiFetch(`/api/admin/users/${editUser.id}`, {
      method:'PATCH', body: JSON.stringify({name:editUser.name, organization:editUser.organization, role:editUser.role})
    });
    if (res.ok) { showToast('User updated.'); setEditUser(null); loadData(); }
  }

  async function toggleAllProjects() {
    if (showAllProjects) { setShowAllProjects(false); return; }
    const res = await apiFetch('/api/admin/all-projects');
    const d = await res.json();
    setAllProjects(d.projects||[]);
    setShowAllProjects(true);
  }

  async function toggleUserProjects(uid) {
    if (expandedUser === uid) { setExpandedUser(null); return; }
    const res = await apiFetch(`/api/admin/users/${uid}/projects`);
    const d = await res.json();
    setUserProjects(d.projects||[]);
    setExpandedUser(uid);
  }

  const filtered = users.filter(u =>
    u.name.toLowerCase().includes(search.toLowerCase()) ||
    u.email.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <Layout title="User Manager">
      {toast && <div className="toast">{toast}</div>}

      <div className="content-grid">
        {stats && (
          <div className="col-12">
            <div className="stat-grid">
              {[['Total Users',stats.totalUsers,'primary'],['Total Projects',stats.totalProjects,'success'],['Total Scans',stats.totalScans,'warning']].map(([l,n,c])=>(
                <div key={l} className="stat-card">
                  <div className="stat-num" style={{color:`var(--${c})`}}>{n}</div>
                  <div className="stat-label">{l}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="card col-12">
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'14px',flexWrap:'wrap',gap:'10px'}}>
            <h3 style={{margin:0}}>Registered Users</h3>
            <div style={{display:'flex',gap:'8px',alignItems:'center'}}>
              <input className="input" style={{width:'200px'}} placeholder="Search users…" value={search} onChange={e=>setSearch(e.target.value)} />
              <button className="btn btn-secondary" onClick={toggleAllProjects} style={{fontSize:'12px'}}>
                {showAllProjects ? 'Hide All Projects' : '🗂 All Projects'}
              </button>
            </div>
          </div>

          <table className="table">
            <thead><tr><th>#</th><th>Name</th><th>Email</th><th>Org</th><th>Role</th><th>Projects</th><th>Scans</th><th>Joined</th><th>Actions</th></tr></thead>
            <tbody>
              {filtered.map((u,i)=>(
                <>
                  <tr key={u.id}>
                    <td style={{color:'var(--muted)',fontSize:'12px'}}>{i+1}</td>
                    <td><strong>{u.name}</strong></td>
                    <td style={{color:'var(--muted)'}}>{u.email}</td>
                    <td style={{color:'var(--muted)'}}>{u.organization||'—'}</td>
                    <td><span className={`badge role-${u.role}`}>{u.role}</span></td>
                    <td>
                      <button className="btn btn-ghost" style={{fontSize:'11px',padding:'3px 8px'}} onClick={()=>toggleUserProjects(u.id)}>
                        {u.project_count||0} 📁
                      </button>
                    </td>
                    <td>{u.scan_count||0}</td>
                    <td style={{fontSize:'11px',color:'var(--muted)'}}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</td>
                    <td style={{display:'flex',gap:'6px'}}>
                      <button className="btn btn-secondary" style={{fontSize:'11px',padding:'5px 10px'}} onClick={()=>setEditUser({...u})}>Edit</button>
                      <button className="btn btn-danger"    style={{fontSize:'11px',padding:'5px 10px'}} onClick={()=>deleteUser(u.id,u.name)}>Del</button>
                    </td>
                  </tr>
                  {expandedUser === u.id && (
                    <tr key={`proj-${u.id}`}>
                      <td colSpan={9} style={{padding:0}}>
                        <div style={{padding:'12px 20px',background:'rgba(139,111,71,0.04)',borderTop:'1px solid var(--border-light)'}}>
                          {userProjects.length === 0 ? (
                            <span style={{color:'var(--muted)',fontSize:'13px'}}>No projects yet.</span>
                          ) : (
                            <table className="table" style={{fontSize:'12px'}}>
                              <thead><tr><th>Project</th><th>Type</th><th>Scans</th><th>Compliance</th><th>Last Scan</th></tr></thead>
                              <tbody>
                                {userProjects.map(p=>(
                                  <tr key={p.id}>
                                    <td>{p.name}</td>
                                    <td>{p.source_type==='github'?'🐙':p.source_type==='local'?'📂':'📦'} {p.source_type}</td>
                                    <td>{p.scan_count}</td>
                                    <td>{p.compliance_score!=null ? Math.round(p.compliance_score)+'%' : '—'}</td>
                                    <td style={{color:'var(--muted)'}}>{p.last_scanned_at ? new Date(p.last_scanned_at).toLocaleString() : '—'}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>

        {showAllProjects && (
          <div className="card col-12">
            <h3>All Projects (System-wide)</h3>
            <table className="table">
              <thead><tr><th>Project</th><th>Owner</th><th>Type</th><th>Scans</th><th>Compliance</th></tr></thead>
              <tbody>
                {allProjects.map(p=>(
                  <tr key={p.id}>
                    <td><strong>{p.name}</strong></td>
                    <td><div>{p.user_name}</div><div style={{fontSize:'11px',color:'var(--muted)'}}>{p.user_email}</div></td>
                    <td>{p.source_type==='github'?'🐙':p.source_type==='local'?'📂':'📦'} {p.source_type}</td>
                    <td>{p.scan_count}</td>
                    <td>{p.compliance_score!=null ? Math.round(p.compliance_score)+'%' : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editUser && (
        <div className="modal-backdrop" onClick={e=>e.target===e.currentTarget&&setEditUser(null)}>
          <div className="modal-box">
            <h3 style={{marginBottom:'20px'}}>Edit User</h3>
            <div className="field"><label>Name</label><input className="input" value={editUser.name} onChange={e=>setEditUser(u=>({...u,name:e.target.value}))} /></div>
            <div className="field"><label>Organization</label><input className="input" value={editUser.organization||''} onChange={e=>setEditUser(u=>({...u,organization:e.target.value}))} /></div>
            <div className="field">
              <label>Role</label>
              <select className="input" value={editUser.role} onChange={e=>setEditUser(u=>({...u,role:e.target.value}))}>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
                <option value="viewer">viewer</option>
              </select>
            </div>
            <div style={{display:'flex',gap:'8px',marginTop:'8px'}}>
              <button className="btn btn-primary" style={{flex:1}} onClick={saveEdit}>Save</button>
              <button className="btn btn-ghost" style={{flex:1}} onClick={()=>setEditUser(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
