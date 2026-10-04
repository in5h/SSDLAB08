import { useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import PropTypes from 'prop-types';
import apiFetch, { getUser, clearSession } from '../services/api';

const navItems = [
  { to: '/dashboard',        label: 'Dashboard',         icon: '⊞' },
  { to: '/policies',         label: 'Policies',           icon: '📋' },
  { to: '/tools',            label: 'Tools',              icon: '🔧' },
  { to: '/import',           label: 'GitHub Import',      icon: '📦' },
  { to: '/pipeline',         label: 'Pipeline',           icon: '🚦' },
  { to: '/scan',             label: 'Security Scans',     icon: '🔍' },
  { to: '/findings',         label: 'Findings',           icon: '🧾' },
  { to: '/compliance',       label: 'Compliance Mapping', icon: '📊' },
  { to: '/risk',             label: 'Risk Analysis',      icon: '🎯' },
  { to: '/final-report',     label: 'Final Report',       icon: '📘' },
  { to: '/compliance-report',label: 'Compliance Report',  icon: '📑' },
  { to: '/reports',          label: 'Reports',            icon: '📄' },
];

// "Change password" dialog (current password required; other devices are signed out)
function ChangePassword({ onClose }) {
  const [form, setForm] = useState({ currentPassword: '', newPassword: '', confirm: '' });
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  async function save(e) {
    e.preventDefault();
    if (form.newPassword !== form.confirm) { setMsg('❌ The two new passwords do not match.'); return; }
    setBusy(true); setMsg('');
    try {
      const r = await apiFetch('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ currentPassword: form.currentPassword, newPassword: form.newPassword }) });
      const d = await r.json();
      setMsg(r.ok ? `✅ ${d.message}` : `❌ ${d.error}`);
      if (r.ok) setForm({ currentPassword: '', newPassword: '', confirm: '' });
    } catch (err) { setMsg(`❌ ${err.message}`); } finally { setBusy(false); }
  }
  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));
  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.35)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
      <form onClick={e => e.stopPropagation()} onSubmit={save} className="card" style={{ width: 380, maxWidth: '92vw' }}>
        <h3 style={{ marginTop: 0 }}>Change password</h3>
        <div className="field"><label>Current password</label><input className="input" type="password" autoComplete="current-password" value={form.currentPassword} onChange={set('currentPassword')} /></div>
        <div className="field"><label>New password</label><input className="input" type="password" autoComplete="new-password" placeholder="Min 8 chars, uppercase, number, symbol" value={form.newPassword} onChange={set('newPassword')} /></div>
        <div className="field"><label>Confirm new password</label><input className="input" type="password" autoComplete="new-password" value={form.confirm} onChange={set('confirm')} /></div>
        {msg && <div style={{ fontSize: 13, marginBottom: 10 }}>{msg}</div>}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>Close</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Change password'}</button>
        </div>
      </form>
    </div>
  );
}
ChangePassword.propTypes = { onClose: PropTypes.func.isRequired };

export default function Layout({ children, title }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(getUser());
  const [showPwd, setShowPwd] = useState(false);

  // The session is stored on the server, so a reload or server restart keeps you logged in.
  // Refresh the user details (e.g. a role change) from the saved session.
  useEffect(() => {
    apiFetch('/api/auth/me')
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (d?.user) { localStorage.setItem('user', JSON.stringify(d.user)); setUser(d.user); }
      })
      .catch(() => {});
  }, []);

  async function logout() {
    try { await apiFetch('/api/auth/logout', { method: 'POST', body: '{}' }); } catch { /* already logged out */ }
    clearSession();
    navigate('/login', { replace: true });
  }

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src="/logo.png" alt="Parabellum IO" onError={e => e.target.style.display='none'} />
          <div>
            <div className="sidebar-brand-text">Parabellum IO</div>
            <div className="sidebar-brand-sub">DevSecOps</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section">Navigation</div>
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => isActive ? 'active' : ''}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
          {user?.role === 'admin' && (
            <>
              <div className="nav-section" style={{marginTop: 8}}>Admin</div>
              <NavLink to="/admin" className={({ isActive }) => isActive ? 'active' : ''}>
                <span className="nav-icon">👤</span>
                {' '}User Manager
              </NavLink>
            </>
          )}
        </nav>

        <div className="sidebar-footer">
          <strong>{user?.name || 'User'}</strong>
          {user?.email}
        </div>
      </aside>

      {/* Main area */}
      <div className="main-area">
        <header className="topbar">
          <h1>{title}</h1>
          <div className="topbar-right">
            <div style={{textAlign:'right'}}>
              <div className="topbar-user-name">{user?.name}</div>
              <div className="topbar-user-email">{user?.email}</div>
            </div>
            <button className="btn btn-ghost" onClick={() => setShowPwd(true)} style={{padding:'7px 12px',fontSize:'12px'}} title="Change password">
              🔑 Password
            </button>
            <button className="btn btn-danger" onClick={logout} style={{padding:'7px 14px',fontSize:'12px'}}>
              Logout
            </button>
          </div>
        </header>
        <div className="content-area">
          {children}
        </div>
        {showPwd && <ChangePassword onClose={() => setShowPwd(false)} />}
      </div>
    </div>
  );
}

Layout.propTypes = {
  children: PropTypes.node.isRequired,
  title: PropTypes.string.isRequired,
};
