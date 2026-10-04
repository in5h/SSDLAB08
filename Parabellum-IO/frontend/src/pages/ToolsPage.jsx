import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import { toolState } from '../services/toolStatus';

export default function ToolsPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch('/api/tools/status')
      .then(r => r.json())
      .then(d => setStatus(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const defs = [
    { key:'sonarqube', name:'SonarQube', type:'SAST', icon:'🔎', desc:'Code quality and security scanning via static analysis' },
    { key:'semgrep',   name:'Semgrep',   type:'SAST', icon:'🔎', desc:'Lightweight static analysis with pattern-matching rules' },
    { key:'snyk',      name:'Snyk',      type:'SCA',  icon:'📦', desc:'Dependency vulnerability scanning with fix recommendations' },
    { key:'trivy',     name:'Trivy',     type:'Container', icon:'🐳', desc:'Dependency CVEs, IaC misconfigurations and secrets' },
    { key:'zap',       name:'OWASP ZAP', type:'DAST', icon:'🌐', desc:'Dynamic testing of a running web application' },
    { key:'anchore',   name:'Anchore Grype', type:'Container Policy', icon:'🛡️', desc:'Package vulnerability scan with a STOP/WARN policy gate' },
  ];
  const tools = defs.map(d => {
    const s = status?.[d.key];
    const st = toolState(loading ? null : s);
    return {
      ...d,
      status: st.label,
      color: st.color,
      version: s?.version || s?.url || '—',
      hint: s?.error || (st.kind === 'builtin' ? 'Real tool not installed — scans use Parabellum\'s basic built-in checks only.' : ''),
      link: st.kind === 'connected' || st.kind === 'builtin' ? '/scan' : null,
    };
  });

  return (
    <Layout title="Tools">
      <div className="content-grid">
        <div className="card col-12">
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'16px'}}>
            <h3 style={{margin:0}}>Security Tool Integrations</h3>
            {loading && <span style={{fontSize:12,color:'var(--muted)'}}>Checking tool status…</span>}
          </div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(320px,1fr))',gap:'14px'}}>
            {tools.map(t=>(
              <div key={t.name} style={{
                padding:'18px',borderRadius:'12px',
                border:`1px solid ${t.color==='success'?'rgba(74,124,89,0.3)':'var(--border)'}`,
                background:t.color==='success'?'rgba(74,124,89,0.04)':'var(--bg)',
                display:'flex',gap:'14px',alignItems:'flex-start',
                transition:'all .2s',
              }}>
                <div style={{width:'44px',height:'44px',borderRadius:'12px',
                  background:t.color==='success'?'rgba(74,124,89,0.12)':'rgba(139,111,71,0.08)',
                  border:'1px solid var(--border)',display:'flex',alignItems:'center',justifyContent:'center',
                  fontSize:'22px',flexShrink:0}}>
                  {t.icon}
                </div>
                <div style={{flex:1}}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'4px'}}>
                    <strong style={{fontSize:'15px'}}>{t.name}</strong>
                    <span className={`badge badge-${t.color}`}>{t.status}</span>
                  </div>
                  <div style={{fontSize:'11px',color:'var(--muted)',marginBottom:'4px'}}>{t.type} · {t.version}</div>
                  <div style={{fontSize:'12px',color:'var(--muted)',lineHeight:1.5}}>{t.desc}</div>
                  {t.hint && <div style={{fontSize:'11px',color:t.color==='danger'?'var(--danger)':'#b45309',marginTop:'6px'}}>{t.hint}</div>}
                  {t.link && (
                    <a href={t.link} style={{
                      display:'inline-block',marginTop:'10px',padding:'6px 14px',borderRadius:8,
                      background:'var(--primary)',color:'#fff',fontSize:'12px',fontWeight:600,textDecoration:'none',
                    }}>🔍 Go to Scans →</a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}
