import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';
import { toolState } from '../services/toolStatus';

function ToolStatusCard() {
  const [ts, setTs] = useState(null);
  useEffect(() => {
    apiFetch('/api/tools/status').then(r=>r.json()).then(setTs).catch(()=>{});
  }, []);
  const tools = [
    { name:'SonarQube', key:'sonarqube' },
    { name:'Semgrep',   key:'semgrep' },
    { name:'Snyk',      key:'snyk' },
    { name:'Trivy',     key:'trivy' },
    { name:'OWASP ZAP', key:'zap' },
    { name:'Anchore',   key:'anchore' },
  ];
  return (
    <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
      {tools.map(t => {
        const st = toolState(ts ? ts[t.key] : null);
        return (
          <div key={t.name} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 0',borderBottom:'1px solid var(--border)'}}>
            <span style={{fontWeight:500}}>{t.name}</span>
            <span className={`badge badge-${st.color}`}>{st.kind==='connected'?'✓ ':st.kind==='missing'?'✗ ':''}{st.label}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState({
    totalProjects: 0,
    overallCompliance: 0,
    frameworks: [],
    recentActivity: []
  });

  useEffect(() => {
    apiFetch('/api/policies/frameworks')
      .then(res => res.json())
      .then(fw => Array.isArray(fw) && setStats(s => ({
        ...s,
        frameworks: fw.map(f => ({ name: f.name, status: f.status, color: 'success' })),
      })))
      .catch(() => {});
  }, []);

  useEffect(() => {
    // Fetch user projects and compliance scores
    apiFetch('/api/projects')
      .then(res => res.json())
      .then(projects => {
        let totalProjects = projects.length;
        let totalScore = 0;
        let scoredProjects = 0;

        projects.forEach(p => {
          if (p.complianceScore != null) {
            totalScore += p.complianceScore;
            scoredProjects++;
          }
        });

        const overallCompliance = scoredProjects > 0 ? Math.round(totalScore / scoredProjects) : 0;

        // Mock recent activity based on actual projects
        const recentActivity = projects.slice(0, 4).map(p => ({
          event: p.complianceScore ? 'Scan Complete' : 'Project Added',
          details: p.complianceScore 
            ? `${p.name} compliance score: ${p.complianceScore}%`
            : `Added project ${p.name}`,
          time: new Date(p.createdAt || Date.now()).toLocaleDateString(),
          color: p.complianceScore ? 'success' : 'info'
        }));

        setStats(prev => ({
          ...prev,
          totalProjects,
          overallCompliance,
          recentActivity
        }));
      })
      .catch(err => console.error("Error fetching dashboard stats:", err));
  }, []);

  return (
    <Layout title="Dashboard">
      <div className="content-grid">
        <div className="card col-4">
          <h3>Overall Compliance</h3>
          <div style={{textAlign:'center',padding:'20px 0'}}>
            <div style={{fontSize:'56px',fontFamily:'Playfair Display,serif',fontWeight:700,color:'var(--primary)'}}>
              {stats.overallCompliance}%
            </div>
            <div style={{fontSize:'13px',color:'var(--muted)',marginTop:'4px'}}>Average Compliance Score</div>
          </div>
          <div style={{display:'flex',gap:'8px',justifyContent:'center',flexWrap:'wrap'}}>
            <span className="badge badge-success">Total Projects: {stats.totalProjects}</span>
            <span className="badge badge-info">Active Monitoring</span>
          </div>
        </div>

        <div className="card col-4">
          <h3>GRC Frameworks & Policies</h3>
          <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
            {stats.frameworks.map((fw) => (
              <div key={fw.name} style={{display:'flex',justifyContent:'space-between',alignItems:'center', padding: '8px 0', borderBottom: '1px solid var(--border)'}}>
                <span style={{fontWeight:500}}>{fw.name}</span>
                <span className={`badge badge-${fw.color}`}>{fw.status}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card col-4">
          <h3>Tool Integration</h3>
          <ToolStatusCard />
        </div>

        <div className="card col-12">
          <h3>Recent Activity</h3>
          <table className="table">
            <thead>
              <tr><th>Event</th><th>Details</th><th>Date</th></tr>
            </thead>
            <tbody>
              {stats.recentActivity.length > 0 ? stats.recentActivity.map((act, i) => (
                <tr key={i}>
                  <td><span className={`badge badge-${act.color}`}>{act.event}</span></td>
                  <td>{act.details}</td>
                  <td style={{color:'var(--muted)'}}>{act.time}</td>
                </tr>
              )) : (
                <tr><td colSpan="3" style={{textAlign:'center', color:'var(--muted)'}}>No recent activity</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
