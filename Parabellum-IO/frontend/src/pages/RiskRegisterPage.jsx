import Layout from '../components/Layout';
export default function RiskRegisterPage() {
  const risks = [
    { id:'R-001', title:'Hardcoded API Keys in Codebase', likelihood:'High',   impact:'Critical', owner:'Dev Lead',      framework:'NIST CSF', status:'Open'    },
    { id:'R-002', title:'Outdated Dependencies with CVEs', likelihood:'High',   impact:'High',     owner:'DevOps',        framework:'CIS v8',   status:'Mitigate'},
    { id:'R-003', title:'Missing Data Encryption at Rest', likelihood:'Medium', impact:'High',     owner:'Security Team', framework:'GDPR',     status:'Open'    },
    { id:'R-004', title:'Insufficient Access Controls',    likelihood:'Medium', impact:'Medium',   owner:'IAM Team',      framework:'ISO 27001',status:'Review'  },
    { id:'R-005', title:'Container Misconfigurations',     likelihood:'Low',    impact:'Medium',   owner:'DevOps',        framework:'CIS v8',   status:'Monitor' },
  ];
  const impColor = i => i==='Critical'?'danger':i==='High'?'warning':i==='Medium'?'info':'neutral';
  return (
    <Layout title="Risk Register">
      <div className="content-grid">
        <div className="card col-12">
          <h3>Risk Register</h3>
          <table className="table">
            <thead><tr><th>ID</th><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Owner</th><th>Framework</th><th>Status</th></tr></thead>
            <tbody>
              {risks.map(r=>(
                <tr key={r.id}>
                  <td style={{fontFamily:'monospace',fontSize:'12px',color:'var(--muted)'}}>{r.id}</td>
                  <td><strong>{r.title}</strong></td>
                  <td><span className={`badge badge-${impColor(r.likelihood)}`}>{r.likelihood}</span></td>
                  <td><span className={`badge badge-${impColor(r.impact)}`}>{r.impact}</span></td>
                  <td style={{color:'var(--muted)'}}>{r.owner}</td>
                  <td>{r.framework}</td>
                  <td><span className={`badge badge-${r.status==='Monitor'?'info':r.status==='Open'?'danger':r.status==='Mitigate'?'warning':'neutral'}`}>{r.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card col-4">
          <h3>Risk Summary</h3>
          <div style={{display:'flex',flexDirection:'column',gap:'10px'}}>
            {[['Open',2,'danger'],['Mitigate',1,'warning'],['Review',1,'info'],['Monitor',1,'neutral']].map(([l,n,c])=>(
              <div key={l} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 12px',borderRadius:'8px',background:'var(--bg)',border:'1px solid var(--border)'}}>
                <span style={{fontWeight:500}}>{l}</span>
                <span className={`badge badge-${c}`}>{n}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card col-8">
          <h3>Compliance Gap Coverage</h3>
          <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
            {[['NIST CSF',82,'success'],['CIS v8',68,'warning'],['ISO 27001',75,'success'],['GDPR',60,'danger']].map(([fw,pct,c])=>(
              <div key={fw}>
                <div style={{display:'flex',justifyContent:'space-between',fontSize:'13px',marginBottom:'5px'}}>
                  <span style={{fontWeight:500}}>{fw}</span>
                  <span style={{color:`var(--${c})`,fontWeight:600}}>{pct}%</span>
                </div>
                <div style={{height:'8px',background:'var(--border)',borderRadius:'4px'}}>
                  <div style={{width:`${pct}%`,height:'100%',borderRadius:'4px',background:`var(--${c})`,transition:'width .6s ease'}} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}
