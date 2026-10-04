import { useEffect, useState } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

const SEV_COLOR = { Critical: 'danger', High: 'warning', Medium: 'warning', Low: 'neutral' };

export default function PoliciesPage() {
  const [frameworks, setFrameworks] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([
      apiFetch('/api/policies/frameworks').then(r => r.json()),
      apiFetch('/api/policies/catalog').then(r => r.json()),
    ])
      .then(([fw, pol]) => { setFrameworks(Array.isArray(fw) ? fw : []); setPolicies(Array.isArray(pol) ? pol : []); })
      .catch(() => setError('Could not load policies from the server.'));
  }, []);

  return (
    <Layout title="Policy-as-Code Engine">
      {error && <div className="card col-12" style={{ marginBottom: 24, color: 'var(--danger)' }}>❌ {error}</div>}

      <div className="card col-12" style={{ marginBottom: 24 }}>
        <h3 style={{ margin: '0 0 6px 0', fontSize: 18 }}>GRC Frameworks</h3>
        <p style={{ fontSize: 13, color: 'var(--muted)', margin: '0 0 16px 0' }}>
          All frameworks below can be analysed on the Compliance Mapping page. MITRE ATT&amp;CK, OWASP Top 10 and CAPEC are used in Risk Analysis.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          {frameworks.map(fw => (
            <div key={fw.slug} style={{ padding: 16, border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <strong style={{ fontSize: 15 }}>{fw.name}</strong>
                <div>
                  <span className="badge badge-success" style={{ marginRight: 8 }}>{fw.status}</span>
                  <span className="badge badge-neutral">{fw.controls} Controls</span>
                </div>
              </div>
              <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>{fw.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card col-12">
        <h3 style={{ margin: '0 0 6px 0', fontSize: 18 }}>Built-in Policy Rules ({policies.length})</h3>
        <p style={{ fontSize: 13, color: 'var(--muted)', margin: '0 0 16px 0' }}>
          These rules check Dockerfiles, dependency manifests, secrets and CI/CD files. Results appear in Compliance Mapping (NIST CSF) and Risk Analysis.
        </p>
        <table className="table">
          <thead><tr><th>ID</th><th>Rule</th><th>Category</th><th>Severity</th><th>Checks</th><th>NIST CSF 2.0</th></tr></thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id}>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{p.id}</td>
                <td><strong>{p.name}</strong><div style={{ fontSize: 12, color: 'var(--muted)' }}>{p.description}</div></td>
                <td>{p.category}</td>
                <td><span className={`badge badge-${SEV_COLOR[p.severity] || 'neutral'}`}>{p.severity}</span></td>
                <td style={{ fontSize: 12 }}>{p.target}</td>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{(p.nistControls || []).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
