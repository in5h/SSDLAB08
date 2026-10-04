import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import apiFetch from '../services/api';

export default function ReportsPage() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [viewingFile, setViewingFile] = useState(null);
  const [fileContent, setFileContent] = useState('');

  useEffect(() => {
    apiFetch('/api/sonar/reports')
      .then(r=>r.json())
      .then(d=>setReports(d.reports||[]))
      .catch(()=>{})
      .finally(()=>setLoading(false));
  }, []);

  const handleView = async (filename) => {
    setViewingFile(filename);
    setFileContent('Loading content...');
    try {
      const res = await apiFetch(`/api/sonar/reports/${filename}`);
      if (!res.ok) throw new Error('Failed to load file');
      const text = await res.text();
      setFileContent(text);
    } catch (e) {
      setFileContent('Error loading file content: ' + e.message);
    }
  };

  const handleDownload = async (filename) => {
    try {
      const res = await apiFetch(`/api/sonar/reports/${filename}`);
      if (!res.ok) throw new Error('Failed to download file');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      alert('Error downloading file: ' + e.message);
    }
  };

  return (
    <Layout title="Raw Scan Findings (JSON/YAML)">
      <div className="content-grid">
        <div className="card col-12">
          <h3>Generated SonarQube Reports for NIST Mapping</h3>
          <p style={{fontSize:'13px',color:'var(--muted)',marginBottom:'16px'}}>
            These are the raw SonarQube issue extractions in JSON and YAML formats. Our core engine uses these exact files to map findings to NIST CSF 2.0 controls.
          </p>
          {loading ? (
            <div style={{textAlign:'center',padding:'40px',color:'var(--muted)'}}>Loading reports…</div>
          ) : reports.length === 0 ? (
            <div style={{textAlign:'center',padding:'40px',color:'var(--muted)'}}>
              <div style={{fontSize:'40px',opacity:.2}}>📄</div>
              <div style={{marginTop:'10px'}}>No reports yet. Run a SonarQube scan to generate one.</div>
            </div>
          ) : (
            <table className="table">
              <thead><tr><th>Filename</th><th>Type</th><th>Size</th><th>Generated</th><th>Actions</th></tr></thead>
              <tbody>
                {reports.map(r=>(
                  <tr key={r.filename}>
                    <td style={{fontFamily:'monospace',fontSize:'12px'}}>{r.filename}</td>
                    <td><span className="badge badge-neutral">{r.filename.endsWith('.yaml')?'YAML':'JSON'}</span></td>
                    <td style={{color:'var(--muted)',fontSize:'12px'}}>{Math.round(r.size/1024)} KB</td>
                    <td style={{color:'var(--muted)',fontSize:'12px'}}>{new Date(r.createdAt).toLocaleString()}</td>
                    <td>
                      <div style={{display:'flex',gap:'8px'}}>
                        <button 
                          onClick={() => handleView(r.filename)}
                          className="btn btn-ghost" 
                          style={{fontSize:'12px',padding:'5px 12px'}}
                        >👁️ View</button>
                        <button 
                          onClick={() => handleDownload(r.filename)} 
                          className="btn btn-ghost" 
                          style={{fontSize:'12px',padding:'5px 12px'}} 
                        >⬇ Download</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {viewingFile && (
          <div className="card col-12" style={{ marginTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0 }}>Viewing: <span style={{fontFamily:'monospace',fontSize:'14px',color:'var(--primary)'}}>{viewingFile}</span></h3>
              <button 
                onClick={() => setViewingFile(null)} 
                className="btn btn-ghost"
                style={{ padding: '6px 12px' }}
              >✖ Close</button>
            </div>
            <div style={{ background: '#1e1e1e', color: '#d4d4d4', padding: '16px', borderRadius: '8px', overflowX: 'auto', maxHeight: '500px' }}>
              <pre style={{ margin: 0, fontSize: '12px', fontFamily: 'monospace' }}>
                {fileContent}
              </pre>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
