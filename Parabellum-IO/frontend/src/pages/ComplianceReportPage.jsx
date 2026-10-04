import { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import Layout from '../components/Layout';
import apiFetch, { getUser } from '../services/api';

const API_C = '/api/compliance';
const API_R = '/api/risk';

const NIST_META = {
  GOVERN:   { key:'GOVERN',   short:'GV', color:'#7c3aed', controls:'GV.RM-01, GV.OC-01', action:'Establish risk governance policies and assign ownership.' },
  IDENTIFY: { key:'IDENTIFY', short:'ID', color:'#1d4ed8', controls:'ID.AM-01, ID.RA-01',  action:'Complete asset inventory and risk assessment.' },
  PROTECT:  { key:'PROTECT',  short:'PR', color:'#065f46', controls:'PR.DS-01, PR.AA-01',  action:'Enforce least-privilege, patch management, and encryption.' },
  DETECT:   { key:'DETECT',   short:'DE', color:'#92400e', controls:'DE.CM-01, DE.CM-08',  action:'Deploy SIEM and continuous vulnerability scanning.' },
  RESPOND:  { key:'RESPOND',  short:'RS', color:'#991b1b', controls:'RS.MA-01, RS.AN-01',  action:'Document and test incident response playbooks.' },
  RECOVER:  { key:'RECOVER',  short:'RC', color:'#1e3a5f', controls:'RC.RP-01',            action:'Define recovery time objectives (RTO/RPO) and test backups.' },
};

const SEV_BADGE = { Critical:'#dc2626', High:'#ea580c', Medium:'#ca8a04', Low:'#16a34a' };

function Badge({ label, color }) {
  return (
    <span style={{ background:color, color:'#fff', borderRadius:4,
      padding:'2px 8px', fontSize:11, fontWeight:700 }}>{label}</span>
  );
}
Badge.propTypes = { label: PropTypes.string.isRequired, color: PropTypes.string.isRequired };

function getGaugeColor(value) {
  if (value >= 80) return '#16a34a';
  if (value >= 60) return '#ca8a04';
  return '#dc2626';
}

function getCvssColor(cvss) {
  if (cvss >= 9) return '#dc2626';
  if (cvss >= 7) return '#ea580c';
  return '#ca8a04';
}

function ScoreGauge({ score = 0, size = 120 }) {
  const r = size/2 - 10;
  const circ = 2 * Math.PI * r;
  const safe = Math.max(0, Math.min(100, score));
  const offset = circ - (safe / 100) * circ;
  const color = getGaugeColor(safe);
  return (
    <svg width={size} height={size}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#e5e7eb" strokeWidth={10} />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={10}
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round" transform={`rotate(-90 ${size/2} ${size/2})`} />
      <text x={size/2} y={size/2 + 6} textAnchor="middle"
        fontSize={size*0.18} fontWeight={800} fill={color}>{safe}%</text>
    </svg>
  );
}
ScoreGauge.propTypes = { score: PropTypes.number, size: PropTypes.number };

function Section({ title, icon, children }) {
  return (
    <div style={{ background:'#fff', border:'1px solid #e5e7eb', borderRadius:10,
      overflow:'hidden', marginBottom:22 }}>
      <div style={{ padding:'12px 20px', borderBottom:'1px solid #e5e7eb',
        display:'flex', alignItems:'center', gap:10,
        background:'linear-gradient(to right,#f8faff,#fff)' }}>
        <span style={{ fontSize:18 }}>{icon}</span>
        <h2 style={{ margin:0, fontSize:15, fontWeight:700, color:'#111827' }}>{title}</h2>
      </div>
      <div style={{ padding:'18px 22px' }}>{children}</div>
    </div>
  );
}
Section.propTypes = { title: PropTypes.string.isRequired, icon: PropTypes.string.isRequired, children: PropTypes.node.isRequired };

// ── The printable report document ────────────────────────────────────────────
const ALL_FRAMEWORKS = [
  { slug: 'nist_csf', label: 'NIST CSF 2.0' }, { slug: 'iso27001', label: 'ISO 27001:2022' },
  { slug: 'cis_controls', label: 'CIS Controls v8' }, { slug: 'nist_sp800', label: 'NIST SP 800-53' },
  { slug: 'owasp_asvs', label: 'OWASP ASVS v4' }, { slug: 'iso27034', label: 'ISO 27034' },
];

function ReportDoc({ report, user }) {
  const { compliance: cd, risk: rd, generatedAt, project } = report;
  const frameworks = Array.isArray(report.frameworks) ? report.frameworks.filter(f => f && !f.error) : [];
  const toolsUsed = cd.tools?.length ? cd.tools.join(', ') : 'SonarQube';

  const overall       = cd.overall || {};
  const breakdown     = Array.isArray(cd.breakdown) ? cd.breakdown : [];
  const failedCtrl    = Array.isArray(cd.failedControls) ? cd.failedControls : [];
  const totalIssues   = cd.totalIssues ?? 0;
  const cweFindings   = Array.isArray(rd.cweFindings) ? rd.cweFindings : [];
  const riskSummary   = rd.riskSummary || {};

  const critCount = riskSummary.critical_cwes || 0;
  const highCount = riskSummary.high_cwes || 0;
  const medCount  = riskSummary.medium_cwes || 0;
  const lowCount  = riskSummary.low_cwes || 0;

  const auditScore = Number(overall.score ?? cd.overallScore ?? 100);
  const verdict = auditScore >= 70 ? 'PASS' : auditScore >= 50 ? 'CONDITIONAL PASS' : 'FAIL';
  const verdictColor = verdict === 'PASS' ? '#16a34a' : verdict === 'CONDITIONAL PASS' ? '#ca8a04' : '#dc2626';
  const nistTier = auditScore >= 85 ? 'Tier 4 — Adaptive' : auditScore >= 70 ? 'Tier 3 — Repeatable'
                 : auditScore >= 50 ? 'Tier 2 — Risk-Informed' : 'Tier 1 — Partial';

  const reportId = useMemo(() => {
    const seed = (generatedAt.getTime() % 9000) + 1000;
    return `GRC-${generatedAt.getFullYear()}-${seed}`;
  }, [generatedAt]);

  const isPass = verdict === 'PASS';
  const pColor  = isPass ? '#065f46' : '#991b1b';
  const pBg     = isPass ? '#f0fdf4' : '#fef2f2';
  const pBorder = isPass ? '#86efac' : '#fca5a5';

  return (
    <div style={{ fontFamily:'Georgia,serif', color:'#111827', lineHeight:1.6 }}>

      {/* ══ 1. COVER PAGE ══ */}
      <div style={{ background:'linear-gradient(135deg,#0f172a,#1e3a5f)', color:'#fff',
        borderRadius:12, padding:'52px 44px', marginBottom:28, minHeight:340,
        display:'flex', flexDirection:'column', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontSize:10, letterSpacing:3, textTransform:'uppercase', opacity:.6, marginBottom:14 }}>
            Parabellum IO — GRC Compliance Dashboard
          </div>
          <h1 style={{ margin:'0 0 4px', fontSize:28, fontWeight:700, lineHeight:1.2 }}>
            Security &amp; Compliance Audit Report
          </h1>
          <div style={{ fontFamily:'monospace', fontSize:12, opacity:.7, marginBottom:14 }}>{reportId}</div>
          <h2 style={{ margin:'0 0 18px', fontSize:20, fontWeight:400, opacity:.85 }}>{project.name}</h2>
          <div style={{ display:'flex', gap:10, flexWrap:'wrap', marginBottom:16 }}>
            <Badge label={verdict} color={verdictColor} />
            <Badge label={`Score: ${auditScore}%`} color='#1d4ed8' />
            <Badge label={nistTier} color='#7c3aed' />
          </div>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', fontSize:10, opacity:.7 }}>
            {(frameworks.length ? frameworks.map(f => f.frameworkLabel) : ['NIST CSF 2.0']).map(f => (
              <span key={f} style={{ border:'1px solid rgba(255,255,255,.3)', borderRadius:3,
                padding:'2px 7px' }}>{f}</span>
            ))}
          </div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginTop:30, opacity:.85, fontSize:11 }}>
          <div><div style={{ opacity:.6, marginBottom:2 }}>Generated</div>{generatedAt.toLocaleString()}</div>
          <div><div style={{ opacity:.6, marginBottom:2 }}>Prepared By</div>{user?.name || 'Analyst'}</div>
          <div><div style={{ opacity:.6, marginBottom:2 }}>Tools</div>{toolsUsed}</div>
          <div><div style={{ opacity:.6, marginBottom:2 }}>Classification</div>CONFIDENTIAL</div>
        </div>
      </div>

      {/* ══ 2. EXECUTIVE SUMMARY ══ */}
      <Section title="2. Executive Summary" icon="📊">
        <div style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:28, alignItems:'start' }}>
          <div style={{ textAlign:'center' }}>
            <ScoreGauge score={auditScore} size={120} />
            <div style={{ fontSize:12, color:'#6b7280', marginTop:4 }}>Compliance Score</div>
            <Badge label={verdict} color={verdictColor} />
          </div>
          <div>
            <div style={{ background:pBg, border:`1px solid ${pBorder}`,
              borderRadius:8, padding:'13px 16px', marginBottom:14 }}>
              <div style={{ fontWeight:700, color:pColor, fontSize:13 }}>
                {verdict === 'PASS' ? '✅ This project PASSES the security & compliance audit.'
                  : verdict === 'CONDITIONAL PASS' ? '⚠️ CONDITIONAL PASS — remediation required within 30 days.'
                  : '❌ This project FAILS the security & compliance audit.'}
              </div>
              <div style={{ fontSize:12, color:'#374151', marginTop:5 }}>
                The {project.name} pipeline was assessed against NIST CSF 2.0{frameworks.length > 1 ? ` and ${frameworks.length - 1} more frameworks` : ''}
                {' '}using the findings of {toolsUsed}.{' '}
                {totalIssues} issues were analyzed across {cweFindings.length} unique
                CWE weaknesses, producing an audit score of <strong>{auditScore}%</strong>.
              </div>
            </div>
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
              <tbody>
                {[
                  ['NIST CSF Maturity Tier',   nistTier],
                  ['Overall Audit Score',       `${auditScore}/100`],
                  ['Total Issues Scanned',      totalIssues],
                  ['Unique CWE Weaknesses',     cweFindings.length],
                  ['Critical',                  `🔴 ${critCount}`],
                  ['High',                      `🟠 ${highCount}`],
                  ['Medium',                    `🟡 ${medCount}`],
                  ['Low',                       `🟢 ${lowCount}`],
                  ['Overall Risk Score',        `${riskSummary.overall_risk_score ?? 'N/A'} / 10`],
                ].map(([k,v]) => (
                  <tr key={k} style={{ borderBottom:'1px solid #f3f4f6' }}>
                    <td style={{ padding:'5px 0', color:'#6b7280', width:'55%' }}>{k}</td>
                    <td style={{ padding:'5px 0', fontWeight:700, color:'#111827' }}>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>

      {/* ══ ALL FRAMEWORKS ══ */}
      {frameworks.length > 0 && (
        <Section title="2b. Compliance Score — All Frameworks" icon="🧭">
          <div style={{ fontSize:12, color:'#6b7280', marginBottom:10 }}>
            {totalIssues} open findings from {toolsUsed} were mapped to each framework. A control fails when at least one open finding maps to it.
          </div>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead><tr>{['Framework','Score','Status','Failed controls','Most affected controls'].map(h => (
              <th key={h} style={{ textAlign:'left', padding:'7px 10px', background:'#1e293b', color:'#fff' }}>{h}</th>))}</tr></thead>
            <tbody>{frameworks.map(f => (
              <tr key={f.framework} style={{ borderBottom:'1px solid #e5e7eb' }}>
                <td style={{ padding:'7px 10px', fontWeight:700 }}>{f.frameworkLabel}</td>
                <td style={{ padding:'7px 10px', fontWeight:700, color:getGaugeColor(f.overall?.score ?? 0) }}>{f.overall?.score ?? '—'}%</td>
                <td style={{ padding:'7px 10px' }}><Badge label={f.overall?.status || '—'} color={f.overall?.status === 'PASS' ? '#16a34a' : '#dc2626'} /></td>
                <td style={{ padding:'7px 10px' }}>{f.failedControls?.length ?? 0}</td>
                <td style={{ padding:'7px 10px' }}>{(f.failedControls || []).slice(0, 4).map(c => `${c.control_id}${c.description && c.description !== c.control_id ? ` ${c.description}` : ''}`).join('; ') || '—'}</td>
              </tr>))}
            </tbody>
          </table>
        </Section>
      )}

      {/* ══ NIST FUNCTION BREAKDOWN ══ */}
      <Section title="3. NIST CSF 2.0 Function Breakdown" icon="🏛">
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:14, marginBottom:18 }}>
          {breakdown.map(fn => {
            const meta = NIST_META[fn.function] || { color:'#6b7280', short: fn.function?.slice(0,2) };
            const pct  = Math.round(fn.score || 0);
            const fnStatus = fn.status || (pct >= 70 ? 'PASS' : 'FAIL');
            return (
              <div key={fn.function} style={{ background:'#fff', border:'1px solid #e5e7eb',
                borderLeft:`4px solid ${meta.color}`, borderRadius:8, padding:'13px 16px' }}>
                <div style={{ fontWeight:700, color:meta.color, fontSize:13, marginBottom:4 }}>
                  {meta.short} — {fn.function}
                </div>
                <div style={{ fontSize:24, fontWeight:800, color:'#111827' }}>{pct}%</div>
                <Badge label={fnStatus} color={fnStatus === 'PASS' ? '#16a34a' : '#dc2626'} />
              </div>
            );
          })}
        </div>
      </Section>

      {/* ══ CWE TECHNICAL FINDINGS ══ */}
      <Section title="3b. Control Mapping — CWE Technical Findings" icon="🔬">
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead>
            <tr style={{ background:'#f9fafb', borderBottom:'2px solid #e5e7eb' }}>
              {['CWE ID','Vulnerability','CVSS','Severity','Possible Attacks','Issues','Risk Impact'].map(h => (
                <th key={h} style={{ padding:'8px 10px', textAlign:'left', fontWeight:700,
                  color:'#374151', fontSize:11, textTransform:'uppercase', letterSpacing:.4 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cweFindings.map((f, i) => (
              <tr key={f.cwe_id} style={{ borderBottom:'1px solid #f3f4f6',
                background: i%2===0 ? '#fff' : '#f9fafb' }}>
                <td style={{ padding:'8px 10px', fontFamily:'monospace', fontWeight:700,
                  color:'#1e40af', fontSize:11 }}>{f.cwe_id}</td>
                <td style={{ padding:'8px 10px', fontWeight:600 }}>{f.cwe_name}</td>
                <td style={{ padding:'8px 10px' }}>
                  <span style={{ background: getCvssColor(f.cvss_score),
                    color:'#fff', borderRadius:3, padding:'1px 6px', fontFamily:'monospace',
                    fontWeight:700, fontSize:11 }}>{(f.cvss_score||0).toFixed(1)}</span>
                </td>
                <td style={{ padding:'8px 10px' }}>
                  <Badge label={f.severity} color={SEV_BADGE[f.severity]||'#6b7280'} />
                </td>
                <td style={{ padding:'8px 10px', fontSize:11, color:'#374151' }}>
                  {(f.attack_types||[]).slice(0,2).join(', ')}
                </td>
                <td style={{ padding:'8px 10px', textAlign:'center', fontWeight:700 }}>{f.issue_count}</td>
                <td style={{ padding:'8px 10px', fontSize:11, color:'#4b5563', maxWidth:200 }}>
                  {(f.risk_impact||'').slice(0,90)}{(f.risk_impact||'').length>90?'…':''}
                </td>
              </tr>
            ))}
            {cweFindings.length === 0 && (
              <tr><td colSpan={7} style={{ padding:'20px', textAlign:'center', color:'#9ca3af' }}>
                ✅ No CWE findings detected.
              </td></tr>
            )}
          </tbody>
        </table>
      </Section>

      {/* ══ FAILED CONTROLS ══ */}
      {failedCtrl.length > 0 && (
        <Section title="4. Failed NIST Controls" icon="❌">
          {failedCtrl.map(ctrl => (
            <div key={ctrl.control_id || ctrl.id} style={{ border:'1px solid #fca5a5',
              borderRadius:8, marginBottom:14, overflow:'hidden' }}>
              <div style={{ background:'#fef2f2', padding:'10px 14px',
                display:'flex', alignItems:'center', justifyContent:'space-between' }}>
                <div>
                  <span style={{ fontFamily:'monospace', fontWeight:700, color:'#991b1b', marginRight:8 }}>
                    {ctrl.control_id || ctrl.id}
                  </span>
                  <span style={{ fontWeight:600, color:'#111827' }}>
                    {ctrl.description || ctrl.title || ctrl.control_id}
                  </span>
                </div>
                <Badge label="FAIL" color="#dc2626" />
              </div>
              {(Array.isArray(ctrl.violations) ? ctrl.violations : []).slice(0,3).map((v) => (
                <div key={v.message || v.description || Math.random()} style={{ padding:'7px 14px', borderTop:'1px solid #fee2e2',
                  fontSize:12, color:'#374151' }}>
                  <span style={{ fontFamily:'monospace', color:'#6b7280', marginRight:6 }}>
                    [{v.severity||'MAJOR'}]
                  </span>
                  {v.message || v.description || ''}
                </div>
              ))}
              {(ctrl.violations||[]).length > 3 && (
                <div style={{ padding:'5px 14px', fontSize:11, color:'#9ca3af', borderTop:'1px solid #fee2e2' }}>
                  + {ctrl.violations.length - 3} more violations
                </div>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* ══ GOVERNANCE MAPPING ══ */}
      <Section title="4b. Governance & Policy Alignment" icon="🏛">
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead>
            <tr style={{ background:'#f9fafb', borderBottom:'2px solid #e5e7eb' }}>
              {['NIST Function','Score','Status','Key Controls','Recommended Action'].map(h => (
                <th key={h} style={{ padding:'8px 10px', textAlign:'left', fontWeight:700,
                  color:'#374151', fontSize:11, textTransform:'uppercase', letterSpacing:.4 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {breakdown.map((fn, i) => {
              const meta = NIST_META[fn.function] || { color:'#6b7280', controls:'—', action:'Review controls.', short: fn.function };
              const pct  = Math.round(fn.score || 0);
              const fnStatus = fn.status || (pct >= 70 ? 'PASS' : 'FAIL');
              return (
                <tr key={fn.function} style={{ borderBottom:'1px solid #f3f4f6',
                  background: i%2===0?'#fff':'#f9fafb' }}>
                  <td style={{ padding:'8px 10px', fontWeight:700, color:meta.color }}>{fn.function}</td>
                  <td style={{ padding:'8px 10px', fontWeight:700 }}>{pct}%</td>
                  <td style={{ padding:'8px 10px' }}>
                    <Badge label={fnStatus} color={fnStatus==='PASS'?'#16a34a':'#dc2626'} />
                  </td>
                  <td style={{ padding:'8px 10px', fontSize:11, color:'#6b7280' }}>{meta.controls}</td>
                  <td style={{ padding:'8px 10px', fontSize:11, color:'#374151' }}>{meta.action}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Section>

      {/* ══ 5. DETAILED FINDINGS (Remediation) — page break ══ */}
      <div className="page-break" />
      <Section title="5. Detailed Findings & Remediation" icon="🔍">
        {cweFindings.slice(0,10).map((f) => {
          const bdr = f.severity==='Critical'?'#dc2626':f.severity==='High'?'#ea580c':f.severity==='Medium'?'#ca8a04':'#16a34a';
          const effort = f.cvss_score>=9?'1 day':f.cvss_score>=7?'4 hours':f.cvss_score>=4?'1 hour':'15 min';
          const tm = f.threatMapping || {};
          return (
            <div key={f.cwe_id} style={{ borderLeft:`4px solid ${bdr}`, background:'#fff',
              border:'1px solid #e5e7eb', borderRadius:8, padding:'14px 18px', marginBottom:14 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
                <div style={{ fontWeight:700, fontSize:13, color:'#111827' }}>
                  <span style={{ fontFamily:'monospace', color:'#1e40af', marginRight:8 }}>{f.cwe_id}</span>
                  {f.cwe_name}
                </div>
                <div style={{ display:'flex', gap:6 }}>
                  <Badge label={f.severity} color={SEV_BADGE[f.severity]||'#6b7280'} />
                  <span style={{ background:getCvssColor(f.cvss_score), color:'#fff', borderRadius:3,
                    padding:'2px 6px', fontFamily:'monospace', fontWeight:700, fontSize:11 }}>
                    CVSS {f.cvss_score}
                  </span>
                </div>
              </div>
              <div style={{ fontSize:12, color:'#374151', marginBottom:8 }}>{f.risk_impact}</div>
              <div style={{ display:'flex', flexWrap:'wrap', gap:4, marginBottom:8, fontSize:10 }}>
                {(tm.mitre||[]).map(t=><span key={t.id} style={{background:'#eff6ff',border:'1px solid #bfdbfe',borderRadius:3,padding:'1px 5px',color:'#1e40af',fontWeight:700}}>⚔️ {t.id}</span>)}
                {(tm.owasp||[]).map(o=><span key={o.id} style={{background:'#f5f3ff',border:'1px solid #c4b5fd',borderRadius:3,padding:'1px 5px',color:'#5b21b6',fontWeight:700}}>🛡️ {o.id}</span>)}
                {(tm.capec||[]).map(p=><span key={p.id} style={{background:'#fef2f2',border:'1px solid #fca5a5',borderRadius:3,padding:'1px 5px',color:'#991b1b',fontWeight:700}}>🎯 {p.id}</span>)}
              </div>
              <div style={{ fontSize:11, color:'#6b7280', marginBottom:6 }}>
                {f.issue_count} issue{f.issue_count!==1?'s':''} · {f.affected_files} file{f.affected_files!==1?'s':''} · Est. effort: <strong>{effort}</strong>
              </div>
              <div style={{ background:'#f0fdf4', border:'1px solid #86efac', borderRadius:6,
                padding:'8px 12px', fontSize:12, color:'#065f46' }}>
                <strong>Remediation:</strong> {f.remediation}
              </div>
            </div>
          );
        })}
        {cweFindings.length===0 && <div style={{color:'#9ca3af',fontSize:13}}>✅ No findings detected.</div>}
      </Section>

      {/* ══ 6. COMPLIANCE GAP MATRIX ══ */}
      <Section title="6. Compliance Gap Matrix" icon="📋">
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11, border:'1px solid #e5e7eb' }}>
          <thead>
            <tr style={{ background:'#f9fafb', borderBottom:'2px solid #e5e7eb' }}>
              {['Control Area','NIST CSF','State','Gap','Priority'].map(h=>(
                <th key={h} style={{ padding:'7px 8px', textAlign:'left', fontWeight:700,
                  color:'#374151', fontSize:10, textTransform:'uppercase', letterSpacing:.4, borderRight:'1px solid #e5e7eb' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              { area:'Access Control',      nist:'PR.AA-01',  fn:'PROTECT' },
              { area:'Data Security',        nist:'PR.DS-01',  fn:'PROTECT' },
              { area:'Vulnerability Mgmt',   nist:'DE.CM-08',  fn:'DETECT' },
              { area:'Secure Coding',        nist:'PR.PS-01',  fn:'PROTECT' },
              { area:'Logging & Monitoring', nist:'DE.CM-01',  fn:'DETECT' },
              { area:'Incident Response',    nist:'RS.MA-01',  fn:'RESPOND' },
              { area:'Risk Governance',      nist:'GV.RM-01',  fn:'GOVERN' },
              { area:'Asset Management',     nist:'ID.AM-01',  fn:'IDENTIFY' },
            ].map((row, i) => {
              const fnData = breakdown.find(b => b.function === row.fn);
              const fnScore = fnData ? Math.round(fnData.score || 0) : 100;
              const state = fnScore >= 80 ? 'Implemented' : fnScore >= 50 ? 'Partial' : 'Not Implemented';
              const stColor = state==='Implemented'?'#16a34a':state==='Partial'?'#ca8a04':'#dc2626';
              const pri = state==='Not Implemented'?'P1 Critical':state==='Partial'?'P2 High':'P3 Medium';
              return (
                <tr key={row.area} style={{ borderBottom:'1px solid #f3f4f6', background:i%2===0?'#fff':'#f9fafb' }}>
                  <td style={{ padding:'6px 8px', fontWeight:600, borderRight:'1px solid #f3f4f6' }}>{row.area}</td>
                  <td style={{ padding:'6px 8px', fontFamily:'monospace', fontSize:10, borderRight:'1px solid #f3f4f6' }}>{row.nist}</td>
                  <td style={{ padding:'6px 8px', borderRight:'1px solid #f3f4f6' }}><Badge label={state} color={stColor}/></td>
                  <td style={{ padding:'6px 8px', fontSize:10, color:'#6b7280', borderRight:'1px solid #f3f4f6' }}>
                    {state !== 'Implemented' ? `${row.fn} score ${fnScore}% — requires improvement` : 'Meets baseline'}
                  </td>
                  <td style={{ padding:'6px 8px', fontWeight:700, fontSize:10, color:stColor }}>{pri}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Section>

      {/* ══ 7. RISK REGISTER — page break ══ */}
      <div className="page-break" />
      <Section title="7. Risk Register" icon="⚠️">
        {cweFindings.filter(f => f.severity==='Critical'||f.severity==='High').length === 0 && (
          <div style={{ color:'#9ca3af', fontSize:13 }}>✅ No Critical or High risks to register.</div>
        )}
        {cweFindings.filter(f => f.severity==='Critical'||f.severity==='High').length > 0 && (
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:11, border:'1px solid #e5e7eb' }}>
            <thead>
              <tr style={{ background:'#f9fafb', borderBottom:'2px solid #e5e7eb' }}>
                {['Risk ID','Description','Likelihood','Impact','Score','Owner','Status','Target Date'].map(h=>(
                  <th key={h} style={{ padding:'7px 8px', textAlign:'left', fontWeight:700,
                    color:'#374151', fontSize:10, textTransform:'uppercase', borderRight:'1px solid #e5e7eb' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cweFindings.filter(f => f.severity==='Critical'||f.severity==='High').map((f, i) => {
                const likelihood = f.severity==='Critical'?5:4;
                const impact = f.cvss_score>=9?5:f.cvss_score>=7?4:3;
                const riskScore = likelihood * impact;
                const targetDays = f.severity==='Critical'?7:30;
                const targetDate = new Date(generatedAt); targetDate.setDate(targetDate.getDate()+targetDays);
                return (
                  <tr key={f.cwe_id} style={{ borderBottom:'1px solid #f3f4f6', background:i%2===0?'#fff':'#f9fafb' }}>
                    <td style={{ padding:'5px 8px', fontFamily:'monospace', fontWeight:700, color:'#991b1b', borderRight:'1px solid #f3f4f6' }}>
                      RISK-{String(i+1).padStart(3,'0')}
                    </td>
                    <td style={{ padding:'5px 8px', fontSize:10, borderRight:'1px solid #f3f4f6' }}>
                      {f.cwe_id}: {f.cwe_name} ({f.issue_count} issues)
                    </td>
                    <td style={{ padding:'5px 8px', textAlign:'center', fontWeight:700, borderRight:'1px solid #f3f4f6' }}>{likelihood}</td>
                    <td style={{ padding:'5px 8px', textAlign:'center', fontWeight:700, borderRight:'1px solid #f3f4f6' }}>{impact}</td>
                    <td style={{ padding:'5px 8px', textAlign:'center', fontWeight:800,
                      color: riskScore>=20?'#dc2626':'#ea580c', borderRight:'1px solid #f3f4f6' }}>{riskScore}</td>
                    <td style={{ padding:'5px 8px', fontSize:10, borderRight:'1px solid #f3f4f6' }}>Security Team</td>
                    <td style={{ padding:'5px 8px', borderRight:'1px solid #f3f4f6' }}>
                      <Badge label="Open" color="#dc2626" />
                    </td>
                    <td style={{ padding:'5px 8px', fontSize:10, fontWeight:600 }}>
                      {targetDate.toLocaleDateString()} ({targetDays}d)
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Section>

      {/* ══ 8. AUDIT ATTESTATION BLOCK ══ */}
      <Section title="8. Audit Attestation" icon="📎">
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <tbody>
            {[
              ['Report ID',              reportId],
              ['Report Date',            generatedAt.toLocaleString()],
              ['Project Name',           project.name],
              ['Project Key',            project.sonar_key || 'N/A'],
              ['CI/CD Platform',         'Parabellum IO security pipeline'],
              ['Tools Used',             `${toolsUsed}; CWE database; framework mapping (RAG / retriever + rules)`],
              ['Scan Coverage',          `${totalIssues} issues, ${cweFindings.length} CWEs, ${failedCtrl.length} failed controls`],
              ['Frameworks Assessed',    frameworks.map(f => `${f.frameworkLabel} (${f.overall?.score ?? '—'}%)`).join(', ') || 'NIST CSF 2.0'],
              ['Overall Verdict',        verdict],
              ['Report Generation',      'Auto-generated by GRC Compliance Dashboard'],
              ['Prepared By',            user?.name || 'Analyst'],
            ].map(([k,v]) => (
              <tr key={k} style={{ borderBottom:'1px solid #f3f4f6' }}>
                <td style={{ padding:'6px 10px', color:'#6b7280', fontWeight:600, width:'35%' }}>{k}</td>
                <td style={{ padding:'6px 10px', color:'#111827' }}>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ marginTop:20, padding:'14px 16px', background:'#fef3c7', border:'1px solid #fde68a',
          borderRadius:6, fontSize:11, color:'#92400e' }}>
          <strong>⚠️ Disclaimer:</strong> This report is machine-generated evidence supporting human audit
          review. It is not a substitute for a formal third-party audit. Results are based on static
          analysis and automated CWE/NIST mapping. Manual review by a qualified security professional
          is recommended before using this report for regulatory compliance purposes.
        </div>
        <div style={{ marginTop:14, textAlign:'center', fontSize:10, color:'#9ca3af', fontStyle:'italic' }}>
          {reportId} · {project.name} · CONFIDENTIAL
        </div>
      </Section>
    </div>
  );
}
ReportDoc.propTypes = {
  report: PropTypes.shape({
    compliance: PropTypes.object.isRequired,
    risk: PropTypes.object.isRequired,
    generatedAt: PropTypes.instanceOf(Date).isRequired,
    project: PropTypes.shape({
      name: PropTypes.string,
      sonar_key: PropTypes.string,
    }).isRequired,
  }).isRequired,
  user: PropTypes.shape({
    name: PropTypes.string,
  }),
};

// ── Page shell ───────────────────────────────────────────────────────────────
export default function ComplianceReportPage() {
  const [projects, setProjects] = useState([]);
  const [selId, setSelId]       = useState('');
  const [loading, setLoading]   = useState(false);
  const [report, setReport]     = useState(null);
  const [error, setError]       = useState('');
  const user = getUser();

  useEffect(() => {
    apiFetch(`${API_C}/projects`)
      .then(r => r.json())
      .then(d => Array.isArray(d) && setProjects(d))
      .catch(() => {});
  }, []);

  const selProj = projects.find(p => String(p.id) === String(selId));

  async function generate() {
    if (!selProj || selProj.needsScan) return;
    setLoading(true); setError(''); setReport(null);
    try {
      const body = fw => JSON.stringify({ projectId: selProj.id, projectName: selProj.name, framework: fw });
      const [rRes, ...fwRes] = await Promise.all([
        apiFetch(`${API_R}/analyze`, { method:'POST', body: JSON.stringify({ projectId: selProj.id }) }),
        ...ALL_FRAMEWORKS.map(f => apiFetch(`${API_C}/analyze`, { method:'POST', body: body(f.slug) })),
      ]);
      const rd = await rRes.json();
      const fwData = await Promise.all(fwRes.map(r => r.json().then(d => (r.ok ? d : { error: d.error }))));
      const cd = fwData[0];
      if (cd.error) { setError(cd.error || 'Compliance fetch failed'); return; }
      if (!rRes.ok) { setError(rd.error || 'Risk fetch failed'); return; }
      setReport({ compliance: cd, frameworks: fwData, risk: rd, generatedAt: new Date(), project: selProj });
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  function printReport() {
    const orig = document.title;
    document.title = `ComplianceReport_${selProj?.name}_${new Date().toISOString().slice(0,10)}`;
    globalThis.print();
    document.title = orig;
  }

  return (
    <Layout title="Compliance Report">
      <style>{`
        @media print {
          * {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          body {
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
          }
          .no-print, .sidebar, .topbar { display:none !important; }
          .app-shell, .main-area, .content-area { 
            display: block !important; 
            height: auto !important; 
            overflow: visible !important; 
            padding: 0 !important; 
            margin: 0 !important; 
          }
          .page-break { page-break-before: always; }
          @page { size: A4; margin: 18mm; }
        }
      `}</style>

      {/* Controls */}
      <div className="no-print" style={{ display:'flex', gap:12, alignItems:'center',
        background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, padding:'14px 18px', marginBottom:22 }}>
        <span style={{ fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:1 }}>
          Project
        </span>
        <select value={selId} onChange={e => { setSelId(e.target.value); setReport(null); }}
          style={{ flex:1, padding:'8px 12px', border:'1px solid #d1d5db',
            borderRadius:6, fontSize:13, background:'#f9fafb' }}>
          <option value="">— Choose a project —</option>
          {projects.map(p => (
            <option key={p.id} value={p.id} disabled={p.needsScan}>
              {p.name}{p.needsScan ? '  ⚠ Needs Scan First' : ` — ${p.openFindings} open findings`}
            </option>
          ))}
        </select>
        <button onClick={generate} disabled={!selProj || selProj.needsScan || loading}
          style={{ padding:'9px 20px', borderRadius:6, border:'none', cursor:'pointer',
            fontWeight:700, fontSize:13, whiteSpace:'nowrap',
            background: selProj && !selProj.needsScan ? '#1e40af' : '#d1d5db', color:'#fff' }}>
          {loading ? '⏳ Generating…' : '📊 Generate Report'}
        </button>
        {report && (
          <button onClick={printReport}
            style={{ padding:'9px 20px', borderRadius:6, border:'none', cursor:'pointer',
              fontWeight:700, fontSize:13, background:'#065f46', color:'#fff', whiteSpace:'nowrap' }}>
            🖨 Download PDF
          </button>
        )}
      </div>

      {error && (
        <div className="no-print" style={{ background:'#fef2f2', border:'1px solid #fca5a5',
          borderRadius:8, padding:14, marginBottom:20, color:'#991b1b', fontSize:13 }}>
          ❌ {error}
        </div>
      )}

      {!report && !loading && (
        <div className="no-print" style={{ textAlign:'center', padding:'80px 0', color:'#9ca3af' }}>
          <div style={{ fontSize:48, marginBottom:14 }}>📑</div>
          <div style={{ fontSize:18, fontWeight:700, color:'#374151', marginBottom:8 }}>
            Compliance Report Generator
          </div>
          <div style={{ fontSize:13, maxWidth:480, margin:'0 auto', lineHeight:1.7 }}>
            Select a scanned project and click <strong>Generate Report</strong> to produce
            a compliance report for all 6 frameworks (NIST CSF 2.0 in detail) with CWE risk analysis, based on the findings of every security tool.
          </div>
        </div>
      )}

      {loading && (
        <div className="no-print" style={{ textAlign:'center', padding:'80px 0', color:'#6b7280' }}>
          <div style={{ fontSize:48, marginBottom:14 }}>⏳</div>
          <div style={{ fontSize:14 }}>Running compliance analysis for 6 frameworks + CWE risk analysis…</div>
        </div>
      )}

      {report && <ReportDoc report={report} user={user} />}
    </Layout>
  );
}
