import PropTypes from 'prop-types';
import FixPlan from './FixPlan';

// Full details of one scan result, shown when a row is expanded.
const box = { background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px' };
const pre = { margin: 0, fontFamily: 'Consolas, monospace', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word' };

function Row({ label, children }) {
  if (children === null || children === undefined || children === '' || (Array.isArray(children) && !children.length)) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 10, fontSize: 13, marginBottom: 6 }}>
      <div style={{ color: 'var(--muted)', fontWeight: 600 }}>{label}</div>
      <div style={{ wordBreak: 'break-word' }}>{children}</div>
    </div>
  );
}
Row.propTypes = { label: PropTypes.string.isRequired, children: PropTypes.node };

const list = v => (Array.isArray(v) ? v.filter(Boolean).join(', ') : v);

export default function IssueDetails({ issue }) {
  const location = issue.url || (issue.component || issue.file ? `${issue.component || issue.file}${issue.line ? `:${issue.line}` : ''}` : null);
  const fix = issue.solution || issue.resolution || issue.remediation || issue.fix || null;
  const urls = issue.affectedUrls || issue.urls;
  return (
    <div style={{ padding: '14px 16px', background: 'rgba(139,111,71,0.04)', borderTop: '1px solid var(--border)' }}>
      <div style={{ ...box, marginBottom: 10, fontSize: 14, lineHeight: 1.5 }}>{issue.message || issue.title}</div>
      <Row label="Rule">{issue.rule}</Row>
      <Row label="Rule name">{issue.ruleName}</Row>
      <Row label="Tool">{issue.tool}{issue.engine === 'built-in' ? ' (built-in checks)' : ''}</Row>
      <Row label="Risk">{issue.risk ? `${issue.risk} (${issue.riskScore}/10)` : null}</Row>
      <Row label="Location">{location}</Row>
      <Row label="CWE">{list(issue.cwe)}{issue.cweName ? ` — ${issue.cweName}` : ''}</Row>
      <Row label="OWASP">{list(issue.owasp)}</Row>
      <Row label="CVE">{list(issue.cve)}</Row>
      <Row label="Package">{issue.pkgName || issue.packageName || issue.package_name
        ? `${issue.pkgName || issue.packageName || issue.package_name} ${issue.installedVersion || issue.packageVersion || issue.installed_version || ''} → fixed in ${issue.fixedVersion || list(issue.fixedIn) || issue.fixed_version || 'n/a'}`
        : null}</Row>
      <Row label="Confidence">{issue.confidence ? `${issue.confidence}${issue.confidenceReasons ? ` — ${issue.confidenceReasons.join('; ')}` : ''}` : null}</Row>
      <Row label="Explanation"><span style={{ whiteSpace: 'pre-wrap' }}>{issue.description}</span></Row>
      {!issue.fixPlan && <Row label="How to fix">{fix}</Row>}
      <Row label="URLs">{urls?.length ? urls.slice(0, 10).join('\n') : null}</Row>
      {(issue.snippet || issue.evidence) && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 600, marginBottom: 4 }}>Code evidence</div>
          <div style={box}><pre style={pre}>{issue.evidence || issue.snippet}</pre></div>
        </div>
      )}
      <FixPlan plan={issue.fixPlan} />
      {issue.references?.length > 0 && (
        <Row label="References">
          {issue.references.slice(0, 5).map(r => <div key={r}><a href={r} target="_blank" rel="noreferrer">{r}</a></div>)}
        </Row>
      )}
    </div>
  );
}

IssueDetails.propTypes = { issue: PropTypes.object.isRequired };
