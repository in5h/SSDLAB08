import PropTypes from 'prop-types';

// Recommended fix for one finding: why it matters, numbered steps, the tool's own advice,
// a code example, priority/effort and how the fix is verified.
const pre = { margin: '6px 0', fontFamily: 'Consolas, monospace', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px' };
const head = { margin: '12px 0 6px', fontSize: 13, textTransform: 'uppercase', letterSpacing: '.04em', color: 'var(--muted)' };

export default function FixPlan({ plan, title = 'Recommended fix', verified = false }) {
  if (!plan) return null;
  return (
    <div className="fix-plan" style={{ border: '1px solid var(--border)', borderLeft: `4px solid ${verified ? 'var(--success)' : 'var(--primary)'}`, borderRadius: 8, padding: '10px 14px', marginTop: 10, background: 'var(--panel)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', alignItems: 'baseline' }}>
        <strong style={{ fontSize: 14 }}>🛠 {title}</strong>
        <span style={{ fontSize: 12, color: 'var(--muted)' }}>{plan.priority} · effort {plan.effort} · fix within {plan.slaDays} days</span>
      </div>
      {plan.summary && <div style={{ fontSize: 13, marginTop: 4 }}>{plan.summary}</div>}
      {plan.why && <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 4, fontStyle: 'italic' }}>{plan.why}</div>}
      <ol style={{ margin: '8px 0 4px 18px', padding: 0, fontSize: 13, lineHeight: 1.6 }}>
        {plan.steps.map(s => <li key={s}>{s}</li>)}
      </ol>
      {plan.toolAdvice && <>
        <div style={head}>{plan.toolAdviceSource} advice</div>
        <div style={{ ...pre, fontFamily: 'inherit', fontSize: 12.5 }}>{plan.toolAdvice}</div>
      </>}
      {plan.example && <>
        <div style={head}>Example</div>
        <pre style={pre}>{plan.example}</pre>
      </>}
      <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 6 }}><strong>How to check the fix:</strong> {plan.verification}</div>
    </div>
  );
}

FixPlan.propTypes = { plan: PropTypes.object, title: PropTypes.string, verified: PropTypes.bool };
