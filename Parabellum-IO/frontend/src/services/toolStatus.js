// Turns a /api/tools/status entry into a label + colour shown on the Tools page,
// Dashboard and Security Scans tabs.
//   connected — the real tool answered
//   builtin   — real tool missing; only Parabellum's basic built-in checks can run
//   missing   — real tool missing and there is no fallback
export function toolState(s) {
  if (!s) return { kind: 'checking', label: 'Checking…', color: 'neutral', dot: '#a3a3a3' };
  if (s.available) return { kind: 'connected', label: 'Connected', color: 'success', dot: '#22c55e' };
  if (s.builtInFallback) return { kind: 'builtin', label: 'Not installed · basic checks only', color: 'warning', dot: '#f59e0b' };
  return { kind: 'missing', label: 'Not Connected', color: 'danger', dot: '#ef4444' };
}
