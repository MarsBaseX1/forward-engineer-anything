import {RULES} from './core.mjs';

// Generates reviewable runtime protection suggestions.
// Does not inject code, hook processes, or claim runtime defenses are unbypassable.
export function generateRuntimeSuggestions(report) {
  if (!report || !Array.isArray(report.findings) || !report.coverage) {
    throw Error('RUNTIME_INVALID_REPORT');
  }
  const suggestions = [];
  const hasAuth = report.findings.some(f => f.ruleId === 'FEA006');
  const hasData = report.findings.some(f => f.ruleId === 'FEA009');

  if (hasAuth || hasData) {
    suggestions.push({
      id: 'runtime-server-authoritative',
      ruleIds: ['FEA006', 'FEA009'].filter(id => report.findings.some(f => f.ruleId === id)),
      severity: 'high',
      title: 'Keep sensitive state and authorization server-authoritative',
      rationale: 'Client-side checks and exposed state can be observed or patched at runtime. Authoritative decisions must live on the server.',
      steps: [
        'Never store long-lived tokens or license keys in localStorage/sessionStorage for security decisions.',
        'Issue short-lived, scoped session tokens from the server after authentication.',
        'Re-validate sensitive operations on every request; do not trust client-reported entitlements.',
        'Consider binding sessions to additional signals (device, IP range) with clear UX trade-offs.',
        'Log and rate-limit anomalous client behavior on the server.'
      ],
      notice: 'Suggestion only. Runtime checks in the client remain bypassable. Server-side enforcement is the durable control.'
    });
  }

  suggestions.push({
    id: 'runtime-integrity-signals',
    ruleIds: [],
    severity: 'medium',
    title: 'Optional runtime integrity signals (non-blocking)',
    rationale: 'Light-weight signals can raise the cost of casual tampering but must not be the sole protection and can affect compatibility.',
    steps: [
      'Verify ASAR integrity at startup if Electron Fuses are enabled (already recommended by protect).',
      'Detect unexpected debugger attachment only as a soft signal; do not hard-fail in production without a support path.',
      'Prefer server-side anomaly detection over client-side anti-debug tricks.',
      'Document any runtime checks and provide a way to disable them for legitimate debugging builds.'
    ],
    notice: 'Optional. Aggressive anti-debug or integrity checks can break legitimate users and support workflows.'
  });

  return {
    formatVersion: 1,
    kind: 'fea-runtime-suggestions-v1',
    generatedFromFindings: report.findings.length,
    suggestions,
    notice: 'Runtime suggestions raise analysis and tampering cost. They do not make client code confidential or unmodifiable.'
  };
}

export function runtimeMarkdown(result) {
  const lines = ['# FEA runtime protection suggestions', '', '> ' + result.notice, ''];
  for (const s of result.suggestions) {
    lines.push('## ' + s.title, '', '**Severity:** ' + s.severity, '', s.rationale, '', '### Steps', '');
    s.steps.forEach((step, i) => lines.push((i + 1) + '. ' + step));
    lines.push('', '> ' + s.notice, '');
  }
  return lines.join('\n');
}
