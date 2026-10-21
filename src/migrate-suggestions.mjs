import {RULES} from './core.mjs';

// Generates reviewable, non-destructive migration suggestions from a trusted scan report.
// Does not modify source, execute code, or claim that following the suggestions makes software un-reversible.
export function generateMigrationSuggestions(report) {
  if (!report || !Array.isArray(report.findings) || !report.coverage) {
    throw Error('MIGRATE_INVALID_REPORT');
  }
  const suggestions = [];
  const seen = new Set();

  for (const f of report.findings) {
    if (f.ruleId === 'FEA006' && !seen.has('auth')) {
      seen.add('auth');
      suggestions.push({
        id: 'migrate-client-auth',
        ruleIds: ['FEA006'],
        severity: 'high',
        title: 'Move authorization and license decisions to the server',
        rationale: 'Client-side checks (isPremium, checkLicense, etc.) can be bypassed by patching or reimplementing the delivered code. Server-side enforcement raises the cost of unauthorized use.',
        steps: [
          'Identify all client-side entitlement or license checks.',
          'Move the authoritative decision to a server endpoint that the client must call.',
          'Have the server return only the minimum data required for the UI.',
          'Treat any remaining client-side check as cosmetic only; never rely on it for security.',
          'Add server-side rate limiting, revocation, and audit logging.'
        ],
        example: {
          before: 'if (isPremium()) { showAdvancedFeatures(); }',
          after: 'const entitlements = await fetch(\'/api/entitlements\').then(r => r.json()); if (entitlements.advanced) { showAdvancedFeatures(); }'
        },
        notice: 'Suggestion only. Does not automatically rewrite code. Client code remains analyzable after migration.'
      });
    }
    if (f.ruleId === 'FEA007' && !seen.has('secret')) {
      seen.add('secret');
      suggestions.push({
        id: 'migrate-hardcoded-secrets',
        ruleIds: ['FEA007'],
        severity: 'high',
        title: 'Remove hardcoded secrets and credentials from client delivery',
        rationale: 'Hardcoded API keys, tokens or secrets in shipped resources can be extracted by static analysis or REA-style agents.',
        steps: [
          'Rotate any exposed credentials immediately.',
          'Move secret material to server-side configuration or a secret manager.',
          'If the client needs to call a third-party API, proxy the call through your own backend.',
          'Use short-lived, scoped tokens issued by your server instead of long-lived client keys.',
          'Rescan the release resources after the change to confirm the finding is gone.'
        ],
        example: {
          before: 'const api_key = "sk-...long-secret...";',
          after: 'const token = await fetch(\'/api/session-token\').then(r => r.json()); // short-lived, server-issued'
        },
        notice: 'Suggestion only. Rotating real secrets and updating call sites is the developer\'s responsibility.'
      });
    }
  }

  return {
    formatVersion: 1,
    kind: 'fea-migration-suggestions-v1',
    generatedFromFindings: report.findings.length,
    suggestions,
    notice: 'These are architectural recommendations based on static findings. They do not prove that reverse engineering is prevented. Always review and test changes.'
  };
}

export function migrationMarkdown(result) {
  const lines = [
    '# FEA migration suggestions',
    '',
    '> ' + result.notice,
    ''
  ];
  if (!result.suggestions.length) {
    lines.push('No FEA006 or FEA007 findings that trigger migration suggestions.');
    return lines.join('\n');
  }
  for (const s of result.suggestions) {
    lines.push('## ' + s.title, '', '**Severity:** ' + s.severity, '', s.rationale, '', '### Steps', '');
    s.steps.forEach((step, i) => lines.push((i + 1) + '. ' + step));
    lines.push('', '### Example', '', '**Before**', '```js', s.example.before, '```', '', '**After**', '```js', s.example.after, '```', '', '> ' + s.notice, '');
  }
  return lines.join('\n');
}
