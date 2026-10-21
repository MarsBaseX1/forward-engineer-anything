import {RULES} from './core.mjs';

// Generates reviewable obfuscation recommendations from a trusted scan report.
// Does not run obfuscators, modify source, or claim that obfuscation prevents reverse engineering.
export function generateObfuscationSuggestions(report) {
  if (!report || !Array.isArray(report.findings) || !report.coverage) {
    throw Error('OBFUSCATION_INVALID_REPORT');
  }
  const suggestions = [];
  const hasUnobfuscated = report.findings.some(f => f.ruleId === 'FEA008');
  const hasSourceMap = report.findings.some(f => f.ruleId === 'FEA001');

  if (hasUnobfuscated || hasSourceMap) {
    suggestions.push({
      id: 'obfuscate-client-logic',
      ruleIds: ['FEA008', 'FEA001'].filter(id => report.findings.some(f => f.ruleId === id)),
      severity: 'medium',
      title: 'Consider optional client-side obfuscation after removing source maps',
      rationale: 'Readable business logic and source maps lower the cost of REA-style analysis. Obfuscation raises that cost but is not a confidentiality boundary and can affect debugging and performance.',
      options: [
        {
          tool: 'javascript-obfuscator',
          when: 'After confirming no source maps are shipped',
          notes: 'Control string array encoding and dead code injection carefully; measure bundle size and runtime impact.'
        },
        {
          tool: 'bytenode',
          when: 'For critical modules that can be compiled to V8 bytecode',
          notes: 'Bytecode is still reversible with effort; combine with server-side logic for sensitive decisions.'
        }
      ],
      steps: [
        'Remove or exclude all source maps from the release (FEA001).',
        'Identify modules with FEA008 findings (readable business functions or TODO comments).',
        'Apply an obfuscator only to those modules in a staging build.',
        'Run full functional regression and performance tests.',
        'Rescan the final resources and compare findings with Arena or manual review.'
      ],
      notice: 'Suggestion only. Obfuscation does not make code secret. Always keep a non-obfuscated debug build for support.'
    });
  }

  return {
    formatVersion: 1,
    kind: 'fea-obfuscation-suggestions-v1',
    generatedFromFindings: report.findings.length,
    suggestions,
    notice: 'Optional recommendations. Obfuscation raises analysis cost; it does not prevent reverse engineering or replace architectural protections.'
  };
}

export function obfuscationMarkdown(result) {
  const lines = ['# FEA obfuscation suggestions', '', '> ' + result.notice, ''];
  if (!result.suggestions.length) {
    lines.push('No FEA001 or FEA008 findings that trigger obfuscation suggestions.');
    return lines.join('\n');
  }
  for (const s of result.suggestions) {
    lines.push('## ' + s.title, '', s.rationale, '', '### Options', '');
    for (const o of s.options) {
      lines.push('- **' + o.tool + '** — ' + o.when, '  ' + o.notes);
    }
    lines.push('', '### Steps', '');
    s.steps.forEach((step, i) => lines.push((i + 1) + '. ' + step));
    lines.push('', '> ' + s.notice, '');
  }
  return lines.join('\n');
}
