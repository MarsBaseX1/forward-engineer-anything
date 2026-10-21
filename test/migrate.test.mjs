import test from 'node:test';
import assert from 'node:assert/strict';
import {generateMigrationSuggestions,migrationMarkdown} from '../src/migrate-suggestions.mjs';

test('generates suggestions for FEA006 and FEA007, none for other rules',()=>{
  const report={
    findings:[
      {ruleId:'FEA006',severity:'high',pathId:'a'.repeat(16),fingerprint:'b'.repeat(20)},
      {ruleId:'FEA007',severity:'high',pathId:'c'.repeat(16),fingerprint:'d'.repeat(20)},
      {ruleId:'FEA001',severity:'high',pathId:'e'.repeat(16),fingerprint:'f'.repeat(20)}
    ],
    coverage:{complete:true}
  };
  const result=generateMigrationSuggestions(report);
  assert.equal(result.suggestions.length,2);
  assert.ok(result.suggestions.some(s=>s.id==='migrate-client-auth'));
  assert.ok(result.suggestions.some(s=>s.id==='migrate-hardcoded-secrets'));
  assert.match(migrationMarkdown(result),/Move authorization/);
});

test('empty suggestions when no relevant findings',()=>{
  const report={findings:[{ruleId:'FEA001',severity:'high',pathId:'a'.repeat(16),fingerprint:'b'.repeat(20)}],coverage:{complete:true}};
  const result=generateMigrationSuggestions(report);
  assert.equal(result.suggestions.length,0);
  assert.match(migrationMarkdown(result),/No FEA006 or FEA007/);
});
