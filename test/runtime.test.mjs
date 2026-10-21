import test from 'node:test';
import assert from 'node:assert/strict';
import {generateRuntimeSuggestions,runtimeMarkdown} from '../src/runtime-suggestions.mjs';

test('suggests server-authoritative controls when FEA006 or FEA009 present',()=>{
  const report={
    findings:[
      {ruleId:'FEA006',severity:'high',pathId:'a'.repeat(16),fingerprint:'b'.repeat(20)},
      {ruleId:'FEA009',severity:'high',pathId:'c'.repeat(16),fingerprint:'d'.repeat(20)}
    ],
    coverage:{complete:true}
  };
  const result=generateRuntimeSuggestions(report);
  assert.ok(result.suggestions.some(s=>s.id==='runtime-server-authoritative'));
  assert.match(runtimeMarkdown(result),/server-authoritative/);
});

test('always includes optional integrity signals',()=>{
  const report={findings:[],coverage:{complete:true}};
  const result=generateRuntimeSuggestions(report);
  assert.ok(result.suggestions.some(s=>s.id==='runtime-integrity-signals'));
});
