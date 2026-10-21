import test from 'node:test';
import assert from 'node:assert/strict';
import {generateObfuscationSuggestions,obfuscationMarkdown} from '../src/obfuscation-suggestions.mjs';

test('suggests obfuscation when FEA008 or FEA001 present',()=>{
  const report={
    findings:[
      {ruleId:'FEA008',severity:'medium',pathId:'a'.repeat(16),fingerprint:'b'.repeat(20)},
      {ruleId:'FEA001',severity:'high',pathId:'c'.repeat(16),fingerprint:'d'.repeat(20)}
    ],
    coverage:{complete:true}
  };
  const result=generateObfuscationSuggestions(report);
  assert.equal(result.suggestions.length,1);
  assert.equal(result.suggestions[0].id,'obfuscate-client-logic');
  assert.match(obfuscationMarkdown(result),/javascript-obfuscator/);
});

test('no suggestions when relevant findings absent',()=>{
  const report={findings:[{ruleId:'FEA003',severity:'high',pathId:'a'.repeat(16),fingerprint:'b'.repeat(20)}],coverage:{complete:true}};
  const result=generateObfuscationSuggestions(report);
  assert.equal(result.suggestions.length,0);
  assert.match(obfuscationMarkdown(result),/No FEA001 or FEA008/);
});
