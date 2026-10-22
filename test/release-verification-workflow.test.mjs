import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('independent release verification downloads and validates assets before publishing', () => {
  const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'fea-release-verify.yml'), 'utf8');
  assert.ok(workflow.includes('releases?per_page=100'), 'Draft release metadata must be resolved from the releases list');
  assert.ok(workflow.includes('releases/assets/$asset_id'), 'Download assets by API asset ID so drafts are supported');
  assert.ok(workflow.includes('gh api -H "Accept: application/octet-stream"'), 'Use the authenticated GitHub CLI to safely follow asset redirects');
  assert.ok(!workflow.includes('Authorization: Bearer $GH_TOKEN'), 'Do not manually forward the token across asset redirects');
  assert.ok(!workflow.includes('gh release download'), 'Do not use the tag-only download endpoint for draft releases');
  assert.ok(workflow.includes('sha256sum -c SHA256SUMS.txt'));
  assert.ok(workflow.includes('gh attestation verify'));
  assert.ok(workflow.includes('--signer-workflow'));
  assert.ok(workflow.includes('--source-ref refs/heads/main'));
  assert.ok(workflow.includes('--source-digest'));
  assert.ok(workflow.includes('2.102.0'), 'Use a GitHub CLI version with the patched signer-workflow identity check');
  assert.ok(workflow.includes('npm install --offline'));
  assert.ok(workflow.includes('npm-pack.json'));
  assert.ok(workflow.includes('SHA-1 and SHA-512 match npm metadata'));
  assert.ok(workflow.includes('needs: verify'));
  assert.ok(workflow.includes("needs.verify.outputs.release_is_draft == 'true'"));
  assert.ok(workflow.includes("github.event_name == 'push'"));
  assert.ok(workflow.includes('gh api --method PATCH'));
  assert.ok(workflow.includes('-F draft=false'));
});
