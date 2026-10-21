import fs from 'node:fs';
import path from 'node:path';

// Evaluation protocol only: does NOT execute an attacker, inspect third-party binaries,
// call a model, or imply that non-success means an app cannot be reversed.
const STATUSES = new Set(['success', 'failure', 'timeout', 'infrastructure-error']);
const IDENTIFIER = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
const isNum = n => typeof n === 'number' && Number.isFinite(n) && n >= 0;
const check = (ok, code) => { if (!ok) throw new Error(code); };
const median = values => {
  if (!values.length) return null;
  const arr = [...values].sort((a,b)=>a-b), i=Math.floor(arr.length/2);
  return arr.length%2 ? arr[i] : (arr[i-1]+arr[i])/2;
};
const round = n => Math.round(n*10000)/10000;

export function validateSuite(suite) {
  check(suite && suite.formatVersion === 1 && IDENTIFIER.test(suite.suiteId ?? ''), 'ARENA_SUITE_FORMAT');
  check(suite.authorization === 'owned-or-authorized', 'ARENA_AUTHORIZATION_REQUIRED');
  check(Array.isArray(suite.tasks) && suite.tasks.length > 0 && suite.tasks.length <= 50, 'ARENA_TASKS');
  const ids = new Set();
  for (const task of suite.tasks) {
    check(task && IDENTIFIER.test(task.id ?? '') && !ids.has(task.id), 'ARENA_TASK_ID');
    ids.add(task.id);
  }
  check(Number.isSafeInteger(suite.minTrials) && suite.minTrials >= 10 && suite.minTrials <= 1000, 'ARENA_MIN_TRIALS');
  check(suite.budget && Number.isSafeInteger(suite.budget.maxDurationMs) && suite.budget.maxDurationMs > 0 && isNum(suite.budget.maxCostUsd), 'ARENA_BUDGET');
  return suite;
}

export function validateRun(run, suite, variant) {
  validateSuite(suite);
  check(run && run.formatVersion === 1 && run.suiteId === suite.suiteId && run.variant === variant, 'ARENA_RUN_FORMAT');
  check(typeof run.artifactDigest === 'string' && /^[a-f0-9]{64}$/.test(run.artifactDigest), 'ARENA_DIGEST');
  const e = run.engine;
  check(e && ['synthetic','external'].includes(e.kind) &&
    ['id','version','model','environment'].every(key=>IDENTIFIER.test(e[key]??'')), 'ARENA_ENGINE');
  check(Array.isArray(run.trials) && run.trials.length <= 50000, 'ARENA_TRIALS');
  const ids = new Set(suite.tasks.map(x=>x.id)), seen = new Set();
  const counts = new Map(suite.tasks.map(x=>[x.id,0]));
  for (const t of run.trials) {
    check(t && ids.has(t.taskId) && Number.isSafeInteger(t.seed) && t.seed>=0 &&
      typeof t.status === 'string' && STATUSES.has(t.status) &&
      isNum(t.durationMs) && isNum(t.costUsd) && t.durationMs <= suite.budget.maxDurationMs &&
      t.costUsd <= suite.budget.maxCostUsd, 'ARENA_TRIAL_INVALID');
    const key=t.taskId+':'+t.seed;
    check(!seen.has(key), 'ARENA_DUPLICATE_TRIAL');
    seen.add(key);
    if (t.status !== 'infrastructure-error') counts.set(t.taskId,counts.get(t.taskId)+1);
  }
  for (const count of counts.values()) check(count>=suite.minTrials,'ARENA_NOT_ENOUGH_VALID_TRIALS');
  return run;
}

function aggregate(trials) {
  const valid=trials.filter(t=>t.status!=='infrastructure-error');
  const successes=valid.filter(t=>t.status==='success');
  return {
    trials:trials.length, validTrials:valid.length, successes:successes.length,
    failures:valid.filter(t=>t.status==='failure').length,
    timeouts:valid.filter(t=>t.status==='timeout').length,
    infrastructureErrors:trials.length-valid.length,
    successRate:round(successes.length/valid.length),
    medianSuccessfulDurationMs:median(successes.map(t=>t.durationMs)),
    medianValidCostUsd:median(valid.map(t=>t.costUsd)),
    budgetCensored:valid.filter(t=>t.status==='timeout').length
  };
}

export function compareArena(suite, before, after) {
  validateRun(before,suite,'baseline');validateRun(after,suite,'hardened');
  check(before.artifactDigest !== after.artifactDigest,'ARENA_SAME_ARTIFACT');
  check(JSON.stringify(before.engine)===JSON.stringify(after.engine),'ARENA_ENGINE_MISMATCH');
  const pairs=[];
  for (const task of suite.tasks) {
    const a=before.trials.filter(t=>t.taskId===task.id).sort((x,y)=>x.seed-y.seed);
    const b=after.trials.filter(t=>t.taskId===task.id).sort((x,y)=>x.seed-y.seed);
    check(a.length===b.length && a.every((t,i)=>t.seed===b[i].seed),'ARENA_UNPAIRED_SEEDS');
    pairs.push({taskId:task.id,baseline:aggregate(a),hardened:aggregate(b)});
  }
  return {
    formatVersion:1,suiteId:suite.suiteId,engine:before.engine,budget:suite.budget,
    artifacts:{baseline:before.artifactDigest,hardened:after.artifactDigest},
    tasks:pairs,kind:before.engine.kind,
    reproducibility:{minTrials:suite.minTrials,pairedSeeds:true,modelVersionPinned:true},
    notice:before.engine.kind==='synthetic' ?
      'SCRIPTED FIXTURE DEMO ONLY. No AI agent or reverse engineering was exercised; these metrics are NOT AI resistance measurements.' :
      'External run-log evaluation only. Metrics are unverified inputs; no claim of immunity or independent benchmark is made.'
  };
}

export function arenaMarkdown(result) {
  const lines=['# FEA Arena — paired evaluation report','',
    `**Suite:** \`${result.suiteId}\` · **Runner type:** \`${result.kind}\``,
    `**Engine:** \`${result.engine.id}\` / \`${result.engine.version}\` / \`${result.engine.model}\``,
    `**Budget per trial:** ${result.budget.maxDurationMs} ms, USD ${result.budget.maxCostUsd}`,
    `**Minimum valid trials per task:** ${result.reproducibility.minTrials}`,'',
    '| Task | Baseline successes | Hardened successes | Timeouts baseline / hardened |',
    '| --- | ---: | ---: | ---: |'];
  for(const t of result.tasks)lines.push(`| ${t.taskId} | ${t.baseline.successes}/${t.baseline.validTrials} | ${t.hardened.successes}/${t.hardened.validTrials} | ${t.baseline.timeouts}/${t.hardened.timeouts} |`);
  lines.push('',`> ${result.notice}`,'',
    'Success indicates the declared task reached its own success condition. A timeout only means no success **within the specified budget**.','',
    'All raw attempts, environment and model/tool pinning should be retained in restricted CI storage for independent reproduction.','');
  return lines.join('\n');
}

export function loadArenaJson(file, maxBytes=4_000_000) {
  const stat=fs.lstatSync(file);
  check(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maxBytes,'ARENA_INPUT_UNSUPPORTED');
  return JSON.parse(fs.readFileSync(path.resolve(file),'utf8'));
}
