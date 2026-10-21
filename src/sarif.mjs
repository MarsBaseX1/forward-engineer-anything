import {RULES, validateReport, VERSION} from './core.mjs';
import crypto from 'node:crypto';

// A repository-tracked anchor is intentional: public SARIF must not reveal
// distributed binary/resource paths or snippets, while GitHub needs a physical
// location for each alert. It is NOT the affected file's source location.
export const SARIF_ANCHOR = '.github/fea-sarif-anchor.md';
const HEX = /^[a-f0-9]{64}$/;
const LEVEL = Object.freeze({critical:'error',high:'error',medium:'warning'});
const MAX_RESULTS = 5000;

export function toSarif(report) {
  validateReport(report);
  if (!report.coverage.complete || report.coverage.errors.length ||
      Object.keys(RULES).some(rule=>!report.coverage.ruleIds.includes(rule))) {
    throw Error('SARIF_INCOMPLETE_COVERAGE');
  }
  if (report.findings.length > MAX_RESULTS) throw Error('SARIF_RESULTS_LIMIT');
  if (!HEX.test(report.inputDigest)) throw Error('SARIF_INPUT_DIGEST_INVALID');
  const seen=new Set();
  const results=report.findings.map(f=>{
    const key=`${f.ruleId}:${f.pathId}`;
    if (seen.has(key)) throw Error('SARIF_DUPLICATE_FINDING');
    seen.add(key);
    // ALL externally observable fields are owned by FEA's catalog, never from
    // report message, path, user input, or arbitrary extension properties.
    return {
      ruleId:f.ruleId,
      level:LEVEL[RULES[f.ruleId].severity],
      message:{text:`${RULES[f.ruleId].title}. A distributed Electron asset triggered this rule; inspect the trusted private FEA report using its hashed path ID.`},
      locations:[{physicalLocation:{artifactLocation:{uri:SARIF_ANCHOR},region:{startLine:1}}}],
      partialFingerprints:{primaryLocationLineHash:crypto.createHash('sha256').update(`${f.ruleId}:${f.fingerprint}`).digest('hex')},
      properties:{feaHashedPathId:f.pathId,feaScope:'shipped-electron-resource',securitySeverity:RULES[f.ruleId].severity}
    };
  }).sort((a,b)=>a.ruleId.localeCompare(b.ruleId)||a.properties.feaHashedPathId.localeCompare(b.properties.feaHashedPathId));
  return {
    $schema:'https://json.schemastore.org/sarif-2.1.0.json',
    version:'2.1.0',
    runs:[{
      tool:{driver:{name:'Forward Engineer Anything',version:VERSION,
        informationUri:'https://github.com/MarsBaseX1/forward-engineer-anything',
        rules:Object.entries(RULES).map(([id,rule])=>({id,name:id,
          shortDescription:{text:rule.title},
          fullDescription:{text:`${rule.title}. Applies to Electron release resources and may require manual review.`},
          defaultConfiguration:{level:LEVEL[rule.severity]},
          properties:{tags:['security','release-hygiene'],securitySeverity:rule.severity}
        }))}},
      invocations:[{executionSuccessful:true}],
      results,
      properties:{feaReportVersion:report.formatVersion,feaInputStage:report.inputStage,
        feaInputDigest:report.inputDigest,
        notice:'Privacy anchor, not real finding location. Observed release-resource exposures only; neither zero alerts nor scan coverage proves reverse-engineering resistance.'}
    }]
  };
}
