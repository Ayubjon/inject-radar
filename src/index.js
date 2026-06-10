// Public API for inject-radar.
//
//   import { scan } from 'inject-radar';
//   const result = scan(untrustedUserInput);
//   if (result.risk === 'high' || result.risk === 'critical') reject();

export { scan, riskLevel } from './scan.js';
export { RULES, SEVERITY_WEIGHT } from './rules.js';
export {
  normalize,
  stripZeroWidth,
  foldHomoglyphs,
  extractBase64,
} from './normalize.js';
export { formatReport } from './report.js';

export { default } from './scan.js';
