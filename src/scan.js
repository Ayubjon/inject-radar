// Core scanning engine. Runs the rule set against normalized text, folds in
// obfuscation signals, and produces an explainable 0-100 risk score.

import { RULES, SEVERITY_WEIGHT } from './rules.js';
import { normalize } from './normalize.js';

const RISK_THRESHOLDS = [
  { level: 'critical', min: 70 },
  { level: 'high', min: 40 },
  { level: 'medium', min: 20 },
  { level: 'low', min: 1 },
  { level: 'none', min: 0 },
];

/**
 * Map a numeric score (0-100) to a named risk level.
 * @param {number} score
 * @returns {'none'|'low'|'medium'|'high'|'critical'}
 */
export function riskLevel(score) {
  for (const t of RISK_THRESHOLDS) {
    if (score >= t.min) return t.level;
  }
  return 'none';
}

function snippet(text, index, len) {
  const start = Math.max(0, index - 12);
  const end = Math.min(text.length, index + len + 12);
  return (start > 0 ? '…' : '') + text.slice(start, end) + (end < text.length ? '…' : '');
}

function matchRules(text, rules, source) {
  const findings = [];
  for (const rule of rules) {
    const m = rule.pattern.exec(text);
    if (!m) continue;
    findings.push({
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      weight: SEVERITY_WEIGHT[rule.severity],
      match: m[0],
      index: m.index,
      snippet: snippet(text, m.index, m[0].length),
      source,
      description: rule.description,
    });
  }
  return findings;
}

/**
 * Scan text for prompt-injection signals.
 * @param {string} text
 * @param {{ rules?: typeof RULES }} [options]
 * @returns {{
 *   score: number,
 *   risk: string,
 *   findings: Array<object>,
 *   stats: { zeroWidth: number, homoglyphs: number, base64Decoded: number }
 * }}
 */
export function scan(text, options = {}) {
  const rules = options.rules ?? RULES;
  const input = typeof text === 'string' ? text : String(text ?? '');
  const norm = normalize(input);

  const findings = matchRules(norm.normalized, rules, 'text');

  // Obfuscation signals are themselves suspicious.
  if (norm.zeroWidth > 0) {
    findings.push({
      ruleId: 'obfuscation.zero-width',
      category: 'obfuscation',
      severity: 'medium',
      weight: SEVERITY_WEIGHT.medium,
      match: `${norm.zeroWidth} zero-width character(s)`,
      index: -1,
      snippet: `${norm.zeroWidth} invisible character(s) stripped before matching`,
      source: 'meta',
      description: 'Hidden zero-width characters used to break up trigger phrases.',
    });
  }
  if (norm.homoglyphs > 0) {
    findings.push({
      ruleId: 'obfuscation.homoglyph',
      category: 'obfuscation',
      severity: 'medium',
      weight: SEVERITY_WEIGHT.medium,
      match: `${norm.homoglyphs} homoglyph(s)`,
      index: -1,
      snippet: `${norm.homoglyphs} confusable character(s) folded to ASCII`,
      source: 'meta',
      description: 'Look-alike Unicode characters used to evade keyword filters.',
    });
  }

  // Re-scan any base64 payloads; only flag if the decoded text itself is an attack.
  let base64Decoded = 0;
  for (const hit of norm.base64) {
    const decodedNorm = normalize(hit.decoded).normalized;
    const decodedFindings = matchRules(decodedNorm, rules, 'base64');
    if (decodedFindings.length > 0) {
      base64Decoded += 1;
      for (const f of decodedFindings) {
        f.snippet = `base64 payload decodes to: ${f.snippet}`;
        findings.push(f);
      }
    }
  }

  const sum = findings.reduce((acc, f) => acc + f.weight, 0);
  const score = Math.min(100, sum);

  return {
    score,
    risk: riskLevel(score),
    findings,
    stats: {
      zeroWidth: norm.zeroWidth,
      homoglyphs: norm.homoglyphs,
      base64Decoded,
    },
  };
}

export default scan;
