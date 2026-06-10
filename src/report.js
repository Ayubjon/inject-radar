// Human-readable rendering of a scan result for terminals and logs.

const RISK_LABEL = {
  none: 'NONE',
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Render a scan result as a plain-text report.
 * @param {{score:number, risk:string, findings:Array, stats:object}} result
 * @param {{ label?: string }} [opts]
 * @returns {string}
 */
export function formatReport(result, opts = {}) {
  const lines = [];
  const title = opts.label ? `inject-radar — ${opts.label}` : 'inject-radar report';
  lines.push(title);
  lines.push(`risk: ${RISK_LABEL[result.risk] ?? result.risk}  (score ${result.score}/100)`);

  if (result.findings.length === 0) {
    lines.push('no prompt-injection signals detected.');
    return lines.join('\n');
  }

  const sorted = [...result.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );

  lines.push(`${result.findings.length} finding(s):`);
  for (const f of sorted) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.ruleId} (${f.category})`);
    lines.push(`      ${f.description}`);
    lines.push(`      match: ${f.snippet}`);
  }
  return lines.join('\n');
}

export default formatReport;
