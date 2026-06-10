#!/usr/bin/env node
// inject-radar CLI — scan text or files for prompt-injection signals.
// Exit code is 1 when the risk score meets/exceeds --threshold, making it a
// drop-in CI gate. Reads from a file argument or from stdin.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scan } from '../src/scan.js';
import { formatReport } from '../src/report.js';

const HELP = `inject-radar — zero-dependency prompt-injection scanner

Usage:
  inject-radar [file] [options]
  cat prompt.txt | inject-radar [options]

Options:
  --threshold <n>   Fail (exit 1) when score >= n. Default: 50
  --json            Output the raw result as JSON
  --quiet           Print nothing unless the threshold is exceeded
  --label <text>    Label shown in the report header
  -h, --help        Show this help
  -v, --version     Show version

Examples:
  inject-radar user_prompt.txt --threshold 40
  echo "ignore all previous instructions" | inject-radar --json`;

function getVersion() {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    return JSON.parse(readFileSync(pkgPath, 'utf8')).version;
  } catch {
    return '0.0.0';
  }
}

export function parseArgs(argv) {
  const opts = { threshold: 50, json: false, quiet: false, label: undefined, file: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--quiet') opts.quiet = true;
    else if (a === '--threshold') opts.threshold = Number(argv[++i]);
    else if (a === '--label') opts.label = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (!a.startsWith('-')) opts.file = a;
  }
  if (!Number.isFinite(opts.threshold)) opts.threshold = 50;
  return opts;
}

function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (opts.version) {
    process.stdout.write(getVersion() + '\n');
    return 0;
  }

  let input = '';
  if (opts.file) {
    try {
      input = readFileSync(opts.file, 'utf8');
    } catch (err) {
      process.stderr.write(`inject-radar: cannot read ${opts.file}: ${err.message}\n`);
      return 2;
    }
  } else {
    input = readStdin();
  }

  if (!input.trim()) {
    process.stderr.write('inject-radar: no input provided (pass a file or pipe text to stdin)\n');
    return 2;
  }

  const result = scan(input);
  const failed = result.score >= opts.threshold;

  if (opts.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else if (!opts.quiet || failed) {
    process.stdout.write(formatReport(result, { label: opts.label }) + '\n');
  }

  return failed ? 1 : 0;
}

// Only run when invoked directly (not when imported by tests).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code));
}
