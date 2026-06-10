# Changelog

All notable changes to this project are documented here.

## 1.0.0

Initial release.

- Core `scan(text)` engine returning an explainable 0–100 risk score, named
  risk band, per-finding reasons, and obfuscation stats.
- 16 detection rules across 8 categories: instruction-override, jailbreak,
  refusal-suppression, system-prompt-leak, exfiltration, code-execution,
  delimiter-injection, and obfuscation.
- Obfuscation defenses: zero-width stripping, homoglyph folding, and base64
  payload decoding before matching.
- `inject-radar` CLI with `--threshold` CI gate, `--json`, `--quiet`, and
  `--label` options.
- Express middleware and quickstart examples.
- Zero runtime dependencies; pure ESM; `node:test` suite.
