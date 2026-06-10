// Text normalization helpers used to defeat common obfuscation tricks before
// pattern matching. All functions are pure and dependency-free.

// Invisible / formatting code points frequently abused to break up trigger
// phrases (e.g. "ig<ZWSP>nore previous instructions").
const ZERO_WIDTH_RE = /[​-‍⁠⁡⁢⁣⁤﻿­᠎]/g;

// Map of common confusable characters (Cyrillic / Greek / fullwidth) to their
// plain ASCII Latin equivalent. Attackers swap these in to slip past naive
// keyword filters while keeping the text visually identical.
const HOMOGLYPHS = {
  // Cyrillic -> Latin
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', к: 'k',
  м: 'm', т: 't', в: 'b', н: 'h', і: 'i', ј: 'j', ѕ: 's', А: 'A',
  Е: 'E', О: 'O', Р: 'P', С: 'C', Х: 'X', У: 'Y', К: 'K', М: 'M',
  Т: 'T', В: 'B', Н: 'H',
  // Greek -> Latin
  ο: 'o', ρ: 'p', ε: 'e', α: 'a', ι: 'i', ν: 'v', Α: 'A', Ε: 'E',
  Ο: 'O', Ρ: 'P', Τ: 'T', Χ: 'X',
};

// Candidate base64 runs: long-ish, base64 alphabet, optional padding.
const BASE64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;

/**
 * Remove zero-width / invisible characters.
 * @param {string} text
 * @returns {{ text: string, count: number }}
 */
export function stripZeroWidth(text) {
  let count = 0;
  const cleaned = String(text).replace(ZERO_WIDTH_RE, () => {
    count += 1;
    return '';
  });
  return { text: cleaned, count };
}

/**
 * Replace confusable Unicode characters with ASCII equivalents.
 * @param {string} text
 * @returns {{ text: string, count: number }}
 */
export function foldHomoglyphs(text) {
  let count = 0;
  const folded = String(text).replace(/./gu, (ch) => {
    const mapped = HOMOGLYPHS[ch];
    if (mapped !== undefined) {
      count += 1;
      return mapped;
    }
    return ch;
  });
  return { text: folded, count };
}

/**
 * Find embedded base64 runs and decode the ones that look like printable text.
 * @param {string} text
 * @returns {Array<{ raw: string, decoded: string, index: number }>}
 */
export function extractBase64(text) {
  const source = String(text);
  const hits = [];
  for (const match of source.matchAll(BASE64_RE)) {
    const raw = match[0];
    let decoded;
    try {
      decoded = Buffer.from(raw, 'base64').toString('utf8');
    } catch {
      continue;
    }
    // Keep only decodes that are mostly printable ASCII and contain a space or
    // letters — i.e. plausibly natural language rather than binary noise.
    if (decoded.length < 6) continue;
    const printable = decoded.replace(/[^\x20-\x7E]/g, '');
    if (printable.length / decoded.length < 0.85) continue;
    if (!/[a-z].*[a-z]/i.test(printable)) continue;
    hits.push({ raw, decoded, index: match.index ?? source.indexOf(raw) });
  }
  return hits;
}

/**
 * Produce a normalized lowercased string for matching plus obfuscation counts.
 * @param {string} text
 * @returns {{ normalized: string, zeroWidth: number, homoglyphs: number, base64: Array }}
 */
export function normalize(text) {
  const zw = stripZeroWidth(text);
  const hg = foldHomoglyphs(zw.text);
  return {
    normalized: hg.text.toLowerCase(),
    zeroWidth: zw.count,
    homoglyphs: hg.count,
    base64: extractBase64(zw.text),
  };
}
