// Shannon-entropy based detection of high-randomness strings.
//
// Splits source into candidate "tokens" (runs of alphanumeric and base64/hex
// characters), classifies each candidate by character set, computes
// bits-per-character entropy, and flags candidates that exceed the
// configured threshold for that character set.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import { redact } from "./patterns.js";

export interface EntropyThresholds {
  readonly hex: number;
  readonly base64: number;
  readonly minTokenLength: number;
}

export const DEFAULT_THRESHOLDS: EntropyThresholds = {
  hex: 4.5,
  base64: 5.0,
  minTokenLength: 20,
};

export type CharsetKind = "hex" | "base64" | "alphanum" | "other";

const HEX_CHARS = /^[0-9a-fA-F]+$/;
const BASE32_CHARS = /^[A-Z2-7]+=*$/;
const BASE64_CHARS = /^[A-Za-z0-9+/=_-]+$/;

/**
 * Shannon entropy in bits per character.
 * Empty string returns 0.
 */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = s.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Classify a candidate token by its character composition.
 * `hex` and `base64` (which also covers base32 and base64url) get
 * separate thresholds because their max entropy differs.
 */
export function classifyCharset(s: string): CharsetKind {
  if (HEX_CHARS.test(s)) return "hex";
  if (BASE32_CHARS.test(s)) return "base64";
  if (BASE64_CHARS.test(s)) return "base64";
  if (/^[A-Za-z0-9]+$/.test(s)) return "alphanum";
  return "other";
}

function thresholdFor(thresholds: EntropyThresholds, kind: CharsetKind): number {
  if (kind === "hex") return thresholds.hex;
  if (kind === "base64") return thresholds.base64;
  if (kind === "alphanum") return thresholds.base64; // similar character set
  return Number.POSITIVE_INFINITY;
}

export interface EntropyCandidate {
  readonly token: string;
  readonly start: number;
  readonly end: number;
  readonly entropy: number;
  readonly charset: CharsetKind;
  readonly threshold: number;
}

/**
 * Extract candidate tokens from source and return only those whose entropy
 * exceeds the configured threshold for their character class. Tokens are
 * runs of base64/base32/hex characters of at least `minTokenLength`.
 */
export function findHighEntropyTokens(
  source: string,
  thresholds: EntropyThresholds = DEFAULT_THRESHOLDS,
): readonly EntropyCandidate[] {
  const TOKEN_RE = /[A-Za-z0-9+/=_-]+/g;
  const min = thresholds.minTokenLength;
  const out: EntropyCandidate[] = [];
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(source)) !== null) {
    const token = m[0];
    if (token.length < min) continue;
    const charset = classifyCharset(token);
    if (charset === "other") continue;
    const entropy = shannonEntropy(token);
    const threshold = thresholdFor(thresholds, charset);
    if (entropy > threshold) {
      out.push({
        token,
        start: m.index,
        end: m.index + token.length,
        entropy,
        charset,
        threshold,
      });
    }
    if (token.length === 0) TOKEN_RE.lastIndex += 1;
  }
  return out;
}

export interface EntropyScanInput {
  readonly source: string;
  readonly file?: string;
}

/**
 * Scan source for high-entropy strings and emit Finding objects.
 */
export function scanEntropy(
  input: EntropyScanInput,
  thresholds: EntropyThresholds = DEFAULT_THRESHOLDS,
): readonly Finding[] {
  const file = input.file ?? "<inline>";
  const candidates = findHighEntropyTokens(input.source, thresholds);
  const lineOffsets = computeLineOffsets(input.source);

  return candidates.map((c) => {
    const { line, column } = offsetToLineCol(c.start, lineOffsets);
    const evidence = redact(c.token, 240);
    const location: FindingLocation = { file, line_start: line, column };
    const rule = c.charset === "hex" ? "entropy-hex" : "entropy-base64";
    const severity = c.entropy > c.threshold + 0.5 ? "high" : "medium";
    return {
      id: findingId("secrets", rule, location, evidence),
      module: "secrets",
      rule,
      severity,
      cwe: ["CWE-798", "CWE-540"],
      title: `High-entropy ${c.charset} string (possible secret)`,
      description: `A ${c.token.length}-character ${c.charset} string with entropy ${c.entropy.toFixed(2)} bits/char (threshold ${c.threshold.toFixed(2)}). Strings this random rarely occur in source unless they are credentials, tokens, or keys.`,
      location,
      evidence,
      remediation:
        "If this is a credential, rotate it and load from environment variables or a secrets manager. If it is genuinely random data unrelated to security (e.g. a fixture hash), add a comment explaining why, or tune the threshold in `secrets.entropy_min_*`.",
      references: ["https://en.wikipedia.org/wiki/Entropy_(information_theory)"],
      tags: ["secret", "entropy"],
      status: "open",
    };
  });
}

function computeLineOffsets(src: string): readonly number[] {
  const offsets: number[] = [0];
  for (let i = 0; i < src.length; i++) {
    if (src.charCodeAt(i) === 0x0a) offsets.push(i + 1);
  }
  return offsets;
}

function offsetToLineCol(
  offset: number,
  offsets: readonly number[],
): { line: number; column: number } {
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    const v = offsets[mid] ?? 0;
    if (v <= offset) lo = mid;
    else hi = mid - 1;
  }
  const base = offsets[lo] ?? 0;
  return { line: lo + 1, column: offset - base + 1 };
}
