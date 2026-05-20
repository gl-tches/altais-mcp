// Pattern execution engine for the scan module.
//
// Given a list of Patterns and source text, runs every pattern whose
// language set includes the target language and returns Finding objects.
// Comments are stripped per-language so patterns do not fire on commented code.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import { stripCommentsForLanguage } from "./analyzers/strip.js";
import type { Language } from "./languages.js";
import type { Pattern, PatternMatch, PatternMatcherContext } from "./patterns/types.js";

export interface ScanContext {
  readonly source: string;
  readonly language: Language;
  readonly file?: string;
}

export interface RunPatternsOptions {
  /** When set, only run patterns whose id or category matches one of these names. */
  readonly rules?: readonly string[];
  /** Maximum number of findings to return. Default: 500. */
  readonly maxFindings?: number;
}

const DEFAULT_MAX_FINDINGS = 500;
const MAX_EVIDENCE_CHARS = 200;

export function runPatterns(
  patterns: readonly Pattern[],
  ctx: ScanContext,
  options: RunPatternsOptions = {},
): readonly Finding[] {
  const stripped = stripCommentsForLanguage(ctx.source, ctx.language);
  const lines = ctx.source.split(/\r?\n/);
  const lineOffsets = computeLineOffsets(ctx.source);
  const matcherCtx: PatternMatcherContext = {
    stripped,
    source: ctx.source,
    lines,
    lineOffsets,
    language: ctx.language,
  };

  const max = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  const filter = options.rules && options.rules.length > 0 ? new Set(options.rules) : null;
  const out: Finding[] = [];
  for (const pattern of patterns) {
    if (!pattern.languages.includes(ctx.language)) continue;
    if (filter && !filter.has(pattern.id) && !filter.has(pattern.category)) continue;
    const matches = matchOne(pattern, matcherCtx);
    for (const match of matches) {
      if (out.length >= max) return out;
      out.push(buildFinding(pattern, match, ctx.file));
    }
  }
  return out;
}

function matchOne(pattern: Pattern, ctx: PatternMatcherContext): readonly PatternMatch[] {
  const matcher = pattern.matcher;
  if (matcher.type === "function") return matcher.fn(ctx);

  const text = matcher.raw === true ? ctx.source : ctx.stripped;
  const flags = matcher.regex.flags.includes("g") ? matcher.regex.flags : `${matcher.regex.flags}g`;
  const regex = new RegExp(matcher.regex.source, flags);
  const matches: PatternMatch[] = [];
  let m: RegExpExecArray | null;
  while ((m = regex.exec(text)) !== null) {
    const startIdx = m.index;
    const full = m[0];
    const evidenceText =
      matcher.evidenceGroup !== undefined ? (m[matcher.evidenceGroup] ?? full) : full;
    const { line, column } = offsetToLineCol(startIdx, ctx.lineOffsets);
    const endIdx = startIdx + full.length;
    const { line: endLine } = offsetToLineCol(Math.max(startIdx, endIdx - 1), ctx.lineOffsets);
    const match: PatternMatch = {
      line_start: line,
      column,
      evidence: truncate(evidenceText.trim().replace(/\s+/g, " "), MAX_EVIDENCE_CHARS),
      ...(endLine !== line ? { line_end: endLine } : {}),
    };
    matches.push(match);
    if (full.length === 0) regex.lastIndex += 1;
  }
  return matches;
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
  // Binary search for the largest offset <= `offset`.
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

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

function buildFinding(pattern: Pattern, match: PatternMatch, file: string | undefined): Finding {
  const location: FindingLocation = {
    file: file ?? "<inline>",
    line_start: match.line_start,
    ...(match.line_end !== undefined ? { line_end: match.line_end } : {}),
    ...(match.column !== undefined ? { column: match.column } : {}),
  };
  return {
    id: findingId("scan", pattern.id, location, match.evidence),
    module: "scan",
    rule: pattern.id,
    severity: pattern.severity,
    cwe: pattern.cwe,
    title: pattern.title,
    description: pattern.description,
    location,
    evidence: match.evidence,
    remediation: pattern.remediation,
    references: pattern.references,
    tags: [pattern.category],
    status: "open",
  };
}
