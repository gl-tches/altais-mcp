// Pattern types for the scan module.
//
// A Pattern is a self-describing detection rule with metadata (severity,
// CWE references, remediation) and a matcher. The PatternEngine runs all
// patterns whose `languages` set includes the target language.

import type { Severity } from "../../../core/types.js";
import type { Language } from "../languages.js";

export type PatternCategory =
  | "injection"
  | "xss"
  | "ssrf"
  | "path-traversal"
  | "exceptional-conditions"
  | "prototype-pollution"
  | "ssti"
  | "redos"
  | "race-condition"
  | "deserialization"
  | "business-logic"
  | "request-smuggling"
  | "cache-poisoning"
  | "crlf-injection"
  | "host-header-injection";

export interface PatternMatch {
  readonly line_start: number;
  readonly line_end?: number;
  readonly column?: number;
  readonly evidence: string;
}

export interface PatternMatcherContext {
  /** Source with comments and string literals replaced by spaces (newline-preserving). */
  readonly stripped: string;
  /** Raw source as provided to the engine. */
  readonly source: string;
  /** Source split into lines (no trailing newline characters). */
  readonly lines: readonly string[];
  /** Per-line offset into `source`. */
  readonly lineOffsets: readonly number[];
  readonly language: Language;
}

export type PatternMatcher =
  | {
      readonly type: "regex";
      readonly regex: RegExp;
      /** Optional regex capture group used as the evidence snippet. */
      readonly evidenceGroup?: number;
      /** When true, run against the raw source (still uses lineOffsets). */
      readonly raw?: boolean;
    }
  | {
      readonly type: "function";
      readonly fn: (ctx: PatternMatcherContext) => readonly PatternMatch[];
    };

export interface Pattern {
  /** Stable rule id, e.g. "sql-injection". Forms part of the finding id. */
  readonly id: string;
  readonly category: PatternCategory;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly cwe: readonly string[];
  readonly remediation: string;
  readonly references: readonly string[];
  readonly languages: readonly Language[];
  readonly matcher: PatternMatcher;
}
