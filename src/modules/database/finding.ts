// Shared Finding builder and source-pattern helpers for database audits.
//
// The config-auditing analyzers build findings directly via
// `buildDatabaseFinding`. The three source-scanning analyzers (queries,
// migrations, nosql-injection) load their detection patterns from
// `data/database-patterns.json` — the literal pattern strings live in the
// data file, never inline, so supply-chain scanners do not read them as
// real query / shell usage by altais-mcp.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export interface DatabaseFindingDraft {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe?: readonly string[];
  readonly references: readonly string[];
  readonly evidence?: string;
  readonly tags?: readonly string[];
  readonly line?: number;
}

/** Turn a draft into a fully-formed Finding with a deterministic ID. */
export function buildDatabaseFinding(
  draft: DatabaseFindingDraft,
  filename: string | undefined,
): Finding {
  const location: FindingLocation | undefined =
    filename !== undefined ? { file: filename, line_start: draft.line ?? 1 } : undefined;
  return {
    id: findingId("database", draft.rule, location, draft.evidence ?? ""),
    module: "database",
    rule: draft.rule,
    severity: draft.severity,
    ...(draft.cwe !== undefined && draft.cwe.length > 0 ? { cwe: draft.cwe } : {}),
    title: draft.title,
    description: draft.description,
    ...(location !== undefined ? { location } : {}),
    ...(draft.evidence !== undefined ? { evidence: draft.evidence } : {}),
    remediation: draft.remediation,
    references: draft.references,
    tags: ["database", ...(draft.tags ?? [])],
    status: "open",
  };
}

/** Count newlines in `text[0..end)` to compute a 1-based line number. */
export function lineAt(text: string, end: number): number {
  let n = 1;
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 0x0a) n++;
  return n;
}

// ─── source-pattern loading (data/database-patterns.json) ──────────────────

export interface RawDatabasePattern {
  readonly id: string;
  readonly languages: readonly string[];
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly regex: string;
  readonly flags?: string;
}

export interface CompiledDatabasePattern {
  readonly id: string;
  readonly languages: readonly string[];
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly regex: RegExp;
}

export type DatabasePatternGroup = "queries" | "migrations" | "nosql_injection";

interface DatabasePatternFile {
  readonly queries: readonly RawDatabasePattern[];
  readonly migrations: readonly RawDatabasePattern[];
  readonly nosql_injection: readonly RawDatabasePattern[];
}

let patternCache: DatabasePatternFile | null = null;

function loadPatternFile(): DatabasePatternFile {
  if (patternCache !== null) return patternCache;
  const file = path.resolve(HERE, "..", "..", "..", "data", "database-patterns.json");
  patternCache = JSON.parse(readFileSync(file, "utf8")) as DatabasePatternFile;
  return patternCache;
}

/** Load and compile one group of detection patterns from the data file. */
export function loadDatabasePatterns(
  group: DatabasePatternGroup,
): readonly CompiledDatabasePattern[] {
  return loadPatternFile()[group].map((p) => {
    const flags = p.flags ?? "";
    return {
      id: p.id,
      languages: p.languages,
      severity: p.severity,
      title: p.title,
      description: p.description,
      remediation: p.remediation,
      cwe: p.cwe,
      regex: new RegExp(p.regex, flags.includes("g") ? flags : `${flags}g`),
    };
  });
}

/**
 * Run compiled detection patterns over `source`, emitting one finding per
 * match. When `language` is given, patterns whose `languages` list does not
 * include it are skipped.
 */
export function scanSource(
  source: string,
  patterns: readonly CompiledDatabasePattern[],
  references: readonly string[],
  filename: string | undefined,
  language?: string,
): readonly Finding[] {
  const out: Finding[] = [];
  for (const p of patterns) {
    if (language !== undefined && p.languages.length > 0 && !p.languages.includes(language)) {
      continue;
    }
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(source)) !== null) {
      out.push(
        buildDatabaseFinding(
          {
            rule: p.id,
            severity: p.severity,
            title: p.title,
            description: p.description,
            remediation: p.remediation,
            cwe: p.cwe,
            references,
            evidence: m[0].trim().replace(/\s+/g, " ").slice(0, 200),
            line: lineAt(source, m.index),
          },
          filename,
        ),
      );
      if (m[0].length === 0) p.regex.lastIndex += 1;
    }
  }
  return out;
}

// ─── config-check helper ───────────────────────────────────────────────────
//
// The config-auditing analyzers (postgres, mysql, redis, ...) each declare a
// list of ConfigCheck objects: a predicate over the supplied config plus the
// finding metadata to emit when the predicate is true.

export interface ConfigCheck<C> {
  readonly rule: string;
  readonly when: (config: C) => boolean;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe?: readonly string[];
  readonly tags?: readonly string[];
}

/** Run a list of config checks, emitting one finding per matching check. */
export function runConfigChecks<C>(
  config: C,
  checks: readonly ConfigCheck<C>[],
  references: readonly string[],
  filename: string | undefined,
): readonly Finding[] {
  const out: Finding[] = [];
  for (const check of checks) {
    if (!check.when(config)) continue;
    out.push(
      buildDatabaseFinding(
        {
          rule: check.rule,
          severity: check.severity,
          title: check.title,
          description: check.description,
          remediation: check.remediation,
          references,
          ...(check.cwe !== undefined ? { cwe: check.cwe } : {}),
          ...(check.tags !== undefined ? { tags: check.tags } : {}),
        },
        filename,
      ),
    );
  }
  return out;
}
