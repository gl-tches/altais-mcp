// Shared Finding builder for code audits.

import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export interface CodeFindingDraft {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly evidence?: string;
  readonly tags?: readonly string[];
  readonly line?: number;
  readonly column?: number;
}

export function buildCodeFinding(draft: CodeFindingDraft, filename: string | undefined): Finding {
  const location: FindingLocation | undefined =
    filename !== undefined
      ? {
          file: filename,
          line_start: draft.line ?? 1,
          ...(draft.column !== undefined ? { column: draft.column } : {}),
        }
      : undefined;
  return {
    id: findingId("code", draft.rule, location, draft.evidence ?? ""),
    module: "code",
    rule: draft.rule,
    severity: draft.severity,
    cwe: draft.cwe,
    title: draft.title,
    description: draft.description,
    ...(location !== undefined ? { location } : {}),
    ...(draft.evidence !== undefined ? { evidence: draft.evidence } : {}),
    remediation: draft.remediation,
    references: draft.references,
    tags: ["code", ...(draft.tags ?? [])],
    status: "open",
  };
}

/** Count newlines in `text[0..end)` to compute a 1-based line number. */
export function lineAt(text: string, end: number): number {
  let n = 1;
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 0x0a) n++;
  return n;
}

export interface SourcePattern {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly tags?: readonly string[];
}

/**
 * Run a list of source patterns over `source`, producing one Finding per
 * match. Patterns are always evaluated with the global flag so every
 * occurrence is reported.
 */
export function scanWithPatterns(
  source: string,
  patterns: readonly SourcePattern[],
  references: readonly string[],
  filename: string | undefined,
): readonly Finding[] {
  const findings: Finding[] = [];
  for (const pat of patterns) {
    const flags = pat.regex.flags.includes("g") ? pat.regex.flags : `${pat.regex.flags}g`;
    const regex = new RegExp(pat.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      findings.push(
        buildCodeFinding(
          {
            rule: pat.rule,
            severity: pat.severity,
            title: pat.title,
            description: pat.description,
            remediation: pat.remediation,
            cwe: pat.cwe,
            references,
            evidence: m[0].trim().slice(0, 200),
            ...(pat.tags !== undefined ? { tags: pat.tags } : {}),
            line: lineAt(source, m.index),
          },
          filename,
        ),
      );
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  return findings;
}
