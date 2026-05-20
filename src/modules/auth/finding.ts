// Shared Finding builder for auth audits.

import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export interface AuthFindingDraft {
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

export function buildAuthFinding(draft: AuthFindingDraft, source: string | undefined): Finding {
  const location: FindingLocation | undefined =
    source !== undefined
      ? {
          file: source,
          line_start: draft.line ?? 1,
          ...(draft.column !== undefined ? { column: draft.column } : {}),
        }
      : undefined;
  return {
    id: findingId("auth", draft.rule, location, draft.evidence ?? ""),
    module: "auth",
    rule: draft.rule,
    severity: draft.severity,
    cwe: draft.cwe,
    title: draft.title,
    description: draft.description,
    ...(location !== undefined ? { location } : {}),
    ...(draft.evidence !== undefined ? { evidence: draft.evidence } : {}),
    remediation: draft.remediation,
    references: draft.references,
    tags: ["auth", ...(draft.tags ?? [])],
    status: "open",
  };
}

/** Count newlines in `text[0..end)` to compute a 1-based line number. */
export function lineAt(text: string, end: number): number {
  let n = 1;
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 0x0a) n++;
  return n;
}
