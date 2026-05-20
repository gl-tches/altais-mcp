// Shared helpers: hashing, severity sorting, deterministic finding IDs.

import { createHash } from "node:crypto";
import type { Finding, FindingLocation, Severity } from "./types.js";

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Stable short content hash for deterministic finding IDs. Truncated to
 * 12 hex chars (48 bits) — collision risk is negligible per scan session.
 */
export function contentHash(parts: readonly (string | number | undefined)[]): string {
  const h = createHash("sha256");
  for (const part of parts) {
    h.update(part === undefined ? "\0" : String(part));
    h.update("\x1f");
  }
  return h.digest("hex").slice(0, 12);
}

/**
 * Build a deterministic finding ID in the form `{module}:{rule}:{contentHash}`.
 * Same location + evidence always produces the same ID, so duplicate scans
 * do not produce duplicate findings.
 */
export function findingId(
  module: string,
  rule: string,
  location: FindingLocation | undefined,
  evidence: string | undefined,
): string {
  return `${module}:${rule}:${contentHash([
    module,
    rule,
    location?.file,
    location?.line_start,
    location?.line_end,
    location?.column,
    evidence,
  ])}`;
}

export function sortFindingsBySeverity(findings: readonly Finding[]): readonly Finding[] {
  return [...findings].sort((a, b) => {
    const order = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (order !== 0) return order;
    return a.id.localeCompare(b.id);
  });
}
