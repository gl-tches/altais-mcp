// Match Findings to compliance-framework controls.
//
// A finding maps to a control when either:
//   - the finding's CWE refs intersect the control's `cwes`, or
//   - one of the control's lowercase `keywords` occurs in the finding's
//     `rule` or `title`.
// These are coarse advisory hints to focus an audit, not a formal claim
// of compliance.

import type { Finding, Severity } from "../../core/types.js";
import type { ComplianceControl, ComplianceFramework } from "./frameworks.js";

export type ControlStatus = "addressed" | "gap";

/** Control families treated as high-severity when left unassessed. */
const HIGH_RISK_FAMILY_KEYWORDS: readonly string[] = [
  "access",
  "crypto",
  "auth",
  "identification-authentication",
];

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** A normalized, framework-agnostic finding shape used by the mapper. */
export interface MappableFinding {
  readonly id: string;
  readonly rule: string;
  readonly title: string;
  readonly severity: Severity;
  readonly cwe: readonly string[];
}

export interface ControlMapping {
  readonly control: ComplianceControl;
  readonly status: ControlStatus;
  readonly matched_findings: readonly MappableFinding[];
  readonly highest_severity: Severity | null;
}

export interface MappingResult {
  readonly framework_id: string;
  readonly framework_name: string;
  readonly framework_version: string;
  readonly mappings: readonly ControlMapping[];
  readonly summary: {
    readonly total_controls: number;
    readonly addressed: number;
    readonly gap: number;
    readonly coverage_pct: number;
    readonly total_findings: number;
    readonly mapped_findings: number;
  };
}

/** Normalize a CWE identifier to canonical upper-case `CWE-N` form. */
export function normalizeCwe(value: string): string {
  const trimmed = value.trim().toUpperCase();
  if (trimmed === "") return "";
  return trimmed.startsWith("CWE-") ? trimmed : `CWE-${trimmed}`;
}

/** Convert a session `Finding` into the mapper's normalized shape. */
export function toMappable(finding: Finding): MappableFinding {
  return {
    id: finding.id,
    rule: finding.rule,
    title: finding.title,
    severity: finding.severity,
    cwe: finding.cwe ?? [],
  };
}

function highestSeverity(findings: readonly MappableFinding[]): Severity | null {
  if (findings.length === 0) return null;
  let best: Severity = "info";
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}

/**
 * Lowercase a string and collapse word separators (hyphens, underscores,
 * and runs of whitespace) to a single space. This lets a keyword like
 * "sql injection" match a finding rule like "sql-injection-check".
 */
function normalizeText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[-_\s]+/g, " ")
    .trim();
}

/**
 * Decide whether a single finding maps to a single control via CWE
 * intersection or keyword match against the finding's rule / title.
 */
export function findingMatchesControl(
  finding: MappableFinding,
  control: ComplianceControl,
): boolean {
  const controlCwes = new Set(control.cwes.map(normalizeCwe));
  for (const cwe of finding.cwe) {
    if (controlCwes.has(normalizeCwe(cwe))) return true;
  }
  const haystack = normalizeText(`${finding.rule} ${finding.title}`);
  for (const keyword of control.keywords) {
    const needle = normalizeText(keyword);
    if (needle !== "" && haystack.includes(needle)) return true;
  }
  return false;
}

/** True when a control's family is considered high-risk if unassessed. */
export function isHighRiskFamily(family: string): boolean {
  const f = family.toLowerCase();
  return HIGH_RISK_FAMILY_KEYWORDS.some((k) => f.includes(k));
}

/**
 * Map a list of findings against every control in a framework. Returns a
 * per-control mapping plus coverage statistics. Mappings are returned in
 * the framework's declared control order for deterministic output.
 */
export function mapFindingsToFramework(
  findings: readonly MappableFinding[],
  framework: ComplianceFramework,
): MappingResult {
  const mappings: ControlMapping[] = [];
  const mappedFindingIds = new Set<string>();

  for (const control of framework.controls) {
    const matched = findings.filter((f) => findingMatchesControl(f, control));
    for (const m of matched) mappedFindingIds.add(m.id);
    mappings.push({
      control,
      status: matched.length > 0 ? "addressed" : "gap",
      matched_findings: matched,
      highest_severity: highestSeverity(matched),
    });
  }

  const addressed = mappings.filter((m) => m.status === "addressed").length;
  const total = mappings.length;
  return {
    framework_id: framework.id,
    framework_name: framework.name,
    framework_version: framework.version,
    mappings,
    summary: {
      total_controls: total,
      addressed,
      gap: total - addressed,
      coverage_pct: total === 0 ? 0 : Math.round((addressed / total) * 100),
      total_findings: findings.length,
      mapped_findings: mappedFindingIds.size,
    },
  };
}
