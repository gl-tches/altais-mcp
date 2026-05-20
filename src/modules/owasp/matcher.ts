// Match Findings to OWASP categories via CWE overlap, then produce a
// per-category report covering presence / absence / detection hints.

import type { Finding, Severity } from "../../core/types.js";
import type { AsvsControl, AsvsLevel, OwaspCategory } from "./knowledge.js";

export type CoverageStatus = "covered" | "needs_review";

export interface CategoryCoverage {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly status: CoverageStatus;
  readonly matched_findings: readonly Finding[];
  readonly highest_severity: Severity | null;
  readonly detection_hints: readonly string[];
  readonly remediation: string;
}

export interface CoverageReport {
  readonly list: string;
  readonly categories: readonly CategoryCoverage[];
  readonly summary: {
    readonly total_categories: number;
    readonly covered: number;
    readonly needs_review: number;
    readonly by_severity: Readonly<Record<Severity, number>>;
  };
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function normalizeCwe(value: string): string {
  return value.trim().toUpperCase().startsWith("CWE-")
    ? value.trim().toUpperCase()
    : `CWE-${value.trim()}`;
}

function highestSeverity(findings: readonly Finding[]): Severity | null {
  if (findings.length === 0) return null;
  let best: Severity = "info";
  for (const f of findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) best = f.severity;
  }
  return best;
}

export function mapFindingsToCategories(
  findings: readonly Finding[],
  categories: readonly OwaspCategory[],
  listName: string,
): CoverageReport {
  const findingCwes = findings.map((f) => ({
    finding: f,
    cwes: new Set((f.cwe ?? []).map(normalizeCwe)),
  }));

  const covered: CategoryCoverage[] = [];
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const category of categories) {
    const categoryCwes = new Set(category.cwes.map(normalizeCwe));
    const matched: Finding[] = [];
    for (const { finding, cwes } of findingCwes) {
      let hit = false;
      for (const c of cwes) {
        if (categoryCwes.has(c)) {
          hit = true;
          break;
        }
      }
      if (hit) matched.push(finding);
    }
    const status: CoverageStatus = matched.length > 0 ? "covered" : "needs_review";
    const highest = highestSeverity(matched);
    if (highest !== null) bySeverity[highest] += 1;
    covered.push({
      id: category.id,
      name: category.name,
      description: category.description,
      status,
      matched_findings: matched,
      highest_severity: highest,
      detection_hints: category.detection_hints,
      remediation: category.remediation,
    });
  }

  const coveredCount = covered.filter((c) => c.status === "covered").length;
  return {
    list: listName,
    categories: covered,
    summary: {
      total_categories: covered.length,
      covered: coveredCount,
      needs_review: covered.length - coveredCount,
      by_severity: bySeverity,
    },
  };
}

export interface AsvsFilterOptions {
  readonly level: AsvsLevel;
  readonly section?: string;
}

export interface AsvsControlEntry extends AsvsControl {
  readonly evidence: {
    readonly status: CoverageStatus;
    readonly matched_findings: readonly Finding[];
  };
}

export interface AsvsReport {
  readonly version: string;
  readonly level: AsvsLevel;
  readonly section: string | null;
  readonly controls: readonly AsvsControlEntry[];
  readonly summary: {
    readonly total: number;
    readonly covered: number;
    readonly needs_review: number;
  };
}

/**
 * Return ASVS controls applicable at the given level (level N includes
 * controls at levels 1..N). When `findings` is non-empty, each control is
 * annotated with findings whose CWE refs match the section's typical CWE
 * mapping — this is a coarse hint, not a formal claim of compliance.
 */
export function reportAsvs(
  controls: readonly AsvsControl[],
  options: AsvsFilterOptions,
  findings: readonly Finding[],
  version: string,
): AsvsReport {
  const filtered = controls.filter(
    (c) =>
      c.level <= options.level &&
      (options.section === undefined || c.section.toLowerCase() === options.section.toLowerCase()),
  );

  const entries: AsvsControlEntry[] = filtered.map((control) => {
    const matched = findings.filter((f) =>
      (f.cwe ?? []).some((cwe) => sectionCovers(control.section, normalizeCwe(cwe))),
    );
    return {
      ...control,
      evidence: {
        status: matched.length > 0 ? "covered" : "needs_review",
        matched_findings: matched,
      },
    };
  });

  const coveredCount = entries.filter((e) => e.evidence.status === "covered").length;
  return {
    version,
    level: options.level,
    section: options.section ?? null,
    controls: entries,
    summary: {
      total: entries.length,
      covered: coveredCount,
      needs_review: entries.length - coveredCount,
    },
  };
}

const SECTION_CWES: Readonly<Record<string, readonly string[]>> = {
  V1: ["CWE-693", "CWE-841", "CWE-840"],
  V2: ["CWE-287", "CWE-294", "CWE-307", "CWE-347", "CWE-521", "CWE-798", "CWE-916", "CWE-1390"],
  V3: ["CWE-384", "CWE-613", "CWE-614", "CWE-1004", "CWE-1275"],
  V4: [
    "CWE-22",
    "CWE-200",
    "CWE-285",
    "CWE-639",
    "CWE-732",
    "CWE-862",
    "CWE-863",
    "CWE-915",
    "CWE-918",
  ],
  V5: [
    "CWE-20",
    "CWE-74",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-90",
    "CWE-91",
    "CWE-94",
    "CWE-117",
    "CWE-611",
    "CWE-643",
    "CWE-918",
    "CWE-943",
    "CWE-1336",
  ],
  V6: ["CWE-310", "CWE-311", "CWE-321", "CWE-326", "CWE-327", "CWE-330", "CWE-338", "CWE-916"],
  V7: ["CWE-117", "CWE-209", "CWE-532", "CWE-754", "CWE-755", "CWE-778"],
  V8: ["CWE-200", "CWE-311", "CWE-359", "CWE-525"],
  V9: ["CWE-295", "CWE-297", "CWE-319", "CWE-326"],
  V10: ["CWE-345", "CWE-353", "CWE-494", "CWE-829"],
  V11: ["CWE-840", "CWE-799"],
  V12: ["CWE-22", "CWE-73", "CWE-400", "CWE-434", "CWE-770"],
  V13: ["CWE-352", "CWE-444", "CWE-942"],
  V14: ["CWE-2", "CWE-16", "CWE-1188", "CWE-1395", "CWE-1104"],
};

function sectionCovers(section: string, cwe: string): boolean {
  return (SECTION_CWES[section] ?? []).includes(cwe);
}
