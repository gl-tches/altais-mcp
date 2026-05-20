// Finding aggregation and report generation (markdown + JSON).
//
// FindingStore is a per-process, in-memory session of findings. Tools call
// addFindings() to push results into the session; `altais_report` reads from
// the same store to produce a consolidated report.

import { createHash } from "node:crypto";
import { riskSummary } from "./scoring.js";
import type { Finding, ScanResult, ScanSummary, Severity } from "./types.js";
import { sortFindingsBySeverity, SEVERITY_ORDER } from "./utils.js";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export type ReportFormat = "markdown" | "json";
export type ReportGroupBy = "module" | "severity";

export interface ReportOptions {
  readonly format?: ReportFormat;
  readonly include_info?: boolean;
  /**
   * "module" (default in Phase 2): findings are grouped under a per-module
   * section, then sorted by severity within each section.
   * "severity": flat list of findings sorted by severity (legacy layout).
   */
  readonly group_by?: ReportGroupBy;
}

/**
 * Per-process store of findings collected during this server session.
 * Findings are deduplicated by ID so re-scanning the same code does not
 * produce duplicate rows in the final report.
 */
export class FindingStore {
  private readonly findings = new Map<string, Finding>();
  private readonly startedAt = new Date();
  private filesScanned = 0;

  add(finding: Finding): void {
    // Last-write-wins on duplicate IDs; in practice IDs are content-derived
    // so duplicates carry the same payload.
    this.findings.set(finding.id, finding);
  }

  addMany(findings: readonly Finding[]): void {
    for (const f of findings) this.add(f);
  }

  recordFileScanned(): void {
    this.filesScanned += 1;
  }

  clear(): void {
    this.findings.clear();
    this.filesScanned = 0;
  }

  all(): readonly Finding[] {
    return Array.from(this.findings.values());
  }

  size(): number {
    return this.findings.size;
  }

  summarize(): ScanSummary {
    const findings = this.all();
    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    const byModule: Record<string, number> = {};
    for (const f of findings) {
      bySeverity[f.severity] += 1;
      byModule[f.module] = (byModule[f.module] ?? 0) + 1;
    }
    return {
      total: findings.length,
      by_severity: bySeverity,
      by_module: byModule,
      risk_score: riskSummary(findings),
    };
  }

  result(activeModules: readonly string[], configHash: string): ScanResult {
    return {
      findings: sortFindingsBySeverity(this.all()),
      summary: this.summarize(),
      metadata: {
        scanned_at: this.startedAt.toISOString(),
        duration_ms: Date.now() - this.startedAt.getTime(),
        files_scanned: this.filesScanned,
        modules_active: activeModules,
        config_hash: configHash,
      },
    };
  }
}

/**
 * Stable hash of an arbitrary JSON-serializable value. Used for the
 * `config_hash` field on ScanMetadata so reports can be correlated to
 * the config they were produced under.
 */
export function hashJson(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 16);
}

function escapeMd(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function renderLocation(f: Finding): string {
  if (!f.location) return "—";
  const range = f.location.line_end
    ? `${f.location.line_start}-${f.location.line_end}`
    : `${f.location.line_start}`;
  return `${f.location.file}:${range}`;
}

/**
 * Group findings by module preserving the input order (already
 * severity-sorted). Returns module names in count-descending, then
 * alphabetical order for deterministic output.
 */
export interface ModuleBreakdown {
  readonly module: string;
  readonly total: number;
  readonly by_severity: Readonly<Record<Severity, number>>;
  readonly findings: readonly Finding[];
}

function groupByModule(findings: readonly Finding[]): readonly ModuleBreakdown[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = groups.get(f.module) ?? [];
    arr.push(f);
    groups.set(f.module, arr);
  }
  const out: ModuleBreakdown[] = [];
  for (const [mod, items] of groups) {
    const by_severity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of items) by_severity[f.severity] += 1;
    out.push({
      module: mod,
      total: items.length,
      by_severity,
      findings: [...items].sort((a, b) => {
        const sa = SEVERITY_ORDER[a.severity];
        const sb = SEVERITY_ORDER[b.severity];
        if (sa !== sb) return sa - sb;
        return a.id.localeCompare(b.id);
      }),
    });
  }
  out.sort((a, b) => b.total - a.total || a.module.localeCompare(b.module));
  return out;
}

function renderFindingMd(f: Finding, lines: string[]): void {
  lines.push(`#### ${f.severity.toUpperCase()} — ${f.title}`);
  lines.push("");
  lines.push(`- **ID:** \`${f.id}\``);
  lines.push(`- **Module:** ${f.module}`);
  lines.push(`- **Rule:** ${f.rule}`);
  lines.push(`- **Location:** ${renderLocation(f)}`);
  if (f.cvss !== undefined) {
    lines.push(`- **CVSS:** ${f.cvss}${f.cvss_version ? ` (v${f.cvss_version})` : ""}`);
  }
  if (f.cwe && f.cwe.length > 0) {
    lines.push(`- **CWE:** ${f.cwe.join(", ")}`);
  }
  lines.push("");
  lines.push(escapeMd(f.description));
  lines.push("");
  if (f.evidence) {
    lines.push("**Evidence:**");
    lines.push("");
    lines.push("```");
    lines.push(f.evidence);
    lines.push("```");
    lines.push("");
  }
  lines.push("**Remediation:**");
  lines.push("");
  lines.push(f.remediation);
  lines.push("");
  if (f.references.length > 0) {
    lines.push("**References:**");
    for (const ref of f.references) {
      lines.push(`- ${ref}`);
    }
    lines.push("");
  }
}

export function renderMarkdownReport(
  result: ScanResult,
  includeInfo: boolean,
  groupBy: ReportGroupBy = "module",
): string {
  const { summary, metadata } = result;
  const lines: string[] = [];

  lines.push("# altais-mcp Security Report");
  lines.push("");
  lines.push(`- **Scanned:** ${metadata.scanned_at}`);
  lines.push(`- **Duration:** ${metadata.duration_ms} ms`);
  lines.push(`- **Files scanned:** ${metadata.files_scanned}`);
  lines.push(`- **Active modules:** ${metadata.modules_active.join(", ") || "(none)"}`);
  lines.push(`- **Config hash:** \`${metadata.config_hash}\``);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push(`- **Total findings:** ${summary.total}`);
  lines.push(`- **Risk score:** ${summary.risk_score} / 100`);
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  for (const sev of SEVERITIES) {
    lines.push(`| ${sev} | ${summary.by_severity[sev]} |`);
  }
  lines.push("");

  if (Object.keys(summary.by_module).length > 0) {
    lines.push("| Module | Total | Critical | High | Medium | Low | Info |");
    lines.push("|--------|-------|----------|------|--------|-----|------|");
    const breakdowns = groupByModule(result.findings);
    const lookup = new Map(breakdowns.map((b) => [b.module, b]));
    const modules = Object.keys(summary.by_module).sort();
    for (const m of modules) {
      const b = lookup.get(m);
      const bs: Record<Severity, number> = b?.by_severity ?? {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };
      lines.push(
        `| ${m} | ${summary.by_module[m] ?? 0} | ${bs.critical} | ${bs.high} | ${bs.medium} | ${bs.low} | ${bs.info} |`,
      );
    }
    lines.push("");
  }

  const findings = includeInfo
    ? result.findings
    : result.findings.filter((f) => f.severity !== "info");

  lines.push("## Findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("_No findings to report._");
    return lines.join("\n");
  }

  if (groupBy === "severity") {
    for (const f of findings) renderFindingMd(f, lines);
  } else {
    const groups = groupByModule(findings);
    for (const g of groups) {
      lines.push(
        `### \`${g.module}\` module (${g.total} ${g.total === 1 ? "finding" : "findings"})`,
      );
      const sevParts = SEVERITIES.filter((s) => g.by_severity[s] > 0).map(
        (s) => `${s}: ${g.by_severity[s]}`,
      );
      lines.push("");
      if (sevParts.length > 0) {
        lines.push(`_Severity breakdown:_ ${sevParts.join(", ")}`);
        lines.push("");
      }
      for (const f of g.findings) renderFindingMd(f, lines);
    }
  }

  return lines.join("\n");
}

interface JsonReportEnvelope extends ScanResult {
  readonly by_module: readonly ModuleBreakdown[];
}

export function renderJsonReport(result: ScanResult, includeInfo: boolean): string {
  const filteredFindings = includeInfo
    ? result.findings
    : result.findings.filter((f) => f.severity !== "info");
  const envelope: JsonReportEnvelope = {
    ...result,
    findings: filteredFindings,
    by_module: groupByModule(filteredFindings),
  };
  return JSON.stringify(envelope, null, 2);
}

export function renderReport(result: ScanResult, options: ReportOptions = {}): string {
  const includeInfo = options.include_info ?? false;
  const format = options.format ?? "markdown";
  const groupBy = options.group_by ?? "module";
  return format === "json"
    ? renderJsonReport(result, includeInfo)
    : renderMarkdownReport(result, includeInfo, groupBy);
}
