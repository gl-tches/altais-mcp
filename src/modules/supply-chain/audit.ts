// Audit parsed packages against the bundled OSV snapshot.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import { inRange, type Range } from "./semver.js";
import type { DependencyPackage, EcosystemId, LockfileParseResult } from "./types.js";

interface OsvEntry {
  readonly id: string;
  readonly summary: string;
  readonly ecosystem: EcosystemId;
  readonly package: string;
  readonly affected_range: Range;
  readonly severity: Severity;
  readonly cvss?: number;
  readonly cwe?: readonly string[];
  readonly references?: readonly string[];
}

interface OsvSnapshot {
  readonly _meta: { readonly as_of?: string };
  readonly vulnerabilities: readonly OsvEntry[];
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

export class OsvDatabase {
  private readonly byEcosystemName = new Map<string, OsvEntry[]>();

  constructor(
    entries: readonly OsvEntry[],
    public readonly asOf: string | undefined,
  ) {
    for (const e of entries) {
      const key = `${e.ecosystem}/${e.package.toLowerCase()}`;
      const list = this.byEcosystemName.get(key) ?? [];
      list.push(e);
      this.byEcosystemName.set(key, list);
    }
  }

  static async load(dataDir: string = defaultDataDir()): Promise<OsvDatabase> {
    const file = path.join(dataDir, "osv-snapshot.json");
    const raw = await readFile(file, "utf8");
    const parsed = JSON.parse(raw) as OsvSnapshot;
    return new OsvDatabase(parsed.vulnerabilities, parsed._meta.as_of);
  }

  /** Return vulnerabilities affecting (ecosystem, name, version). */
  lookup(pkg: DependencyPackage): readonly OsvEntry[] {
    const key = `${pkg.ecosystem}/${pkg.name.toLowerCase()}`;
    const candidates = this.byEcosystemName.get(key) ?? [];
    return candidates.filter((c) => inRange(pkg.version, c.affected_range));
  }

  size(): number {
    let total = 0;
    for (const list of this.byEcosystemName.values()) total += list.length;
    return total;
  }
}

export interface AuditResult {
  readonly ecosystem: EcosystemId;
  readonly package_manager: string;
  readonly packages_scanned: number;
  readonly findings: readonly Finding[];
  readonly summary: Readonly<Record<Severity, number>>;
  readonly database_as_of: string | undefined;
}

export function auditPackages(
  parsed: LockfileParseResult,
  db: OsvDatabase,
  source: string | undefined,
): AuditResult {
  const findings: Finding[] = [];
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const pkg of parsed.packages) {
    const hits = db.lookup(pkg);
    for (const hit of hits) {
      const finding = buildFinding(pkg, hit, source);
      findings.push(finding);
      summary[finding.severity] += 1;
    }
  }
  return {
    ecosystem: parsed.ecosystem,
    package_manager: parsed.package_manager,
    packages_scanned: parsed.packages.length,
    findings,
    summary,
    database_as_of: db.asOf,
  };
}

function buildFinding(
  pkg: DependencyPackage,
  entry: OsvEntry,
  source: string | undefined,
): Finding {
  const location: FindingLocation | undefined =
    source !== undefined ? { file: source, line_start: 1 } : undefined;
  const evidence = `${pkg.name}@${pkg.version} (${pkg.ecosystem})`;
  return {
    id: findingId("supply_chain", entry.id, location, evidence),
    module: "supply_chain",
    rule: entry.id,
    severity: entry.severity,
    cwe: entry.cwe ?? [],
    title: `${entry.id}: ${entry.summary}`,
    description: `${pkg.name} ${pkg.version} (${pkg.ecosystem}) is affected by ${entry.id}: ${entry.summary}.`,
    ...(location !== undefined ? { location } : {}),
    evidence,
    remediation: `Upgrade ${pkg.name} to a version outside the affected range (${formatRange(entry.affected_range)}). Pin by hash in your lockfile.`,
    references: entry.references ?? [],
    tags: ["supply-chain", "vulnerability", `ecosystem:${pkg.ecosystem}`],
    status: "open",
  };
}

function formatRange(range: Range): string {
  const parts: string[] = [];
  if (range.introduced !== undefined && range.introduced !== "0")
    parts.push(`>= ${range.introduced}`);
  if (range.fixed !== undefined) parts.push(`< ${range.fixed}`);
  if (range.last_affected !== undefined) parts.push(`<= ${range.last_affected}`);
  return parts.length > 0 ? parts.join(", ") : "all versions";
}
