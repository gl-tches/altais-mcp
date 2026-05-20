// CVE lookup (altais_lookup_cve).
//
// Reads a curated, bundled offline snapshot of well-known, high-impact
// CVEs from `data/cve-database.json`. No network calls — the database
// ships with the package (CLAUDE.md rule 3).

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { Severity } from "../../core/types.js";

export interface CveEntry {
  readonly id: string;
  readonly description: string;
  readonly cvss_v31_vector?: string;
  readonly cvss_score?: number;
  readonly severity: Severity;
  readonly cwe: readonly string[];
  readonly affected: string;
  readonly published: string;
  readonly remediation: string;
  readonly references: readonly string[];
}

/** Canonical CVE identifier shape: `CVE-YYYY-NNNN+`. */
export const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * Locate the bundled `data/` directory. Works whether the package is run
 * from `dist/modules/vuln-db/` (compiled) or `src/modules/vuln-db/`.
 */
function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

/** Normalize a user-supplied CVE id to canonical upper-case form, or null. */
export function normalizeCveId(input: string): string | null {
  const trimmed = input.trim();
  if (!CVE_ID_RE.test(trimmed)) return null;
  const dash = trimmed.indexOf("-");
  return `CVE${trimmed.slice(dash)}`.toUpperCase();
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

function isCveEntry(value: unknown): value is CveEntry {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r.id === "string" &&
    typeof r.description === "string" &&
    typeof r.severity === "string" &&
    SEVERITIES.has(r.severity) &&
    isStringArray(r.cwe) &&
    typeof r.affected === "string" &&
    typeof r.published === "string" &&
    typeof r.remediation === "string" &&
    isStringArray(r.references)
  );
}

export class CveDatabase {
  private readonly byId = new Map<string, CveEntry>();

  constructor(entries: readonly CveEntry[]) {
    for (const entry of entries) {
      this.byId.set(entry.id.toUpperCase(), entry);
    }
  }

  static async load(dataDir: string = defaultDataDir()): Promise<CveDatabase> {
    const file = path.join(dataDir, "cve-database.json");
    const raw = await readFile(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error(`CVE database is not an array: ${file}`);
    }
    const entries: CveEntry[] = [];
    for (const item of parsed) {
      if (!isCveEntry(item)) {
        throw new Error(`Malformed CVE entry in ${file}`);
      }
      entries.push(item);
    }
    return new CveDatabase(entries);
  }

  lookup(id: string): CveEntry | undefined {
    const normalized = normalizeCveId(id);
    if (normalized === null) return undefined;
    return this.byId.get(normalized);
  }

  size(): number {
    return this.byId.size;
  }

  /** All CVE ids in the snapshot, sorted, for use in error messages. */
  ids(): readonly string[] {
    return [...this.byId.keys()].sort();
  }
}

export interface CveLookupSuccess {
  readonly found: true;
  readonly cve: CveEntry;
}

export interface CveLookupFailure {
  readonly found: false;
  readonly message: string;
}

export type CveLookupResult = CveLookupSuccess | CveLookupFailure;

/**
 * Look up a CVE id against the loaded database. The database is a curated
 * offline snapshot, not a live feed — an unknown id returns an actionable
 * failure rather than implying the CVE does not exist.
 */
export function lookupCve(db: CveDatabase, id: string): CveLookupResult {
  const normalized = normalizeCveId(id);
  if (normalized === null) {
    return {
      found: false,
      message: `\`${id}\` is not a valid CVE identifier. Expected the form CVE-YYYY-NNNN (e.g. CVE-2021-44228).`,
    };
  }
  const cve = db.lookup(normalized);
  if (cve === undefined) {
    return {
      found: false,
      message:
        `${normalized} is not in the bundled CVE database. This database is a curated offline ` +
        `snapshot of ${String(db.size())} well-known, high-impact CVEs — it is not a complete ` +
        `feed. Consult https://nvd.nist.gov/vuln/detail/${normalized} for full, current details.`,
    };
  }
  return { found: true, cve };
}
