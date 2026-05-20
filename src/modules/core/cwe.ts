import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface CweEntry {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly examples: readonly string[];
  readonly remediation: string;
  readonly references: readonly string[];
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * Locate the bundled `data/` directory. Works whether the package is run
 * from `dist/modules/core/` (compiled) or `src/modules/core/` (ts-node).
 * The data files ship at the package root under `data/`.
 */
function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

/**
 * Normalize a user-supplied CWE identifier into canonical "CWE-N" form.
 * Accepts: "79", "CWE-79", "cwe79", " cwe 79 ".
 */
export function normalizeCweId(input: string): string | null {
  const trimmed = input.trim();
  if (trimmed === "") return null;
  const match = /^(?:cwe[-_ ]?)?(\d{1,5})$/i.exec(trimmed);
  if (match?.[1]) return `CWE-${match[1]}`;
  // Allow named variants like "CWE-77-LDAP" already present in the bundled DB.
  const named = /^cwe[-_ ]?(\d{1,5}[-_][a-z0-9]+)$/i.exec(trimmed);
  if (named?.[1]) return `CWE-${named[1].toUpperCase()}`;
  return null;
}

export class CweDatabase {
  private readonly byId = new Map<string, CweEntry>();

  constructor(entries: readonly CweEntry[]) {
    for (const entry of entries) {
      this.byId.set(entry.id.toUpperCase(), entry);
    }
  }

  static async load(dataDir: string = defaultDataDir()): Promise<CweDatabase> {
    const file = path.join(dataDir, "cwe-database.json");
    const raw = await readFile(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error(`CWE database is not an array: ${file}`);
    }
    return new CweDatabase(parsed as CweEntry[]);
  }

  lookup(id: string): CweEntry | undefined {
    const normalized = normalizeCweId(id);
    if (!normalized) return undefined;
    return this.byId.get(normalized.toUpperCase());
  }

  size(): number {
    return this.byId.size;
  }
}
