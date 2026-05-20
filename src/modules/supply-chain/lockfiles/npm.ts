// `package-lock.json` parser (lockfileVersion 1, 2, 3).

import type { DependencyPackage, LockfileParseResult } from "../types.js";
import { makePurl } from "../types.js";

interface PackageEntry {
  readonly version?: string;
  readonly integrity?: string;
  readonly resolved?: string;
  readonly dev?: boolean;
  readonly optional?: boolean;
  readonly license?: string;
  readonly dependencies?: Record<string, unknown>;
}

interface NpmLock {
  readonly name?: string;
  readonly lockfileVersion?: number;
  readonly packages?: Record<string, PackageEntry>;
  readonly dependencies?: Record<string, PackageEntry & { requires?: Record<string, string> }>;
}

function pathToName(path: string): string | null {
  if (path === "") return null;
  const last = path.lastIndexOf("node_modules/");
  if (last < 0) return null;
  return path.slice(last + "node_modules/".length);
}

export function parseNpmLock(text: string): LockfileParseResult {
  const json = JSON.parse(text) as NpmLock;
  const packages: DependencyPackage[] = [];

  if (json.packages) {
    // lockfileVersion 2/3: keyed by relative path (`node_modules/...`).
    for (const [path, entry] of Object.entries(json.packages)) {
      const name = pathToName(path);
      if (!name || !entry.version) continue;
      const pkg: DependencyPackage = {
        name,
        version: entry.version,
        ecosystem: "npm",
        ...(entry.resolved !== undefined ? { source: entry.resolved } : {}),
        ...(entry.integrity !== undefined ? { integrity: entry.integrity } : {}),
        ...(entry.license !== undefined ? { license: entry.license } : {}),
        ...(entry.dev !== undefined ? { dev: entry.dev } : {}),
        ...(entry.optional !== undefined ? { optional: entry.optional } : {}),
        ...(entry.dependencies !== undefined
          ? { dependencies: Object.keys(entry.dependencies) }
          : {}),
        purl: makePurl({ ecosystem: "npm", name, version: entry.version }),
      };
      packages.push(pkg);
    }
  } else if (json.dependencies) {
    // lockfileVersion 1: nested dependency tree.
    const visit = (entries: NonNullable<NpmLock["dependencies"]>): void => {
      for (const [name, entry] of Object.entries(entries)) {
        if (!entry.version) continue;
        packages.push({
          name,
          version: entry.version,
          ecosystem: "npm",
          ...(entry.resolved !== undefined ? { source: entry.resolved } : {}),
          ...(entry.integrity !== undefined ? { integrity: entry.integrity } : {}),
          ...(entry.dev !== undefined ? { dev: entry.dev } : {}),
          purl: makePurl({ ecosystem: "npm", name, version: entry.version }),
        });
        if (entry.dependencies) {
          visit(entry.dependencies as NonNullable<NpmLock["dependencies"]>);
        }
      }
    };
    visit(json.dependencies);
  }

  return {
    ecosystem: "npm",
    package_manager: "npm",
    ...(json.lockfileVersion !== undefined
      ? { lockfile_version: String(json.lockfileVersion) }
      : {}),
    packages: dedupe(packages),
  };
}

function dedupe(packages: readonly DependencyPackage[]): readonly DependencyPackage[] {
  const seen = new Map<string, DependencyPackage>();
  for (const p of packages) {
    const key = `${p.name}@${p.version}`;
    if (!seen.has(key)) seen.set(key, p);
  }
  return Array.from(seen.values());
}
