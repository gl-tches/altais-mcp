// `poetry.lock` parser.

import { parse as parseToml } from "smol-toml";
import type { DependencyPackage, LockfileParseResult } from "../types.js";
import { makePurl } from "../types.js";

interface PoetryPackage {
  readonly name: string;
  readonly version: string;
  readonly description?: string;
  readonly category?: string;
  readonly optional?: boolean;
  readonly source?: { readonly url?: string; readonly type?: string };
  readonly dependencies?: Record<string, unknown>;
}

interface PoetryLock {
  readonly metadata?: { readonly "lock-version"?: string };
  readonly package?: readonly PoetryPackage[];
}

export function parsePoetryLock(text: string): LockfileParseResult {
  const parsed = parseToml(text) as unknown as PoetryLock;
  const packages: DependencyPackage[] = [];
  for (const p of parsed.package ?? []) {
    if (!p.name || !p.version) continue;
    packages.push({
      name: p.name,
      version: p.version,
      ecosystem: "pypi",
      ...(p.source?.url !== undefined ? { source: p.source.url } : {}),
      ...(p.category === "dev" ? { dev: true } : {}),
      ...(p.optional !== undefined ? { optional: p.optional } : {}),
      ...(p.dependencies !== undefined ? { dependencies: Object.keys(p.dependencies) } : {}),
      purl: makePurl({ ecosystem: "pypi", name: p.name, version: p.version }),
    });
  }
  return {
    ecosystem: "pypi",
    package_manager: "poetry",
    ...(parsed.metadata?.["lock-version"] !== undefined
      ? { lockfile_version: parsed.metadata["lock-version"] }
      : {}),
    packages,
  };
}
