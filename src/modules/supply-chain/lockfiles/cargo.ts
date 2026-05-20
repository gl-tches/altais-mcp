// `Cargo.lock` parser.

import { parse as parseToml } from "smol-toml";
import type { DependencyPackage, LockfileParseResult } from "../types.js";
import { makePurl } from "../types.js";

interface CargoLockPackage {
  readonly name: string;
  readonly version: string;
  readonly source?: string;
  readonly checksum?: string;
  readonly dependencies?: readonly string[];
}

interface CargoLock {
  readonly version?: number;
  readonly package?: readonly CargoLockPackage[];
}

export function parseCargoLock(text: string): LockfileParseResult {
  const parsed = parseToml(text) as unknown as CargoLock;
  const packages: DependencyPackage[] = [];
  for (const p of parsed.package ?? []) {
    if (!p.name || !p.version) continue;
    packages.push({
      name: p.name,
      version: p.version,
      ecosystem: "cargo",
      ...(p.source !== undefined ? { source: p.source } : {}),
      ...(p.checksum !== undefined ? { integrity: `sha256:${p.checksum}` } : {}),
      ...(p.dependencies !== undefined
        ? { dependencies: p.dependencies.map((d) => d.split(" ")[0] ?? d) }
        : {}),
      purl: makePurl({ ecosystem: "cargo", name: p.name, version: p.version }),
    });
  }
  return {
    ecosystem: "cargo",
    package_manager: "cargo",
    ...(parsed.version !== undefined ? { lockfile_version: String(parsed.version) } : {}),
    packages,
  };
}
