// Shared types for the supply-chain module.

export type EcosystemId = "npm" | "cargo" | "pypi" | "go";

export interface DependencyPackage {
  readonly name: string;
  readonly version: string;
  readonly ecosystem: EcosystemId;
  readonly source?: string;
  readonly integrity?: string;
  readonly license?: string;
  readonly dev?: boolean;
  readonly optional?: boolean;
  readonly dependencies?: readonly string[];
  readonly purl?: string;
}

export interface LockfileParseResult {
  readonly ecosystem: EcosystemId;
  readonly package_manager: string;
  readonly lockfile_version?: string;
  readonly packages: readonly DependencyPackage[];
}

export function makePurl(pkg: Pick<DependencyPackage, "ecosystem" | "name" | "version">): string {
  const type = pkg.ecosystem === "pypi" ? "pypi" : pkg.ecosystem;
  return `pkg:${type}/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}`;
}
