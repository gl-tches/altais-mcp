// Dependency-confusion detector.
//
// Given a list of internal package names / npm scopes / Python prefixes,
// flag any packages that match the internal pattern but resolved to a
// public registry source.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import type { DependencyPackage } from "./types.js";

const PUBLIC_REGISTRY_HOSTS = [
  "registry.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "proxy.golang.org",
];

export interface DepConfusionInput {
  readonly internal_names?: readonly string[];
  readonly internal_scopes?: readonly string[];
  readonly internal_prefixes?: readonly string[];
  readonly internal_registries?: readonly string[];
}

export interface DepConfusionReport {
  readonly findings: readonly Finding[];
  readonly suspects: readonly { readonly name: string; readonly source: string | undefined }[];
}

function isPublicRegistry(source: string | undefined): boolean {
  if (!source) return true;
  try {
    const u = new URL(source.startsWith("registry+") ? source.slice("registry+".length) : source);
    return PUBLIC_REGISTRY_HOSTS.some((h) => u.host.endsWith(h));
  } catch {
    return false;
  }
}

function isInternalRegistry(source: string | undefined, internal: readonly string[]): boolean {
  if (!source) return false;
  return internal.some((host) => source.includes(host));
}

function matchesInternal(pkg: DependencyPackage, input: DepConfusionInput): boolean {
  if (input.internal_names?.includes(pkg.name) ?? false) return true;
  if (input.internal_scopes) {
    for (const scope of input.internal_scopes) {
      const s = scope.startsWith("@") ? scope : `@${scope}`;
      if (pkg.name.startsWith(`${s}/`)) return true;
    }
  }
  if (input.internal_prefixes) {
    for (const prefix of input.internal_prefixes) {
      if (pkg.name.startsWith(prefix)) return true;
    }
  }
  return false;
}

export function checkDependencyConfusion(
  packages: readonly DependencyPackage[],
  input: DepConfusionInput,
  source: string | undefined,
): DepConfusionReport {
  const findings: Finding[] = [];
  const suspects: { name: string; source: string | undefined }[] = [];
  const internalRegistries = input.internal_registries ?? [];

  for (const pkg of packages) {
    if (!matchesInternal(pkg, input)) continue;
    if (isInternalRegistry(pkg.source, internalRegistries)) continue;
    if (!isPublicRegistry(pkg.source)) continue;
    suspects.push({ name: pkg.name, source: pkg.source });
    findings.push(buildFinding(pkg, source));
  }
  return { findings, suspects };
}

function buildFinding(pkg: DependencyPackage, src: string | undefined): Finding {
  const location: FindingLocation | undefined =
    src !== undefined ? { file: src, line_start: 1 } : undefined;
  const evidence = `${pkg.name}@${pkg.version} source=${pkg.source ?? "(unknown)"}`;
  return {
    id: findingId("supply_chain", "dependency-confusion", location, evidence),
    module: "supply_chain",
    rule: "dependency-confusion",
    severity: "critical",
    cwe: ["CWE-1357", "CWE-829"],
    title: `Possible dependency confusion: \`${pkg.name}\` resolved from a public registry`,
    description: `\`${pkg.name}\` matches an internal naming pattern but resolved from \`${pkg.source ?? "(unknown)"}\` — a public registry. An attacker could publish a matching name with a higher version and have it picked up by your installer.`,
    ...(location !== undefined ? { location } : {}),
    evidence,
    remediation:
      "Reserve internal names on the public registry. Configure scoped registries / package routing rules in your package manager (npm: `publishConfig.registry`; pip: `--index-url`; cargo: alternative registries).",
    references: [
      "https://cwe.mitre.org/data/definitions/1357.html",
      "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
    ],
    tags: ["supply-chain", "dependency-confusion", `ecosystem:${pkg.ecosystem}`],
    status: "open",
  };
}
