// License checker.
//
// Default policy:
// - allow: permissive OSS licenses (MIT, BSD, Apache-2.0, ISC, ...)
// - warn: weak copyleft (MPL-2.0, LGPL variants)
// - deny: strong copyleft (GPL, AGPL) and unknown / unlicensed
// Callers can supply custom lists.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import type { DependencyPackage } from "./types.js";

export const DEFAULT_ALLOW: readonly string[] = [
  "MIT",
  "MIT-0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "Apache-2.0",
  "ISC",
  "0BSD",
  "Unlicense",
  "CC0-1.0",
  "Zlib",
  "BlueOak-1.0.0",
  "Python-2.0",
];

export const DEFAULT_WARN: readonly string[] = [
  "MPL-1.1",
  "MPL-2.0",
  "EPL-1.0",
  "EPL-2.0",
  "CDDL-1.0",
  "CDDL-1.1",
  "LGPL-2.0",
  "LGPL-2.0-only",
  "LGPL-2.1",
  "LGPL-2.1-only",
  "LGPL-2.1-or-later",
  "LGPL-3.0",
  "LGPL-3.0-only",
  "LGPL-3.0-or-later",
];

export const DEFAULT_DENY: readonly string[] = [
  "GPL-1.0",
  "GPL-1.0-only",
  "GPL-1.0-or-later",
  "GPL-2.0",
  "GPL-2.0-only",
  "GPL-2.0-or-later",
  "GPL-3.0",
  "GPL-3.0-only",
  "GPL-3.0-or-later",
  "AGPL-1.0",
  "AGPL-3.0",
  "AGPL-3.0-only",
  "AGPL-3.0-or-later",
  "SSPL-1.0",
  "BUSL-1.1",
  "Commons-Clause",
];

export interface LicensePolicy {
  readonly allow?: readonly string[];
  readonly warn?: readonly string[];
  readonly deny?: readonly string[];
}

export type LicenseClass = "allowed" | "warn" | "denied" | "unknown";

export interface LicenseReport {
  readonly findings: readonly Finding[];
  readonly summary: {
    readonly allowed: number;
    readonly warn: number;
    readonly denied: number;
    readonly unknown: number;
  };
}

function classify(license: string | undefined, policy: LicensePolicy): LicenseClass {
  if (!license || license === "NOASSERTION") return "unknown";
  const allow = new Set(policy.allow ?? DEFAULT_ALLOW);
  const warn = new Set(policy.warn ?? DEFAULT_WARN);
  const deny = new Set(policy.deny ?? DEFAULT_DENY);
  // Tolerate composite expressions like "(MIT OR Apache-2.0)".
  const tokens = license.split(/[ ()|/]+|\s+OR\s+|\s+AND\s+/i).filter(Boolean);
  let highest: LicenseClass = "allowed";
  let saw = false;
  for (const tok of tokens) {
    const lic = tok.replace(/[+]$/, "");
    if (deny.has(lic)) return "denied";
    if (warn.has(lic)) highest = "warn";
    if (allow.has(lic)) saw = true;
  }
  if (!saw && highest === "allowed") return "unknown";
  return highest;
}

export function checkLicenses(
  packages: readonly DependencyPackage[],
  policy: LicensePolicy,
  source: string | undefined,
): LicenseReport {
  const findings: Finding[] = [];
  const summary = { allowed: 0, warn: 0, denied: 0, unknown: 0 };
  for (const pkg of packages) {
    const klass = classify(pkg.license, policy);
    summary[klass] += 1;
    if (klass === "allowed") continue;
    findings.push(buildFinding(pkg, klass, source));
  }
  return { findings, summary };
}

function buildFinding(
  pkg: DependencyPackage,
  klass: Exclude<LicenseClass, "allowed">,
  source: string | undefined,
): Finding {
  const location: FindingLocation | undefined =
    source !== undefined ? { file: source, line_start: 1 } : undefined;
  const evidence = `${pkg.name}@${pkg.version} license=${pkg.license ?? "unknown"}`;
  const severity = klass === "denied" ? "high" : klass === "warn" ? "medium" : "low";
  const title =
    klass === "denied"
      ? `Denied license: ${pkg.license} (${pkg.name}@${pkg.version})`
      : klass === "warn"
        ? `Weak copyleft license: ${pkg.license} (${pkg.name}@${pkg.version})`
        : `Unknown / unspecified license (${pkg.name}@${pkg.version})`;
  const description =
    klass === "denied"
      ? `The license \`${pkg.license}\` is on the deny list — strong copyleft or commercial restriction that conflicts with the project's license policy.`
      : klass === "warn"
        ? `The license \`${pkg.license}\` is weak copyleft — it may impose obligations on distribution that the project should review with legal.`
        : `No license declared for ${pkg.name}@${pkg.version}, or the value (\`${pkg.license ?? "n/a"}\`) is not in any policy list.`;
  return {
    id: findingId("supply_chain", `license-${klass}`, location, evidence),
    module: "supply_chain",
    rule: `license-${klass}`,
    severity,
    cwe: ["CWE-1357"],
    title,
    description,
    ...(location !== undefined ? { location } : {}),
    evidence,
    remediation:
      klass === "denied"
        ? "Replace the dependency with an allow-listed alternative, or obtain a commercial license."
        : klass === "warn"
          ? "Review the distribution terms with legal. Confirm whether the project's distribution model triggers copyleft obligations."
          : "Open the package's repository and document the license. Update the package metadata if the upstream omits it.",
    references: ["https://spdx.org/licenses/"],
    tags: ["supply-chain", "license", `license-class:${klass}`],
    status: "open",
  };
}
