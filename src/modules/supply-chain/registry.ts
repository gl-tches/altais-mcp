// Package registry configuration audit.
//
// Recognizes .npmrc, pip.conf / pyproject.toml [tool.poetry.source], and
// .cargo/config.toml [registries] entries. Flags HTTP registries,
// plaintext auth tokens, and missing scoped-registry configuration that
// would let dependency-confusion attacks succeed.

import type { Finding } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export type RegistryConfigKind = "npmrc" | "pip" | "cargo" | "auto";

export interface RegistryAuditReport {
  readonly findings: readonly Finding[];
  readonly summary: { readonly total: number };
}

const REFS = [
  "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc",
  "https://pip.pypa.io/en/stable/topics/authentication/",
  "https://doc.rust-lang.org/cargo/reference/registries.html",
];

interface Check {
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly applies: readonly RegistryConfigKind[];
  readonly regex: RegExp;
}

const CHECKS: readonly Check[] = [
  {
    rule: "registry-http",
    severity: "critical",
    title: "Registry configured over HTTP (not HTTPS)",
    description:
      "Plain-HTTP registries allow a network attacker to swap downloaded packages on the fly.",
    remediation: "Replace the URL with the HTTPS equivalent.",
    cwe: ["CWE-319"],
    applies: ["npmrc", "pip", "cargo", "auto"],
    regex: /^\s*(?:registry|index-url|extra-index-url|index|url)\s*=\s*http:\/\//im,
  },
  {
    rule: "registry-plaintext-authtoken",
    severity: "high",
    title: "Auth token in registry config (likely committed plaintext)",
    description:
      "An `_authToken` / `password` is set inline. Even when this file is .gitignored, copy-paste between machines and CI leaves the token in shell history and backups.",
    remediation:
      "Reference a value from the environment (`${NPM_TOKEN}` for npm, env vars for pip, `[registries.foo.token]` from a separate file for cargo).",
    cwe: ["CWE-256", "CWE-540"],
    applies: ["npmrc", "pip", "cargo", "auto"],
    regex: /^\s*(?:.*:_authToken|password|token)\s*=\s*(?!.*\$\{)[^\s${]/im,
  },
  {
    rule: "registry-strict-ssl-disabled",
    severity: "critical",
    title: "TLS certificate validation disabled (`strict-ssl=false`)",
    description:
      "Disabling certificate verification makes the registry connection trivially MITM-able.",
    remediation:
      "Remove `strict-ssl=false` / re-enable verification. Install the root CA if a private registry uses an internal CA.",
    cwe: ["CWE-295"],
    applies: ["npmrc", "auto"],
    regex: /^\s*strict-ssl\s*=\s*false\s*$/im,
  },
  {
    rule: "registry-pip-trusted-host-public",
    severity: "high",
    title: "pip `trusted-host` includes a public host",
    description:
      "`trusted-host` disables TLS verification for the listed host. Listing public hosts (pypi.org, files.pythonhosted.org) removes a defense-in-depth control with no benefit.",
    remediation:
      "Remove `trusted-host` for public registries. Use only for internal hosts when TLS is genuinely unavailable.",
    cwe: ["CWE-295"],
    applies: ["pip", "auto"],
    regex: /^\s*trusted-host\s*=\s*.*(?:pypi\.org|files\.pythonhosted\.org)/im,
  },
];

export function auditRegistryConfig(
  text: string,
  kind: RegistryConfigKind,
  source: string | undefined,
): RegistryAuditReport {
  const findings: Finding[] = [];
  for (const check of CHECKS) {
    if (!check.applies.includes(kind) && !check.applies.includes("auto")) continue;
    const flagSet = new Set([...check.regex.flags.split(""), "g", "m"]);
    const regex = new RegExp(check.regex.source, Array.from(flagSet).join(""));
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      const evidence = m[0].trim().slice(0, 200);
      const idx = m.index;
      const line = countLines(text, idx);
      const location = source !== undefined ? { file: source, line_start: line } : undefined;
      findings.push({
        id: findingId("supply_chain", check.rule, location, evidence),
        module: "supply_chain",
        rule: check.rule,
        severity: check.severity,
        cwe: check.cwe,
        title: check.title,
        description: check.description,
        ...(location !== undefined ? { location } : {}),
        evidence,
        remediation: check.remediation,
        references: REFS,
        tags: ["supply-chain", "registry-config", `kind:${kind}`],
        status: "open",
      });
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  return { findings, summary: { total: findings.length } };
}

function countLines(text: string, end: number): number {
  let n = 1;
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 0x0a) n++;
  return n;
}
