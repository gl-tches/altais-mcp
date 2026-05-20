// Build-integrity audit for CI/CD configurations.
//
// Pattern-based checks against the raw text of GitHub Actions / GitLab
// CI / generic shell pipelines. Flags third-party actions without a
// commit pin, secrets echoed to logs, missing signature verification on
// release artifacts, and a few classic misconfigurations.

import type { Finding } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

interface Check {
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly regex: RegExp;
}

const REFS = ["https://slsa.dev/spec/v1.0/source-requirements"];

const CHECKS: readonly Check[] = [
  {
    rule: "action-unpinned-tag",
    severity: "high",
    title: "Third-party GitHub Action pinned by a moving tag",
    description:
      "An action is referenced by tag (e.g. `@v3`). Tags are mutable — an attacker who compromises the maintainer or repo can replace the tag with a malicious commit, and the next workflow run will pick it up silently.",
    remediation:
      "Pin third-party actions by full commit SHA. Verified-creator actions from `actions/*` may be pinned by tag with care.",
    cwe: ["CWE-829", "CWE-353"],
    regex: /\buses:\s+([^/\s]+)\/([^@\s]+)@v?\d+(?:\.\d+){0,2}\b/g,
  },
  {
    rule: "action-floating-branch",
    severity: "critical",
    title: "GitHub Action pinned to a branch",
    description:
      "An action is referenced by branch (e.g. `@main`). The action's code can change at any time without any signal in the workflow file.",
    remediation: "Pin by commit SHA, or by an immutable tag from a maintainer you trust.",
    cwe: ["CWE-829"],
    regex: /\buses:\s+[^/\s]+\/[^@\s]+@(?:main|master|develop|trunk)\b/g,
  },
  {
    rule: "secret-echoed-in-step",
    severity: "high",
    title: "Secret value used in `echo`, `printf`, or similar output command",
    description:
      "Workflow shell steps echo `${{ secrets.* }}` to stdout. CI logs are persistently stored and often accessible to broader audiences than the secret.",
    remediation:
      "Pass secrets via environment variables to commands that need them, never echo them. Mask values with `::add-mask::` if they must appear.",
    cwe: ["CWE-532"],
    regex: /\b(?:echo|printf|printenv)\b[^\n]*\$\{\{\s*secrets\./g,
  },
  {
    rule: "permissions-write-all",
    severity: "high",
    title: "Workflow grants `permissions: write-all` at top level",
    description:
      "`write-all` permissions give the workflow's `GITHUB_TOKEN` write access to every scope. Any third-party action it runs gains those rights.",
    remediation:
      "Scope permissions per-job. Default `contents: read`; add explicit `contents: write`, `packages: write`, etc. only where needed.",
    cwe: ["CWE-269"],
    regex: /\bpermissions:\s*write-all\b/g,
  },
  {
    rule: "pull-request-target-with-checkout-ref",
    severity: "critical",
    title: "`pull_request_target` checks out untrusted code with secrets",
    description:
      "`pull_request_target` runs with write secrets. Combining it with `actions/checkout` of the PR ref allows a contributor's PR code to read those secrets.",
    remediation:
      "Avoid `pull_request_target` for jobs that need PR code. Run on `pull_request` (no write secrets) instead.",
    cwe: ["CWE-269", "CWE-829"],
    regex:
      /pull_request_target[\s\S]{0,400}?actions\/checkout@[\s\S]{0,200}?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/g,
  },
  {
    rule: "no-cosign-verify-before-deploy",
    severity: "medium",
    title: "Release/deploy step does not verify a signature first",
    description:
      "A `release` / `deploy` step runs without an apparent `cosign verify` (or equivalent). Unsigned artifacts cannot be distinguished from supplier-compromise artifacts at deploy time.",
    remediation:
      "Add `cosign verify` (or your verifier of choice) on every release-bound artifact. Fail the job if verification fails.",
    cwe: ["CWE-345"],
    regex: /\b(release|deploy|publish)\b[\s\S]{0,800}?run:[\s\S]{0,200}/g,
  },
  {
    rule: "curl-bash-pipeline",
    severity: "critical",
    title: "`curl … | bash` in CI",
    description:
      "Piping a remote URL into a shell trusts the upstream server every run. No integrity check, no version pin.",
    remediation:
      "Download artifacts to a file, verify a published checksum or signature, then execute.",
    cwe: ["CWE-494", "CWE-829"],
    regex: /\bcurl[^\n]*\|\s*(?:bash|sh|zsh)\b/g,
  },
];

export interface BuildIntegrityReport {
  readonly findings: readonly Finding[];
  readonly summary: { readonly total: number; readonly by_rule: Readonly<Record<string, number>> };
}

export function checkBuildIntegrity(
  text: string,
  source: string | undefined,
): BuildIntegrityReport {
  const findings: Finding[] = [];
  const byRule: Record<string, number> = {};
  const lines = text.split(/\r?\n/);
  for (const check of CHECKS) {
    const regex = new RegExp(
      check.regex.source,
      check.regex.flags.includes("g") ? check.regex.flags : `${check.regex.flags}g`,
    );
    let m: RegExpExecArray | null;
    while ((m = regex.exec(text)) !== null) {
      const evidence = m[0].slice(0, 180).replace(/\s+/g, " ").trim();
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
        tags: ["supply-chain", "build-integrity"],
        status: "open",
      });
      byRule[check.rule] = (byRule[check.rule] ?? 0) + 1;
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  void lines;
  return { findings, summary: { total: findings.length, by_rule: byRule } };
}

function countLines(text: string, end: number): number {
  let n = 1;
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 0x0a) n++;
  return n;
}
