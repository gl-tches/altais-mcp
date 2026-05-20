// CI/CD pipeline security auditor (altais_audit_ci_cd).
//
// Reviews a CI/CD pipeline for the security GATES that should block an
// insecure change from shipping: SAST, dependency / SCA scanning, secret
// scanning, container image scanning, DAST, and a fail-on-findings
// policy. When pipeline YAML is supplied it is additionally scanned for
// unpinned third-party actions, over-broad permissions, and secrets
// echoed to logs.

import type { Finding } from "../../core/types.js";
import { buildSdlcFinding, lineAt } from "./finding.js";

export interface CiCdConfig {
  readonly has_sast?: boolean;
  readonly has_dependency_scan?: boolean;
  readonly has_secret_scan?: boolean;
  readonly has_container_scan?: boolean;
  readonly has_dast?: boolean;
  readonly blocks_on_failure?: boolean;
  readonly signed_artifacts?: boolean;
}

export interface CiCdAuditInput {
  readonly content?: string;
  readonly config?: CiCdConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
  "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
  "https://cwe.mitre.org/data/definitions/1395.html",
];

interface GateCheck {
  readonly key: keyof CiCdConfig;
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

const GATE_CHECKS: readonly GateCheck[] = [
  {
    key: "has_sast",
    rule: "ci-missing-sast-gate",
    severity: "high",
    title: "Pipeline has no static analysis (SAST) gate",
    description:
      "Without a SAST stage, code with injection, path-traversal, or unsafe-deserialization flaws can merge and deploy with no automated review. Static analysis is the cheapest place to catch these defects.",
    remediation:
      "Add a SAST job (CodeQL, Semgrep, or an equivalent) that runs on every pull request and fails the pipeline on new findings.",
    cwe: ["CWE-1395"],
  },
  {
    key: "has_dependency_scan",
    rule: "ci-missing-dependency-scan",
    severity: "high",
    title: "Pipeline has no dependency / SCA scan",
    description:
      "Without software-composition analysis, known-vulnerable third-party packages enter the build undetected. Most exploited application CVEs originate in dependencies, not first-party code.",
    remediation:
      "Add a dependency-scanning job (`npm audit`, `pip-audit`, Dependabot, OSV-Scanner, or Trivy) that runs on every change and fails on high/critical advisories.",
    cwe: ["CWE-1395", "CWE-1104"],
  },
  {
    key: "has_secret_scan",
    rule: "ci-missing-secret-scan",
    severity: "high",
    title: "Pipeline has no secret-scanning gate",
    description:
      "Without secret scanning, a committed API key, token, or private key can reach the default branch and any published artifact before anyone notices.",
    remediation:
      "Add a secret-scanning job (gitleaks, TruffleHog, or GitHub secret scanning with push protection) that runs on every push and pull request.",
    cwe: ["CWE-1395", "CWE-798"],
  },
  {
    key: "has_container_scan",
    rule: "ci-missing-container-scan",
    severity: "medium",
    title: "Pipeline does not scan built container images",
    description:
      "If the pipeline builds container images but never scans them, vulnerable OS packages and base layers ship to production undetected.",
    remediation:
      "Add an image-scanning step (Trivy, Grype, or Docker Scout) after the image build and fail on high/critical findings.",
    cwe: ["CWE-1395", "CWE-1104"],
  },
  {
    key: "has_dast",
    rule: "ci-missing-dast",
    severity: "low",
    title: "Pipeline has no dynamic analysis (DAST) stage",
    description:
      "Static analysis cannot observe runtime behavior. Without a DAST stage against a deployed preview environment, misconfigurations and runtime-only flaws go untested.",
    remediation:
      "Add a DAST job (OWASP ZAP or an equivalent) against an ephemeral preview deployment for web-facing services.",
    cwe: ["CWE-1395"],
  },
  {
    key: "blocks_on_failure",
    rule: "ci-does-not-block-on-failure",
    severity: "high",
    title: "Pipeline does not fail on security findings",
    description:
      "A security stage that does not fail the build is advisory only: insecure changes still merge and deploy. The pipeline must enforce, not just report (CWE-1269: improper privilege management of the release gate).",
    remediation:
      "Make every security job a required, blocking check. Remove `continue-on-error: true` and `|| true` from security steps so a finding fails the pipeline.",
    cwe: ["CWE-1269", "CWE-693"],
  },
  {
    key: "signed_artifacts",
    rule: "ci-unsigned-artifacts",
    severity: "medium",
    title: "Pipeline does not sign build artifacts",
    description:
      "Unsigned artifacts cannot be cryptographically traced to the pipeline that produced them. A tampered or substituted artifact is then indistinguishable from a genuine one.",
    remediation:
      "Sign release artifacts and container images (Sigstore cosign, or a signing key in an HSM) and verify signatures before deployment.",
    cwe: ["CWE-345", "CWE-1357"],
  },
];

interface ContentRule {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

// `uses:` referencing a third-party action by a mutable tag/branch (not a
// 40-char commit SHA). Local actions (`./`) and `docker://` are skipped.
const UNPINNED_ACTION_RE =
  /^[ \t]*-?[ \t]*uses:[ \t]*["']?([A-Za-z0-9][\w.-]*\/[\w.-]+(?:\/[\w.-]+)?)@([^\s"'#]+)/gim;

const CONTENT_RULES: readonly ContentRule[] = [
  {
    rule: "ci-broad-write-permissions",
    regex: /^[ \t]*permissions:[ \t]*write-all\b/gim,
    severity: "high",
    title: "Workflow grants `permissions: write-all`",
    description:
      "`write-all` hands the job's `GITHUB_TOKEN` write access to every scope — contents, packages, deployments, and more. A compromised step or dependency can then push code, publish packages, or alter releases.",
    remediation:
      "Set `permissions: {}` at the workflow level and grant only the minimal scopes each job needs (for example `contents: read`).",
    cwe: ["CWE-1269", "CWE-250"],
  },
  {
    rule: "ci-secret-echoed-to-log",
    regex: /\becho\b[^\n]*\$\{\{[ \t]*secrets\.[A-Za-z0-9_]+[ \t]*\}\}/gi,
    severity: "high",
    title: "Secret echoed to the build log",
    description:
      "Interpolating a `secrets.*` value into an `echo` (or `print`) writes the secret into the job log. Logs are widely readable and frequently retained, so this discloses the credential.",
    remediation:
      "Never print secrets. Pass them through `env:` and let the tool read them; rely on the runner's automatic log masking and avoid echoing secret-bearing variables.",
    cwe: ["CWE-532", "CWE-798"],
  },
  {
    rule: "ci-curl-pipe-shell",
    regex: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|a|da)?sh\b/gi,
    severity: "medium",
    title: "Pipeline pipes a remote script directly into a shell",
    description:
      "A `curl ... | sh` step in CI executes unverified, attacker-controllable code with the pipeline's privileges and secrets. A hijacked URL compromises the build.",
    remediation:
      "Download the script, verify a pinned checksum, then execute it — or install the tool from a pinned, trusted package source.",
    cwe: ["CWE-494", "CWE-829"],
  },
];

const SHA_RE = /^[0-9a-f]{40}$/i;
// Well-known first-party action namespaces — owned by GitHub itself.
const TRUSTED_ACTION_OWNERS = new Set(["actions", "github"]);

export function auditCiCd(input: CiCdAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;
  const config = input.config;
  const content = input.content;

  if (config !== undefined) {
    for (const gate of GATE_CHECKS) {
      if (config[gate.key] === false) {
        findings.push(
          buildSdlcFinding(
            {
              rule: gate.rule,
              severity: gate.severity,
              title: gate.title,
              description: gate.description,
              remediation: gate.remediation,
              cwe: gate.cwe,
              references: REFS,
              evidence: `${gate.key}: false`,
              tags: ["ci-cd", "gate"],
            },
            file,
          ),
        );
      }
    }
  }

  if (content !== undefined) {
    for (const rule of CONTENT_RULES) {
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let m: RegExpExecArray | null;
      while ((m = regex.exec(content)) !== null) {
        findings.push(
          buildSdlcFinding(
            {
              rule: rule.rule,
              severity: rule.severity,
              title: rule.title,
              description: rule.description,
              remediation: rule.remediation,
              cwe: rule.cwe,
              references: REFS,
              evidence: m[0].trim().slice(0, 200),
              tags: ["ci-cd"],
              line: lineAt(content, m.index),
            },
            file,
          ),
        );
        if (m[0].length === 0) regex.lastIndex += 1;
      }
    }

    const actionRe = new RegExp(UNPINNED_ACTION_RE.source, UNPINNED_ACTION_RE.flags);
    let am: RegExpExecArray | null;
    while ((am = actionRe.exec(content)) !== null) {
      const ref = am[1] ?? "";
      const version = am[2] ?? "";
      const owner = (ref.split("/")[0] ?? "").toLowerCase();
      if (TRUSTED_ACTION_OWNERS.has(owner)) continue;
      if (SHA_RE.test(version)) continue;
      findings.push(
        buildSdlcFinding(
          {
            rule: "ci-unpinned-third-party-action",
            severity: "high",
            title: `Third-party action \`${ref}\` is pinned to a mutable ref`,
            description:
              "A third-party action referenced by a tag or branch (`@v1`, `@main`) is mutable: the owner — or anyone who compromises that repo — can change the code the tag points to and run it inside your pipeline with its secrets.",
            remediation:
              "Pin third-party actions to a full 40-character commit SHA (`uses: owner/action@<sha>`), and record the human-readable version in a trailing comment.",
            cwe: ["CWE-829", "CWE-1357"],
            references: REFS,
            evidence: `uses: ${ref}@${version}`.slice(0, 200),
            tags: ["ci-cd", "supply-chain"],
            line: lineAt(content, am.index),
          },
          file,
        ),
      );
      if (am[0].length === 0) actionRe.lastIndex += 1;
    }
  }

  return findings;
}
