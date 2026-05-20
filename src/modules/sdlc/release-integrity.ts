// Release-integrity auditor (altais_check_release_integrity).
//
// Verifies that a release process carries the controls that let a
// consumer trust a published artifact: signatures, checksums,
// reproducible builds, an SBOM, provenance attestation, release from a
// protected branch, a maintained changelog, and signed tags.

import type { Finding } from "../../core/types.js";
import { buildSdlcFinding } from "./finding.js";

export interface ReleaseIntegrityConfig {
  readonly artifacts_signed?: boolean;
  readonly checksums_published?: boolean;
  readonly reproducible_build?: boolean;
  readonly sbom_published?: boolean;
  readonly provenance_attestation?: boolean;
  readonly release_from_protected_branch?: boolean;
  readonly changelog_maintained?: boolean;
  readonly tags_signed?: boolean;
}

export interface ReleaseIntegrityAuditInput {
  readonly config: ReleaseIntegrityConfig;
  readonly filename?: string;
}

const REFS = [
  "https://slsa.dev/spec/v1.0/requirements",
  "https://owasp.org/www-project-software-component-verification-standard/",
  "https://cwe.mitre.org/data/definitions/353.html",
];

interface ControlCheck {
  readonly key: keyof ReleaseIntegrityConfig;
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

const CONTROLS: readonly ControlCheck[] = [
  {
    key: "artifacts_signed",
    rule: "release-artifacts-unsigned",
    severity: "high",
    title: "Release artifacts are not signed",
    description:
      "Unsigned release artifacts cannot be verified as authentic. A consumer cannot tell a genuine artifact from one substituted by a compromised mirror, registry, or CDN.",
    remediation:
      "Sign every release artifact (Sigstore cosign, GPG, or minisign) and publish the public key / verification instructions alongside the release.",
    cwe: ["CWE-347", "CWE-345"],
  },
  {
    key: "checksums_published",
    rule: "release-no-checksums",
    severity: "medium",
    title: "Release does not publish checksums",
    description:
      "Without published checksums (`SHA256SUMS`), consumers cannot detect an artifact corrupted or tampered with in transit.",
    remediation:
      "Publish a checksum manifest for every release artifact, and sign the manifest so the checksums themselves are tamper-evident.",
    cwe: ["CWE-353", "CWE-345"],
  },
  {
    key: "reproducible_build",
    rule: "release-not-reproducible",
    severity: "low",
    title: "Build is not reproducible",
    description:
      "A non-reproducible build cannot be independently rebuilt to the same bytes, so a backdoor injected into the official build is undetectable by comparison.",
    remediation:
      "Make the build reproducible: pin all inputs, eliminate timestamps and non-determinism, and document the steps to rebuild bit-for-bit.",
    cwe: ["CWE-1357"],
  },
  {
    key: "sbom_published",
    rule: "release-no-sbom",
    severity: "medium",
    title: "Release does not publish an SBOM",
    description:
      "Without a Software Bill of Materials, consumers cannot determine which components and versions a release contains, and cannot assess exposure when a new CVE lands.",
    remediation:
      "Generate and publish an SBOM (CycloneDX or SPDX) for every release as a signed release asset.",
    cwe: ["CWE-1357", "CWE-1104"],
  },
  {
    key: "provenance_attestation",
    rule: "release-no-provenance",
    severity: "high",
    title: "Release has no provenance attestation",
    description:
      "Without signed provenance (SLSA / in-toto), there is no verifiable link between the published artifact and the source commit and build that produced it.",
    remediation:
      "Generate SLSA provenance for every release (for example via the SLSA GitHub generator) and sign it so consumers can verify the build path.",
    cwe: ["CWE-345", "CWE-1357"],
  },
  {
    key: "release_from_protected_branch",
    rule: "release-from-unprotected-branch",
    severity: "high",
    title: "Releases are not cut from a protected branch",
    description:
      "If releases can be built from an arbitrary, unprotected branch, an unreviewed or malicious commit can be released without passing required checks.",
    remediation:
      "Restrict the release workflow to a protected branch (and signed, protected tags) so every released commit has passed branch-protection controls.",
    cwe: ["CWE-284", "CWE-345"],
  },
  {
    key: "changelog_maintained",
    rule: "release-no-changelog",
    severity: "low",
    title: "Release has no maintained changelog",
    description:
      "Without a changelog, consumers cannot see what changed between versions — including security fixes — and cannot make an informed upgrade decision.",
    remediation:
      "Maintain a changelog (Keep a Changelog format) and call out security-relevant fixes explicitly in each release.",
    cwe: ["CWE-1357"],
  },
  {
    key: "tags_signed",
    rule: "release-tags-unsigned",
    severity: "medium",
    title: "Release tags are not signed",
    description:
      "An unsigned git tag can be created or moved by anyone with push access, so a tag alone does not attest who cut the release or that it points at the reviewed commit.",
    remediation:
      "Create annotated, GPG- or SSH-signed tags for every release and require signed tags in branch / tag protection.",
    cwe: ["CWE-347", "CWE-345"],
  },
];

export function checkReleaseIntegrity(input: ReleaseIntegrityAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const config = input.config;
  for (const control of CONTROLS) {
    if (config[control.key] === false) {
      findings.push(
        buildSdlcFinding(
          {
            rule: control.rule,
            severity: control.severity,
            title: control.title,
            description: control.description,
            remediation: control.remediation,
            cwe: control.cwe,
            references: REFS,
            evidence: `${control.key}: false`,
            tags: ["release", "integrity"],
          },
          input.filename,
        ),
      );
    }
  }
  return findings;
}
