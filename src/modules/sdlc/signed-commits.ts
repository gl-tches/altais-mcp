// Commit-signing auditor (altais_check_signed_commits).
//
// Verifies that commits are GPG/SSH signed and that signing is enforced.
// Accepts either parsed `git log` output (one commit per line with a
// signature marker) or a precomputed summary in `config`.

import type { Finding } from "../../core/types.js";
import { buildSdlcFinding } from "./finding.js";

export interface SignedCommitsConfig {
  readonly signing_enforced?: boolean;
  readonly total_commits?: number;
  readonly signed_commits?: number;
  readonly verified_commits?: number;
}

export interface SignedCommitsAuditInput {
  readonly git_log?: string;
  readonly config?: SignedCommitsConfig;
  readonly filename?: string;
}

const REFS = [
  "https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification",
  "https://docs.github.com/en/repositories/configuring-branches-and-merges-for-your-repository/managing-protected-branches/about-protected-branches",
  "https://cwe.mitre.org/data/definitions/347.html",
];

export interface SigningStats {
  readonly total: number;
  readonly signed: number;
  readonly verified: number;
}

// `git log --pretty=...%G?` emits a one-char status per commit:
//   G good, U good-but-untrusted, X expired, Y expired-key, R revoked-key,
//   E cannot-check, B bad, N no signature.
const GOOD_STATUSES = new Set(["G", "U"]);
const SIGNED_BUT_UNVERIFIED = new Set(["X", "Y", "R", "E", "B"]);

/**
 * Parse `git log` text into signing stats. Each non-empty line is treated
 * as one commit. A line counts as signed if it carries a recognizable
 * signature marker; verified if that marker indicates a good signature.
 */
export function parseGitLog(text: string): SigningStats {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== "");
  let signed = 0;
  let verified = 0;
  for (const line of lines) {
    const lower = line.toLowerCase();
    const goodText =
      lower.includes("good signature") ||
      lower.includes('good "git" signature') ||
      /\bgpg:\s*good\b/.test(lower);
    const badText =
      lower.includes("bad signature") ||
      lower.includes("no signature") ||
      lower.includes("can't check signature") ||
      lower.includes("cannot check signature");
    // A trailing single-letter %G? marker, e.g. "abc1234 ... G".
    const markerMatch = / ([GUXYRENB])\s*$/.exec(line);
    const marker = markerMatch?.[1];

    let isSigned = false;
    let isVerified = false;
    if (marker !== undefined) {
      if (GOOD_STATUSES.has(marker)) {
        isSigned = true;
        isVerified = true;
      } else if (SIGNED_BUT_UNVERIFIED.has(marker)) {
        isSigned = true;
      }
    }
    if (goodText) {
      isSigned = true;
      isVerified = true;
    } else if (lower.includes("gpg:") && !badText) {
      isSigned = true;
    }
    if (badText && !goodText) {
      // An explicit "no signature" / "bad signature" line is unsigned/unverified.
      isVerified = false;
    }
    if (isSigned) signed++;
    if (isVerified) verified++;
  }
  return { total: lines.length, signed, verified };
}

function mk(
  input: SignedCommitsAuditInput,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
): Finding {
  return buildSdlcFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["commit-signing", "integrity"],
    },
    input.filename,
  );
}

export function checkSignedCommits(input: SignedCommitsAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const config = input.config;

  // Derive stats: prefer explicit config numbers, else parse the git log.
  let stats: SigningStats | undefined;
  if (
    config?.total_commits !== undefined &&
    config.signed_commits !== undefined &&
    config.verified_commits !== undefined
  ) {
    stats = {
      total: config.total_commits,
      signed: config.signed_commits,
      verified: config.verified_commits,
    };
  } else if (input.git_log !== undefined) {
    stats = parseGitLog(input.git_log);
  }

  if (config?.signing_enforced === false) {
    findings.push(
      mk(
        input,
        "commit-signing-not-enforced",
        "high",
        "Commit signing is not enforced",
        "Without an enforced signing requirement, any contributor — or anyone who compromises a contributor's push access — can author commits under a forged identity, and the history carries no cryptographic attestation of authorship.",
        "Enable `Require signed commits` in branch protection so unsigned or unverified commits are rejected on the protected branches.",
        ["CWE-347"],
        "signing_enforced: false",
      ),
    );
  }

  if (stats !== undefined && stats.total > 0) {
    const unsigned = stats.total - stats.signed;
    const unverified = stats.signed - stats.verified;
    if (unsigned > 0) {
      findings.push(
        mk(
          input,
          "unsigned-commits-present",
          "medium",
          `${String(unsigned)} of ${String(stats.total)} commits are unsigned`,
          "Unsigned commits carry no cryptographic proof of authorship. A pushed commit can claim any author identity, so the history cannot be trusted to attribute changes.",
          "Configure local commit signing (`git config commit.gpgsign true`) for every contributor and reject unsigned commits in branch protection.",
          ["CWE-347"],
          `unsigned=${String(unsigned)}/${String(stats.total)}`,
        ),
      );
    }
    if (unverified > 0) {
      findings.push(
        mk(
          input,
          "unverified-commit-signatures",
          "medium",
          `${String(unverified)} commit signature(s) could not be verified`,
          "A commit is signed but the signature is bad, expired, revoked, or made with an unknown key. The signature provides no trust until it can be verified against a known, valid key.",
          "Register each signer's current GPG/SSH public key with the forge, rotate expired keys, and re-sign or reject commits whose signatures cannot be verified.",
          ["CWE-347", "CWE-345"],
          `unverified=${String(unverified)}/${String(stats.signed)}`,
        ),
      );
    }
  }

  return findings;
}
