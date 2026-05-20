// Branch-protection auditor (altais_audit_branch_protection).
//
// Audits the protection settings of a repository's default branch and
// flags each weak or missing control that would let an unreviewed,
// force-pushed, or deleting change reach the protected branch.

import type { Finding } from "../../core/types.js";
import { buildSdlcFinding } from "./finding.js";

export interface BranchProtectionConfig {
  readonly required_reviews?: number;
  readonly dismiss_stale_reviews?: boolean;
  readonly required_status_checks?: boolean | readonly string[];
  readonly require_up_to_date?: boolean;
  readonly enforce_for_admins?: boolean;
  readonly restrict_force_push?: boolean;
  readonly restrict_deletions?: boolean;
  readonly require_signed_commits?: boolean;
  readonly require_linear_history?: boolean;
  readonly require_conversation_resolution?: boolean;
}

export interface BranchProtectionAuditInput {
  readonly config: BranchProtectionConfig;
  readonly filename?: string;
}

const REFS = [
  "https://docs.github.com/en/repositories/configuring-branches-and-merges-for-your-repository/managing-protected-branches/about-protected-branches",
  "https://cwe.mitre.org/data/definitions/1269.html",
  "https://cwe.mitre.org/data/definitions/284.html",
];

function statusChecksConfigured(value: boolean | readonly string[] | undefined): boolean {
  if (value === undefined) return false;
  if (typeof value === "boolean") return value;
  return value.length > 0;
}

function mk(
  input: BranchProtectionAuditInput,
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
      tags: ["branch-protection", "access-control"],
    },
    input.filename,
  );
}

export function auditBranchProtection(input: BranchProtectionAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const c = input.config;

  if (c.required_reviews === undefined || c.required_reviews < 1) {
    findings.push(
      mk(
        input,
        "branch-no-required-review",
        "high",
        "Default branch does not require a pull-request review",
        "With zero required reviews, a contributor can merge their own changes to the protected branch unreviewed, removing the four-eyes control that catches both mistakes and malicious code.",
        "Require at least one — ideally two — approving reviews before a pull request can merge to the default branch.",
        ["CWE-1269", "CWE-284"],
        `required_reviews: ${String(c.required_reviews ?? 0)}`,
      ),
    );
  }

  if (c.dismiss_stale_reviews === false) {
    findings.push(
      mk(
        input,
        "branch-stale-reviews-not-dismissed",
        "medium",
        "Stale approvals are not dismissed when new commits are pushed",
        "If an approval survives later pushes, a reviewer's sign-off applies to code they never saw. An attacker can get a benign change approved and then push malicious commits before merge.",
        "Enable `Dismiss stale pull request approvals when new commits are pushed`.",
        ["CWE-1269"],
        "dismiss_stale_reviews: false",
      ),
    );
  }

  if (!statusChecksConfigured(c.required_status_checks)) {
    findings.push(
      mk(
        input,
        "branch-no-required-status-checks",
        "high",
        "Default branch has no required status checks",
        "Without required status checks, a pull request can merge even when CI, tests, and security scans have failed or never ran, so the protected branch is not guaranteed to be in a known-good state.",
        "Require the CI, test, and security-scan checks to pass before merge to the default branch.",
        ["CWE-1269", "CWE-693"],
        "required_status_checks: none",
      ),
    );
  } else if (c.require_up_to_date === false) {
    findings.push(
      mk(
        input,
        "branch-not-up-to-date-merge",
        "low",
        "Branches need not be up to date before merging",
        "A pull request can merge against a stale base, so the merged combination of changes may never have had its status checks run together, allowing a semantic conflict or regression to slip in.",
        "Enable `Require branches to be up to date before merging` so checks run against the final merge result.",
        ["CWE-1269"],
        "require_up_to_date: false",
      ),
    );
  }

  if (c.enforce_for_admins === false) {
    findings.push(
      mk(
        input,
        "branch-admins-bypass-protection",
        "high",
        "Administrators can bypass branch protection",
        "If protection does not apply to administrators, any admin account — or anyone who compromises one — can push directly to the protected branch, skipping review and status checks entirely.",
        "Enable `Do not allow bypassing the above settings` (include administrators) so the rules apply to everyone.",
        ["CWE-1269", "CWE-284"],
        "enforce_for_admins: false",
      ),
    );
  }

  if (c.restrict_force_push === false) {
    findings.push(
      mk(
        input,
        "branch-force-push-allowed",
        "high",
        "Force pushes to the default branch are allowed",
        "An allowed force push lets someone rewrite the protected branch's history, erasing or substituting commits and destroying the audit trail and any signed history.",
        "Disable force pushes on the default branch in branch protection.",
        ["CWE-1269", "CWE-284"],
        "restrict_force_push: false",
      ),
    );
  }

  if (c.restrict_deletions === false) {
    findings.push(
      mk(
        input,
        "branch-deletion-allowed",
        "medium",
        "The default branch can be deleted",
        "If the protected branch can be deleted, an accidental or malicious deletion removes the branch and its protection in one step, enabling a re-creation with weaker rules.",
        "Disable branch deletion for the default branch in branch protection.",
        ["CWE-1269"],
        "restrict_deletions: false",
      ),
    );
  }

  if (c.require_signed_commits === false) {
    findings.push(
      mk(
        input,
        "branch-signed-commits-not-required",
        "medium",
        "Default branch does not require signed commits",
        "Without a signed-commit requirement, unsigned commits with a forged author identity can land on the protected branch, leaving the history with no cryptographic attribution.",
        "Enable `Require signed commits` for the default branch.",
        ["CWE-347", "CWE-1269"],
        "require_signed_commits: false",
      ),
    );
  }

  if (c.require_conversation_resolution === false) {
    findings.push(
      mk(
        input,
        "branch-conversations-not-required-resolved",
        "low",
        "Unresolved review conversations do not block merge",
        "If open review threads do not block merge, a reviewer's unresolved security concern can be silently bypassed.",
        "Enable `Require conversation resolution before merging` for the default branch.",
        ["CWE-1269"],
        "require_conversation_resolution: false",
      ),
    );
  }

  if (c.require_linear_history === false) {
    findings.push(
      mk(
        input,
        "branch-linear-history-not-required",
        "info",
        "Default branch does not require a linear history",
        "A non-linear history makes the protected branch harder to audit and review and complicates bisecting a regression to a single commit.",
        "Consider enabling `Require linear history` so each change is a single, reviewable commit or squash.",
        ["CWE-1269"],
        "require_linear_history: false",
      ),
    );
  }

  return findings;
}
