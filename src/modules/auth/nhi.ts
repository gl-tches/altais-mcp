// Non-Human Identity auditor against OWASP NHI Top 10 (2025).

import type { Finding, Severity } from "../../core/types.js";
import { buildAuthFinding } from "./finding.js";

export type NhiKind =
  | "service_account"
  | "api_key"
  | "machine_user"
  | "ci_runner"
  | "workload_identity"
  | "bot_account"
  | "other";

export interface NhiIdentity {
  readonly name: string;
  readonly kind: NhiKind;
  readonly environment?: string;
  readonly owner?: string;
  readonly credential_type?: "static_key" | "oidc" | "workload_identity" | "mTLS" | "password";
  readonly credential_age_days?: number;
  readonly rotation_period_days?: number;
  readonly scopes?: readonly string[];
  readonly scoped_to_resources?: readonly string[];
  readonly expires_at?: string;
  readonly mfa_enabled?: boolean;
  readonly stored_in_repo?: boolean;
  readonly stored_in_env_vars?: boolean;
}

export interface NhiAuditInput {
  readonly identities: readonly NhiIdentity[];
  readonly filename?: string;
}

const REFS = ["https://owasp.org/www-project-non-human-identities-top-10/"];

interface Check {
  readonly rule: string;
  readonly nhi: string; // OWASP NHI category (NHI1..NHI10)
  readonly severity: Severity;
  readonly title: (i: NhiIdentity) => string;
  readonly description: (i: NhiIdentity) => string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly applies: (i: NhiIdentity) => boolean;
}

const CHECKS: readonly Check[] = [
  {
    rule: "nhi-no-owner",
    nhi: "NHI1",
    severity: "medium",
    title: (i) => `NHI \`${i.name}\` has no owner`,
    description: (i) =>
      `Without an owner, rotation and offboarding for ${i.name} have no responsible party.`,
    remediation: "Assign a team and a backup owner. Encode them in IaC / inventory.",
    cwe: ["CWE-693"],
    applies: (i) => i.owner === undefined || i.owner === "",
  },
  {
    rule: "nhi-long-lived-static-key",
    nhi: "NHI3",
    severity: "high",
    title: (i) => `NHI \`${i.name}\` uses a static key`,
    description: () =>
      "Static keys do not expire and survive in environments long after the workload that consumed them. Prefer workload identity or OIDC federation.",
    remediation:
      "Migrate to OIDC federation / workload identity / mTLS. Where static keys are unavoidable, rotate ≤ 90 days.",
    cwe: ["CWE-798"],
    applies: (i) => i.credential_type === "static_key",
  },
  {
    rule: "nhi-credential-not-rotated",
    nhi: "NHI3",
    severity: "high",
    title: (i) => `NHI \`${i.name}\` credential age exceeds rotation period`,
    description: (i) =>
      `Credential is ${i.credential_age_days}d old; rotation period is ${i.rotation_period_days}d.`,
    remediation: "Rotate now. Automate rotation through your secrets manager.",
    cwe: ["CWE-798"],
    applies: (i) =>
      i.credential_age_days !== undefined &&
      i.rotation_period_days !== undefined &&
      i.credential_age_days > i.rotation_period_days,
  },
  {
    rule: "nhi-overprivileged-wildcard-scope",
    nhi: "NHI4",
    severity: "high",
    title: (i) => `NHI \`${i.name}\` granted wildcard scope`,
    description: () =>
      "Wildcard scopes (`*`) give the identity more access than any workload needs.",
    remediation:
      "Enumerate the specific actions and resources the identity uses. Re-evaluate quarterly.",
    cwe: ["CWE-269"],
    applies: (i) => (i.scopes ?? []).some((s) => s === "*" || s.endsWith(":*")),
  },
  {
    rule: "nhi-credential-in-repo",
    nhi: "NHI6",
    severity: "critical",
    title: (i) => `NHI \`${i.name}\` credential committed to a repository`,
    description: () =>
      "Credentials in git history are functionally exposed even after deletion. Treat them as breached.",
    remediation:
      "Rotate immediately. Use a secrets manager with at-runtime reference (`${SECRETS.FOO}`).",
    cwe: ["CWE-798", "CWE-540"],
    applies: (i) => i.stored_in_repo === true,
  },
  {
    rule: "nhi-credential-in-env-only",
    nhi: "NHI6",
    severity: "low",
    title: (i) => `NHI \`${i.name}\` credential lives in environment variables`,
    description: () =>
      "Environment variables are visible in process listings and many telemetry tools. Acceptable for low-sensitivity workloads, but a managed secrets store is preferable.",
    remediation:
      "Move to a managed secrets store (AWS SSM/Secrets Manager, HashiCorp Vault, GCP Secret Manager).",
    cwe: ["CWE-256"],
    applies: (i) =>
      i.stored_in_env_vars === true &&
      i.stored_in_repo !== true &&
      i.credential_type !== "workload_identity" &&
      i.credential_type !== "oidc",
  },
  {
    rule: "nhi-no-expiry",
    nhi: "NHI7",
    severity: "medium",
    title: (i) => `NHI \`${i.name}\` credential has no expiry`,
    description: () =>
      "An NHI credential without expiry survives until manually revoked. Forgotten credentials are a common compromise path.",
    remediation:
      "Set expires_at on every issued credential. Default 90 days; require justification for longer.",
    cwe: ["CWE-613"],
    applies: (i) =>
      i.expires_at === undefined &&
      i.credential_type !== "workload_identity" &&
      i.credential_type !== "oidc",
  },
  {
    rule: "nhi-password-credential",
    nhi: "NHI3",
    severity: "high",
    title: (i) => `NHI \`${i.name}\` uses a password credential`,
    description: () =>
      "Service accounts authenticating with a password are indistinguishable from shared user accounts. They cannot rotate cleanly and tend to be over-privileged.",
    remediation:
      "Migrate to OIDC / workload identity / mTLS. If passwords are unavoidable, store in a managed vault with rotation.",
    cwe: ["CWE-798"],
    applies: (i) => i.credential_type === "password",
  },
];

export function auditNhi(input: NhiAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  for (const id of input.identities) {
    for (const check of CHECKS) {
      if (!check.applies(id)) continue;
      findings.push(
        buildAuthFinding(
          {
            rule: check.rule,
            severity: check.severity,
            title: check.title(id),
            description: `${check.nhi}: ${check.description(id)}`,
            remediation: check.remediation,
            cwe: check.cwe,
            references: REFS,
            evidence: `name=${id.name}, kind=${id.kind}, env=${id.environment ?? "?"}`,
            tags: ["nhi", check.nhi.toLowerCase()],
          },
          input.filename,
        ),
      );
    }
  }
  return findings;
}
