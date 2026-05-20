// Secret lifecycle auditor — rotation, expiry, revocation, audit.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding } from "./finding.js";

export type SecretKind =
  | "api_key"
  | "oauth_client_secret"
  | "signing_key"
  | "encryption_key"
  | "password"
  | "webhook";

export interface SecretRecord {
  readonly name: string;
  readonly kind: SecretKind;
  readonly owner?: string;
  readonly created_at?: string;
  readonly last_rotated_at?: string;
  readonly expires_at?: string;
  readonly rotation_period_days?: number;
  readonly revocation_procedure_documented?: boolean;
  readonly audit_logged?: boolean;
  readonly stored_in?: "vault" | "secrets_manager" | "env_var" | "repo" | "file_on_disk";
}

export interface SecretLifecycleInput {
  readonly secrets: readonly SecretRecord[];
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-cheat-sheets/cheatsheets/Secrets_Management_Cheat_Sheet.html",
];

const MAX_AGE_BY_KIND: Readonly<Record<SecretKind, number>> = {
  api_key: 180,
  oauth_client_secret: 365,
  signing_key: 365,
  encryption_key: 365,
  password: 180,
  webhook: 365,
};

export function auditSecretLifecycle(input: SecretLifecycleInput): readonly Finding[] {
  const findings: Finding[] = [];
  const now = Date.now();
  const day = 86_400_000;

  for (const s of input.secrets) {
    if (s.stored_in === "repo") {
      findings.push(
        buildAuthFinding(
          {
            rule: "secret-stored-in-repo",
            severity: "critical",
            title: `Secret \`${s.name}\` stored in a repository`,
            description: "Secrets in repos are exposed even after deletion. Treat as breached.",
            remediation: "Move to a managed vault. Rotate immediately.",
            cwe: ["CWE-540", "CWE-798"],
            references: REFS,
            evidence: `${s.name} stored_in=repo`,
            tags: ["secret-lifecycle"],
          },
          input.filename,
        ),
      );
    }
    if (s.last_rotated_at !== undefined) {
      const ageDays = Math.floor((now - new Date(s.last_rotated_at).getTime()) / day);
      const max = s.rotation_period_days ?? MAX_AGE_BY_KIND[s.kind];
      if (ageDays > max) {
        findings.push(
          buildAuthFinding(
            {
              rule: "secret-rotation-overdue",
              severity: ageDays > max * 2 ? "high" : "medium",
              title: `Secret \`${s.name}\` overdue for rotation (${ageDays}d / max ${max}d)`,
              description: `${s.kind} secrets should rotate at least every ${max}d.`,
              remediation: "Rotate now. Automate rotation through your secrets manager.",
              cwe: ["CWE-798"],
              references: REFS,
              evidence: `${s.name} age=${ageDays}d`,
              tags: ["secret-lifecycle"],
            },
            input.filename,
          ),
        );
      }
    } else if (s.created_at !== undefined) {
      const ageDays = Math.floor((now - new Date(s.created_at).getTime()) / day);
      if (ageDays > MAX_AGE_BY_KIND[s.kind]) {
        findings.push(
          buildAuthFinding(
            {
              rule: "secret-never-rotated",
              severity: "high",
              title: `Secret \`${s.name}\` has never been rotated (${ageDays}d old)`,
              description:
                "No `last_rotated_at` is recorded for a credential older than the rotation threshold.",
              remediation: "Establish a rotation date and rotate.",
              cwe: ["CWE-798"],
              references: REFS,
              evidence: `${s.name} created=${s.created_at}`,
              tags: ["secret-lifecycle"],
            },
            input.filename,
          ),
        );
      }
    }
    if (s.expires_at === undefined) {
      findings.push(
        buildAuthFinding(
          {
            rule: "secret-no-expiry",
            severity: "medium",
            title: `Secret \`${s.name}\` has no expiry`,
            description:
              "A secret without expiry survives until manually revoked. Forgotten credentials are a common compromise path.",
            remediation: "Set an expires_at. Default 1 year; require justification for longer.",
            cwe: ["CWE-613"],
            references: REFS,
            evidence: s.name,
            tags: ["secret-lifecycle"],
          },
          input.filename,
        ),
      );
    } else {
      const remaining = Math.floor((new Date(s.expires_at).getTime() - now) / day);
      if (remaining < 0) {
        findings.push(
          buildAuthFinding(
            {
              rule: "secret-expired-still-in-use",
              severity: "high",
              title: `Secret \`${s.name}\` is past its declared expiry`,
              description: `expires_at=${s.expires_at} but the secret is still listed.`,
              remediation:
                "Verify the secret has been retired in every consumer. Remove from inventory.",
              cwe: ["CWE-613"],
              references: REFS,
              evidence: `${s.name} expired ${Math.abs(remaining)}d ago`,
              tags: ["secret-lifecycle"],
            },
            input.filename,
          ),
        );
      }
    }
    if (s.revocation_procedure_documented === false) {
      findings.push(
        buildAuthFinding(
          {
            rule: "secret-no-revocation-procedure",
            severity: "medium",
            title: `Secret \`${s.name}\` has no documented revocation procedure`,
            description:
              "Without a written procedure, revocation in an incident relies on tribal knowledge.",
            remediation:
              "Document the exact steps and the parties responsible. Practice in tabletop drills.",
            cwe: ["CWE-693"],
            references: REFS,
            evidence: s.name,
            tags: ["secret-lifecycle"],
          },
          input.filename,
        ),
      );
    }
    if (s.audit_logged === false) {
      findings.push(
        buildAuthFinding(
          {
            rule: "secret-no-audit-log",
            severity: "medium",
            title: `Secret \`${s.name}\` access is not audit-logged`,
            description:
              "Without audit logs, compromise detection and rotation timing are guesswork.",
            remediation:
              "Log read / decrypt / rotate / revoke events. Ship logs off-host append-only.",
            cwe: ["CWE-778"],
            references: REFS,
            evidence: s.name,
            tags: ["secret-lifecycle"],
          },
          input.filename,
        ),
      );
    }
  }
  return findings;
}
