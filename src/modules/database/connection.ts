// altais_audit_connection — database connection-string security audit.
//
// Inspects connection strings / URIs for embedded credentials, disabled
// or unspecified TLS, plaintext schemes, default credentials, and empty
// passwords.

import { z } from "zod";
import type { Finding, Severity } from "../../core/types.js";
import { buildDatabaseFinding } from "./finding.js";

const REFS = [
  "https://cwe.mitre.org/data/definitions/798.html",
  "https://cwe.mitre.org/data/definitions/319.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
];

export const connectionSchema = z.object({
  connection_strings: z
    .array(z.string().min(1).max(2048))
    .min(1)
    .max(64)
    .describe(
      "Database connection strings / URIs to audit (postgres://, mysql://, mongodb+srv://, redis://, etc.).",
    ),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type ConnectionInput = z.infer<typeof connectionSchema>;

interface UriCheck {
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly test: (uri: string) => boolean;
}

const CHECKS: readonly UriCheck[] = [
  {
    rule: "connection-credentials-in-uri",
    severity: "high",
    title: "Database credentials embedded in the connection string",
    description:
      "The connection string contains an inline `user:password@` pair. Connection strings reach source control, environment dumps, process listings, and crash logs — an embedded password is exposed everywhere the string travels.",
    remediation:
      "Move the password to a secret manager or an environment variable read at startup; keep only a placeholder, or omit credentials entirely, from any stored connection string.",
    cwe: ["CWE-798"],
    test: (u) => /:\/\/[^/\s:@]+:[^/\s:@]+@/.test(u),
  },
  {
    rule: "connection-empty-password",
    severity: "high",
    title: "Database connection string has an empty password",
    description:
      "The connection string supplies a username with an empty password (`user:@host`). An account with no password is trivially reachable by anyone who can connect to the database port.",
    remediation:
      "Set a strong, unique password for the account and supply it from a secret manager. Reject accounts with empty passwords at the database level.",
    cwe: ["CWE-258"],
    test: (u) => /:\/\/[^/\s:@]+:@/.test(u),
  },
  {
    rule: "connection-default-credentials",
    severity: "high",
    title: "Database connection string uses default or well-known credentials",
    description:
      "The connection string pairs a built-in administrative username (postgres, root, sa, admin, elastic, ...) with a default or trivial password. Default credentials are the first thing an attacker tries.",
    remediation:
      "Create a dedicated least-privilege application account with a strong, unique password and rotate or disable the built-in administrative accounts.",
    cwe: ["CWE-798", "CWE-1392"],
    test: (u) =>
      /:\/\/(?:postgres|postgresql|root|sa|admin|mysql|mongo|elastic|sysadmin):(?:postgres|postgresql|root|sa|admin|password|passw0rd|changeme|secret|123456|test|mysql|mongo|elastic)@/i.test(
        u,
      ),
  },
  {
    rule: "connection-tls-disabled",
    severity: "high",
    title: "Connection string disables or weakens TLS",
    description:
      "The connection string disables transport encryption or selects a non-verifying mode (`sslmode=disable/allow/prefer/require`, `ssl=false`, `tls=false`). Database traffic — credentials and query data — then crosses the network in cleartext, or without authenticating the server (`require` encrypts but does not verify the certificate).",
    remediation:
      "Require verified TLS: `sslmode=verify-full` for PostgreSQL, `ssl={rejectUnauthorized:true}` for MySQL/Node, `tls=true` for MongoDB. Never use `disable`, `allow`, `prefer`, or bare `require` in production.",
    cwe: ["CWE-319", "CWE-295"],
    test: (u) =>
      /sslmode=(?:disable|allow|prefer|require)\b|[?&]ssl=(?:false|0)\b|[?&]tls=false\b/i.test(u),
  },
  {
    rule: "connection-plaintext-scheme",
    severity: "high",
    title: "Connection string uses a plaintext (non-TLS) scheme",
    description:
      "The connection string uses a scheme that is unencrypted by default (`redis://` instead of `rediss://`, `http://` instead of `https://` for Elasticsearch). The connection — including the auth handshake — is sent in cleartext.",
    remediation:
      "Use the TLS scheme: `rediss://` for Redis, `https://` for Elasticsearch, and confirm the server presents a valid certificate.",
    cwe: ["CWE-319"],
    test: (u) => /^(?:redis|http):\/\//i.test(u.trim()),
  },
  {
    rule: "connection-tls-not-specified",
    severity: "medium",
    title: "Connection string does not explicitly require TLS",
    description:
      "A PostgreSQL / MySQL / MariaDB / MongoDB connection string sets no `sslmode` / `ssl` / `tls` parameter. The driver's default may be an unencrypted connection, so TLS is not guaranteed.",
    remediation:
      "Add an explicit verified-TLS parameter (`sslmode=verify-full`, `ssl=true`, `tls=true`) rather than relying on the driver default.",
    cwe: ["CWE-319"],
    test: (u) =>
      /^(?:postgres(?:ql)?|mysql|mariadb|mongodb):\/\//i.test(u.trim()) &&
      !/sslmode=|[?&](?:ssl|tls)=/i.test(u),
  },
];

/** Mask the password in a connection string so evidence does not leak it. */
function maskUri(uri: string): string {
  return uri
    .replace(/(:\/\/[^/\s:@]+:)[^/\s:@]*(@)/, "$1***$2")
    .trim()
    .slice(0, 200);
}

/** Audit a set of database connection strings. */
export function auditConnection(input: ConnectionInput): readonly Finding[] {
  const findings: Finding[] = [];
  input.connection_strings.forEach((uri, index) => {
    for (const check of CHECKS) {
      if (!check.test(uri)) continue;
      findings.push(
        buildDatabaseFinding(
          {
            rule: check.rule,
            severity: check.severity,
            title: check.title,
            description: check.description,
            remediation: check.remediation,
            cwe: check.cwe,
            references: REFS,
            evidence: maskUri(uri),
            tags: ["connection-string"],
            line: index + 1,
          },
          input.filename,
        ),
      );
    }
  });
  return findings;
}
