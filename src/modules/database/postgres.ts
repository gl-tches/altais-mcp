// altais_audit_postgres — PostgreSQL / CockroachDB configuration audit.
//
// Reviews role and privilege posture, public-schema exposure, row-level
// security, pg_hba.conf authentication, TLS, network binding, extension
// trust, and connection logging.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
];

export const postgresSchema = z.object({
  config: z.object({
    app_connects_as_superuser: z
      .boolean()
      .optional()
      .describe("Whether the application connects with a superuser role."),
    public_schema_create_revoked: z
      .boolean()
      .optional()
      .describe("Whether CREATE on the public schema has been revoked from PUBLIC."),
    row_level_security_enabled: z
      .boolean()
      .optional()
      .describe("Whether row-level security is enabled on multi-tenant / sensitive tables."),
    pg_hba_trust_auth: z
      .boolean()
      .optional()
      .describe("Whether any pg_hba.conf entry uses the `trust` authentication method."),
    password_encryption: z
      .enum(["scram-sha-256", "md5", "password"])
      .optional()
      .describe("The configured password_encryption / authentication algorithm."),
    ssl_enabled: z.boolean().optional().describe("Whether TLS (ssl = on) is enabled."),
    listen_addresses: z
      .string()
      .max(256)
      .optional()
      .describe("The listen_addresses value (e.g. `localhost`, `*`)."),
    untrusted_extensions: z
      .array(z.string().min(1).max(64))
      .max(64)
      .optional()
      .describe(
        "Installed extensions that grant code execution or network reach (dblink, postgres_fdw, plpythonu, ...).",
      ),
    log_connections: z.boolean().optional().describe("Whether connection attempts are logged."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type PostgresInput = z.infer<typeof postgresSchema>;
type PostgresConfig = PostgresInput["config"];

const RISKY_EXTENSIONS =
  /^(dblink|postgres_fdw|file_fdw|plpythonu|plpython3u|plperlu|pltclu|adminpack)$/i;

const CHECKS: readonly ConfigCheck<PostgresConfig>[] = [
  {
    rule: "pg-app-superuser",
    when: (c) => c.app_connects_as_superuser === true,
    severity: "high",
    title: "Application connects to PostgreSQL as a superuser",
    description:
      "A superuser bypasses every privilege check and row-level security policy. A SQL-injection flaw or compromised credential then has unrestricted control of the cluster.",
    remediation:
      "Create a dedicated application role with only the privileges it needs (GRANT on specific schemas/tables) and connect as that role. Reserve superuser for migrations and administration.",
    cwe: ["CWE-250"],
  },
  {
    rule: "pg-public-schema-create",
    when: (c) => c.public_schema_create_revoked === false,
    severity: "medium",
    title: "PUBLIC can CREATE objects in the public schema",
    description:
      "By default every role may create objects in the public schema. Any low-privilege account — or a SQL-injection foothold — can plant functions or tables that other sessions trust.",
    remediation:
      "`REVOKE CREATE ON SCHEMA public FROM PUBLIC;` and grant CREATE only to the roles that genuinely need it. On PostgreSQL 15+ this is the default.",
    cwe: ["CWE-732"],
  },
  {
    rule: "pg-rls-disabled",
    when: (c) => c.row_level_security_enabled === false,
    severity: "high",
    title: "Row-level security is not enabled on sensitive tables",
    description:
      "Without row-level security, application-layer tenant scoping is the only thing separating tenants' rows. A missing WHERE clause or an injection flaw exposes every tenant's data.",
    remediation:
      "Enable RLS (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`) on multi-tenant and sensitive tables and define policies that scope rows to the current tenant / user.",
    cwe: ["CWE-285"],
  },
  {
    rule: "pg-hba-trust-auth",
    when: (c) => c.pg_hba_trust_auth === true,
    severity: "critical",
    title: "pg_hba.conf uses the `trust` authentication method",
    description:
      "A `trust` entry lets anyone who can reach the matching host/database connect as any role with no password at all — a complete authentication bypass.",
    remediation:
      "Replace every `trust` entry with `scram-sha-256` (or `cert` for service-to-service). Reserve `trust` for nothing; even local sockets should require authentication.",
    cwe: ["CWE-287"],
  },
  {
    rule: "pg-weak-password-encryption",
    when: (c) => c.password_encryption !== undefined && c.password_encryption !== "scram-sha-256",
    severity: "medium",
    title: "PostgreSQL uses weak password authentication",
    description:
      "`md5` and plain `password` authentication are weak: md5 password hashes are crackable and replayable, and `password` sends the secret in cleartext on the wire.",
    remediation:
      "Set `password_encryption = scram-sha-256`, then have every role reset its password so the SCRAM verifier is stored. Use `scram-sha-256` in pg_hba.conf.",
    cwe: ["CWE-327"],
  },
  {
    rule: "pg-ssl-disabled",
    when: (c) => c.ssl_enabled === false,
    severity: "high",
    title: "PostgreSQL TLS is disabled",
    description:
      "With `ssl = off`, client connections are unencrypted: credentials, query text, and result data all cross the network in cleartext.",
    remediation:
      "Set `ssl = on`, provide a server certificate, and require TLS for non-local connections in pg_hba.conf (`hostssl`). Clients should use `sslmode=verify-full`.",
    cwe: ["CWE-319"],
  },
  {
    rule: "pg-listen-all-interfaces",
    when: (c) => c.listen_addresses === "*" || c.listen_addresses === "0.0.0.0",
    severity: "medium",
    title: "PostgreSQL listens on all network interfaces",
    description:
      "`listen_addresses = '*'` binds the server to every interface. Combined with a permissive pg_hba.conf or firewall gap, the database becomes reachable from untrusted networks.",
    remediation:
      "Bind to the specific private address the application uses (`listen_addresses = 'localhost'` or an internal IP) and restrict access with pg_hba.conf and a firewall.",
    cwe: ["CWE-1327"],
  },
  {
    rule: "pg-untrusted-extension",
    when: (c) => c.untrusted_extensions?.some((e) => RISKY_EXTENSIONS.test(e.trim())) === true,
    severity: "medium",
    title: "High-risk PostgreSQL extension installed",
    description:
      "Extensions such as `dblink`, `postgres_fdw`, `file_fdw`, and the untrusted procedural languages (`plpythonu`, `plperlu`) grant code execution, filesystem reads, or outbound network access from inside the database.",
    remediation:
      "Remove extensions the application does not require. Where one is needed, restrict EXECUTE / USAGE to specific roles and keep it out of the application role's reach.",
    cwe: ["CWE-829"],
  },
  {
    rule: "pg-no-log-connections",
    when: (c) => c.log_connections === false,
    severity: "low",
    title: "PostgreSQL connection logging is disabled",
    description:
      "With `log_connections = off` there is no record of who connected and when, leaving no audit trail for incident investigation.",
    remediation:
      "Set `log_connections = on` (and `log_disconnections = on`) and ship the logs to a central, access-controlled destination.",
    cwe: ["CWE-778"],
  },
];

/** Audit a PostgreSQL / CockroachDB configuration. */
export function auditPostgres(input: PostgresInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
