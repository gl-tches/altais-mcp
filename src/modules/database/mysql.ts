// altais_audit_mysql — MySQL / MariaDB configuration audit.
//
// Reviews authentication bypass settings, network binding, legacy
// password hashing, local-infile file access, transport security,
// anonymous and wildcard-host accounts, application-account privileges,
// and SQL strict mode.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html",
];

export const mysqlSchema = z.object({
  config: z.object({
    skip_grant_tables: z
      .boolean()
      .optional()
      .describe("Whether the server runs with --skip-grant-tables."),
    bind_address: z
      .string()
      .max(256)
      .optional()
      .describe("The bind-address value (e.g. `127.0.0.1`, `0.0.0.0`)."),
    secure_auth: z
      .boolean()
      .optional()
      .describe("Whether secure_auth is enabled (rejects pre-4.1 password hashes)."),
    old_passwords: z
      .boolean()
      .optional()
      .describe("Whether the legacy old_passwords hashing mode is enabled."),
    local_infile: z.boolean().optional().describe("Whether LOAD DATA LOCAL INFILE is enabled."),
    require_secure_transport: z
      .boolean()
      .optional()
      .describe("Whether the server requires TLS for all connections."),
    anonymous_accounts_present: z
      .boolean()
      .optional()
      .describe("Whether anonymous (empty-username) accounts exist."),
    app_user_has_excessive_privileges: z
      .boolean()
      .optional()
      .describe("Whether the application account holds GRANT ALL / SUPER / FILE privileges."),
    wildcard_host_accounts: z
      .boolean()
      .optional()
      .describe("Whether accounts exist with a `%` host (connectable from anywhere)."),
    strict_sql_mode: z
      .boolean()
      .optional()
      .describe("Whether STRICT_ALL_TABLES / STRICT_TRANS_TABLES is in sql_mode."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type MysqlInput = z.infer<typeof mysqlSchema>;
type MysqlConfig = MysqlInput["config"];

const CHECKS: readonly ConfigCheck<MysqlConfig>[] = [
  {
    rule: "mysql-skip-grant-tables",
    when: (c) => c.skip_grant_tables === true,
    severity: "critical",
    title: "MySQL is running with --skip-grant-tables",
    description:
      "`--skip-grant-tables` disables the privilege system entirely: anyone who can reach the port connects as any user with full rights. It is a maintenance-only mode and a complete authentication bypass in production.",
    remediation:
      "Remove `--skip-grant-tables` / `skip-grant-tables` from the configuration and restart. Use it only on an isolated host for password recovery, then revert immediately.",
    cwe: ["CWE-287"],
  },
  {
    rule: "mysql-bind-all-interfaces",
    when: (c) => c.bind_address === "0.0.0.0" || c.bind_address === "*",
    severity: "medium",
    title: "MySQL binds to all network interfaces",
    description:
      "`bind-address = 0.0.0.0` exposes the server on every interface. With a permissive firewall or host account, the database is reachable from untrusted networks.",
    remediation:
      "Bind to the specific private interface the application uses, and restrict access with host-based account grants and a firewall.",
    cwe: ["CWE-1327"],
  },
  {
    rule: "mysql-legacy-authentication",
    when: (c) => c.secure_auth === false || c.old_passwords === true,
    severity: "high",
    title: "MySQL uses legacy password hashing",
    description:
      "Disabling `secure_auth` or enabling `old_passwords` permits the pre-4.1 password hash, which is short and trivially crackable, and weakens the authentication handshake.",
    remediation:
      "Enable `secure_auth`, disable `old_passwords`, and migrate every account to `caching_sha2_password` (MySQL 8) or a current `mysql_native_password` hash.",
    cwe: ["CWE-327"],
  },
  {
    rule: "mysql-local-infile-enabled",
    when: (c) => c.local_infile === true,
    severity: "medium",
    title: "MySQL LOAD DATA LOCAL INFILE is enabled",
    description:
      "With `local_infile` enabled, a malicious or compromised server (or a SQL-injection foothold) can read files from the client host, and the feature widens the server's file-access surface.",
    remediation:
      "Disable `local_infile` unless a specific import workflow needs it; enable it only for that session and host.",
    cwe: ["CWE-22"],
  },
  {
    rule: "mysql-tls-not-required",
    when: (c) => c.require_secure_transport === false,
    severity: "high",
    title: "MySQL does not require TLS for connections",
    description:
      "Without `require_secure_transport = ON`, clients may connect unencrypted, sending credentials and query data in cleartext.",
    remediation:
      "Set `require_secure_transport = ON`, provision server certificates, and configure clients with `REQUIRE SSL` / verified TLS.",
    cwe: ["CWE-319"],
  },
  {
    rule: "mysql-anonymous-accounts",
    when: (c) => c.anonymous_accounts_present === true,
    severity: "high",
    title: "MySQL anonymous accounts exist",
    description:
      "Anonymous (empty-username) accounts let unidentified clients authenticate, often with access to the `test` database, and undermine accountability.",
    remediation:
      "Run `mysql_secure_installation` or `DROP USER ''@'localhost'` (and any other anonymous entries) to remove every anonymous account.",
    cwe: ["CWE-1392"],
  },
  {
    rule: "mysql-app-excessive-privileges",
    when: (c) => c.app_user_has_excessive_privileges === true,
    severity: "high",
    title: "MySQL application account has excessive privileges",
    description:
      "An application account holding `ALL PRIVILEGES`, `SUPER`, or `FILE` can read server files, change configuration, or administer the server — turning any injection flaw into full compromise.",
    remediation:
      "Grant the application account only the DML it needs on its own schema (`SELECT, INSERT, UPDATE, DELETE`). Never grant `SUPER`, `FILE`, or `GRANT OPTION` to it.",
    cwe: ["CWE-250"],
  },
  {
    rule: "mysql-wildcard-host-accounts",
    when: (c) => c.wildcard_host_accounts === true,
    severity: "medium",
    title: "MySQL accounts permit connections from any host",
    description:
      "Accounts defined with a `%` host can authenticate from anywhere, removing network-origin as a defense layer.",
    remediation:
      "Scope accounts to the specific application host or subnet (`'app'@'10.0.1.%'`) instead of `'app'@'%'`.",
    cwe: ["CWE-284"],
  },
  {
    rule: "mysql-no-strict-sql-mode",
    when: (c) => c.strict_sql_mode === false,
    severity: "low",
    title: "MySQL strict SQL mode is disabled",
    description:
      "Without a STRICT sql_mode, MySQL silently truncates or coerces out-of-range and malformed values instead of rejecting them, which can corrupt data and mask injection-driven anomalies.",
    remediation:
      "Add `STRICT_ALL_TABLES` (or `STRICT_TRANS_TABLES`) to `sql_mode` so invalid data is rejected with an error.",
  },
];

/** Audit a MySQL / MariaDB configuration. */
export function auditMysql(input: MysqlInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
