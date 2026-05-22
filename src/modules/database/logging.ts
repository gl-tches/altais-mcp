// altais_audit_db_logging — database audit-logging configuration audit.
//
// Reviews audit / connection / failed-login / slow-query logging, the
// security of the log destination, sensitive data in logs, and log
// retention.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
];

export const dbLoggingSchema = z.object({
  config: z.object({
    audit_logging_enabled: z
      .boolean()
      .optional()
      .describe("Whether database audit logging (data access / DDL) is enabled."),
    connection_logging_enabled: z
      .boolean()
      .optional()
      .describe("Whether connection and disconnection events are logged."),
    failed_login_logging_enabled: z
      .boolean()
      .optional()
      .describe("Whether failed authentication attempts are logged."),
    slow_query_log_enabled: z
      .boolean()
      .optional()
      .describe("Whether the slow-query log is enabled."),
    log_destination_secured: z
      .boolean()
      .optional()
      .describe("Whether the log destination has restricted, least-privilege access."),
    logs_contain_sensitive_data: z
      .boolean()
      .optional()
      .describe("Whether logged statements include credentials, tokens, or personal data."),
    log_retention_adequate: z
      .boolean()
      .optional()
      .describe("Whether log retention is long enough for incident investigation."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type DbLoggingInput = z.infer<typeof dbLoggingSchema>;
type DbLoggingConfig = DbLoggingInput["config"];

const CHECKS: readonly ConfigCheck<DbLoggingConfig>[] = [
  {
    rule: "db-logging-audit-disabled",
    when: (c) => c.audit_logging_enabled === false,
    severity: "medium",
    title: "Database audit logging is disabled",
    description:
      "Without audit logging there is no record of who accessed or changed which data. An intrusion or insider misuse leaves no trail to detect or investigate it.",
    remediation:
      "Enable the database's audit logging (pgaudit, the MySQL audit plugin, MongoDB auditing, SQL Server Audit) for data-access and DDL events, scoped to sensitive objects.",
    cwe: ["CWE-778"],
  },
  {
    rule: "db-logging-connections-disabled",
    when: (c) => c.connection_logging_enabled === false,
    severity: "low",
    title: "Database connection logging is disabled",
    description:
      "Without connection / disconnection logging there is no record of who connected, from where, and when — context that is essential when scoping an incident.",
    remediation:
      "Enable connection and disconnection logging and forward it to the central log destination.",
    cwe: ["CWE-778"],
  },
  {
    rule: "db-logging-failed-logins-disabled",
    when: (c) => c.failed_login_logging_enabled === false,
    severity: "medium",
    title: "Database failed-login logging is disabled",
    description:
      "Failed authentication attempts are the primary signal of credential-stuffing and brute-force attacks. Not logging them means those attacks proceed undetected.",
    remediation:
      "Log failed authentication attempts and alert on bursts of failures per account or source address.",
    cwe: ["CWE-778"],
  },
  {
    rule: "db-logging-slow-query-disabled",
    when: (c) => c.slow_query_log_enabled === false,
    severity: "low",
    title: "Database slow-query log is disabled",
    description:
      "The slow-query log surfaces inefficient and abusive queries — including the expensive queries an attacker uses to probe for injection or to cause denial of service.",
    remediation:
      "Enable the slow-query log with a sensible threshold and review it for both performance and abuse patterns.",
  },
  {
    rule: "db-logging-destination-unsecured",
    when: (c) => c.log_destination_secured === false,
    severity: "high",
    title: "Database log destination is not access-restricted",
    description:
      "Database logs contain query text, identifiers, and connection metadata. A log destination readable by untrusted users leaks that data; one that is writable lets an attacker tamper with or erase the audit trail.",
    remediation:
      "Ship logs to a central destination with least-privilege, append-only access, and restrict who can read or modify them.",
    cwe: ["CWE-532"],
  },
  {
    rule: "db-logging-sensitive-data",
    when: (c) => c.logs_contain_sensitive_data === true,
    severity: "high",
    title: "Database logs contain sensitive data",
    description:
      "Statement logging that captures credentials, tokens, or personal data copies that sensitive data into the logging system, widening where it is exposed and who can see it.",
    remediation:
      "Redact or parameterize logged statements so values are not captured, keep secrets out of SQL literals, and apply log-side masking for any unavoidable sensitive fields.",
    cwe: ["CWE-532"],
  },
  {
    rule: "db-logging-short-retention",
    when: (c) => c.log_retention_adequate === false,
    severity: "low",
    title: "Database log retention is inadequate",
    description:
      "Intrusions are frequently detected weeks or months after the fact. Logs that are rotated away too quickly are gone before an investigation can use them.",
    remediation:
      "Retain database audit and security logs long enough to cover realistic detection times (commonly 90 days hot, longer in cold storage) and align with any compliance obligations.",
    cwe: ["CWE-778"],
  },
];

/** Audit a database's audit-logging configuration. */
export function auditDbLogging(input: DbLoggingInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
