// altais_audit_mssql — Microsoft SQL Server configuration audit.
//
// Reviews the sa account, xp_cmdshell, CLR and OLE Automation, linked
// servers, transport encryption, the application login's privileges, and
// contained databases.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://learn.microsoft.com/en-us/sql/relational-databases/security/securing-sql-server",
];

export const mssqlSchema = z.object({
  config: z.object({
    sa_account_enabled: z
      .boolean()
      .optional()
      .describe("Whether the built-in `sa` account is enabled."),
    xp_cmdshell_enabled: z
      .boolean()
      .optional()
      .describe("Whether the xp_cmdshell extended procedure is enabled."),
    clr_integration_enabled: z
      .boolean()
      .optional()
      .describe("Whether CLR integration (clr enabled) is on."),
    ole_automation_enabled: z
      .boolean()
      .optional()
      .describe("Whether OLE Automation Procedures (sp_OACreate) are enabled."),
    linked_servers_with_saved_credentials: z
      .boolean()
      .optional()
      .describe("Whether linked servers store fixed remote credentials."),
    force_encryption: z
      .boolean()
      .optional()
      .describe("Whether the server forces TLS for all connections."),
    app_login_is_sysadmin: z
      .boolean()
      .optional()
      .describe("Whether the application login is a member of the sysadmin role."),
    contained_databases_enabled: z
      .boolean()
      .optional()
      .describe("Whether contained databases (authentication inside the database) are enabled."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type MssqlInput = z.infer<typeof mssqlSchema>;
type MssqlConfig = MssqlInput["config"];

const CHECKS: readonly ConfigCheck<MssqlConfig>[] = [
  {
    rule: "mssql-sa-account-enabled",
    when: (c) => c.sa_account_enabled === true,
    severity: "high",
    title: "SQL Server sa account is enabled",
    description:
      "`sa` is a well-known, sysadmin-level login and the first target of brute-force and credential-stuffing attacks against SQL Server.",
    remediation:
      "Disable the `sa` login (`ALTER LOGIN sa DISABLE`), or at minimum rename it and set a long random password. Administer the server with individual Windows-authenticated accounts.",
    cwe: ["CWE-1392"],
  },
  {
    rule: "mssql-xp-cmdshell-enabled",
    when: (c) => c.xp_cmdshell_enabled === true,
    severity: "critical",
    title: "SQL Server xp_cmdshell is enabled",
    description:
      "`xp_cmdshell` runs arbitrary operating-system commands from inside SQL Server. With it enabled, any sysadmin-level access — or a SQL-injection flaw reaching it — is full OS command execution.",
    remediation:
      "Disable xp_cmdshell (`sp_configure 'xp_cmdshell', 0`). If a workflow truly needs OS interaction, move it to a dedicated, sandboxed job with a minimal proxy account.",
    cwe: ["CWE-78"],
  },
  {
    rule: "mssql-clr-integration-enabled",
    when: (c) => c.clr_integration_enabled === true,
    severity: "medium",
    title: "SQL Server CLR integration is enabled",
    description:
      "CLR integration lets .NET assemblies run inside the server. An UNSAFE assembly can execute arbitrary code and is a recurring SQL Server persistence and privilege-escalation vector.",
    remediation:
      "Disable `clr enabled` unless required. If needed, allow only SAFE assemblies, enable `clr strict security`, and sign assemblies — never use `TRUSTWORTHY ON`.",
  },
  {
    rule: "mssql-ole-automation-enabled",
    when: (c) => c.ole_automation_enabled === true,
    severity: "medium",
    title: "SQL Server OLE Automation Procedures are enabled",
    description:
      "`sp_OACreate` and the OLE Automation procedures can instantiate COM objects, giving a path to filesystem and command execution from T-SQL.",
    remediation:
      "Disable OLE Automation Procedures (`sp_configure 'Ole Automation Procedures', 0`).",
    cwe: ["CWE-78"],
  },
  {
    rule: "mssql-linked-server-saved-credentials",
    when: (c) => c.linked_servers_with_saved_credentials === true,
    severity: "medium",
    title: "SQL Server linked servers store fixed credentials",
    description:
      "A linked server with a saved remote login lets anyone who can query the local server pivot to the remote one with those stored credentials.",
    remediation:
      "Prefer pass-through (current security context) authentication for linked servers, scope the remote login to least privilege, and remove unused linked servers.",
    cwe: ["CWE-522"],
  },
  {
    rule: "mssql-force-encryption-off",
    when: (c) => c.force_encryption === false,
    severity: "high",
    title: "SQL Server does not force connection encryption",
    description:
      "Without Force Encryption, clients may negotiate an unencrypted connection, exposing the login and all query traffic in cleartext.",
    remediation:
      "Enable Force Encryption with a trusted server certificate, and configure clients to use `Encrypt=true` with certificate validation.",
    cwe: ["CWE-319"],
  },
  {
    rule: "mssql-app-login-sysadmin",
    when: (c) => c.app_login_is_sysadmin === true,
    severity: "high",
    title: "SQL Server application login is a sysadmin",
    description:
      "A sysadmin-role application login bypasses every permission check and can enable xp_cmdshell, read any database, and reconfigure the server — turning any injection flaw into full compromise.",
    remediation:
      "Give the application a dedicated login mapped to a database user with only the required object permissions. Never place the application login in the sysadmin role.",
    cwe: ["CWE-250"],
  },
  {
    rule: "mssql-contained-databases-enabled",
    when: (c) => c.contained_databases_enabled === true,
    severity: "medium",
    title: "SQL Server contained databases are enabled",
    description:
      "Contained-database users authenticate inside the database without a server login. A user with ALTER permission on a contained database can create users that bypass server-level controls, and a detached/attached database carries its accounts with it.",
    remediation:
      "Enable contained databases only where required, restrict who can create contained users, and review contained-database authentication as part of the server's auth boundary.",
    cwe: ["CWE-284"],
  },
];

/** Audit a Microsoft SQL Server configuration. */
export function auditMssql(input: MssqlInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
