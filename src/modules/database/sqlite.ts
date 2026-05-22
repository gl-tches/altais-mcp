// altais_audit_sqlite — SQLite configuration audit.
//
// Reviews database- and journal-file permissions, encryption at rest,
// runtime extension loading, ATTACH exposure, and temp-store security.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://www.sqlite.org/security.html",
];

export const sqliteSchema = z.object({
  config: z.object({
    database_file_world_readable: z
      .boolean()
      .optional()
      .describe("Whether the database file is readable by users other than the application."),
    encrypted_at_rest: z
      .boolean()
      .optional()
      .describe("Whether the database file is encrypted at rest (e.g. SQLCipher)."),
    extension_loading_enabled: z
      .boolean()
      .optional()
      .describe("Whether runtime extension loading (load_extension) is enabled."),
    attach_from_untrusted_input: z
      .boolean()
      .optional()
      .describe("Whether ATTACH DATABASE can receive a caller-influenced file path."),
    journal_file_world_readable: z
      .boolean()
      .optional()
      .describe("Whether the WAL / rollback journal file is readable by other users."),
    temp_store_directory_world_writable: z
      .boolean()
      .optional()
      .describe("Whether the temporary-store directory is world-writable."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type SqliteInput = z.infer<typeof sqliteSchema>;
type SqliteConfig = SqliteInput["config"];

const CHECKS: readonly ConfigCheck<SqliteConfig>[] = [
  {
    rule: "sqlite-db-file-world-readable",
    when: (c) => c.database_file_world_readable === true,
    severity: "high",
    title: "SQLite database file is readable by other users",
    description:
      "SQLite has no network auth layer — file permissions are the access control. A world-readable database file lets any local user (or another compromised process) read every row directly.",
    remediation:
      "Restrict the database file to the application's user/group (`chmod 600`), and place it outside any web-served or shared directory.",
    cwe: ["CWE-732", "CWE-312"],
  },
  {
    rule: "sqlite-not-encrypted-at-rest",
    when: (c) => c.encrypted_at_rest === false,
    severity: "medium",
    title: "SQLite database holding sensitive data is not encrypted at rest",
    description:
      "A plain SQLite file stores all data in cleartext on disk. If the host, a backup, or a stolen device is accessed, the entire database is readable.",
    remediation:
      "Use an encrypted SQLite build (SQLCipher) or full-disk / filesystem encryption for databases that hold personal data, secrets, or other sensitive records.",
    cwe: ["CWE-312"],
  },
  {
    rule: "sqlite-extension-loading-enabled",
    when: (c) => c.extension_loading_enabled === true,
    severity: "high",
    title: "SQLite runtime extension loading is enabled",
    description:
      "`load_extension()` loads a native shared library into the process. If a caller can influence the path, it is arbitrary code execution; even otherwise it widens the attack surface considerably.",
    remediation:
      "Leave extension loading disabled (the default). If an extension is required, load it once at startup from a fixed, trusted path and keep `enable_load_extension` off for query-time use.",
    cwe: ["CWE-94"],
  },
  {
    rule: "sqlite-attach-untrusted-path",
    when: (c) => c.attach_from_untrusted_input === true,
    severity: "high",
    title: "SQLite ATTACH DATABASE accepts a caller-influenced path",
    description:
      "`ATTACH DATABASE` opens an arbitrary file as a database. A caller-controlled path lets an attacker attach a file outside the intended scope or read/write unexpected locations.",
    remediation:
      "Never build an ATTACH path from request input. Attach only fixed, server-controlled database files, and resolve/validate any path against an allow-list first.",
    cwe: ["CWE-73"],
  },
  {
    rule: "sqlite-journal-file-world-readable",
    when: (c) => c.journal_file_world_readable === true,
    severity: "medium",
    title: "SQLite WAL / journal file is readable by other users",
    description:
      "The WAL and rollback-journal files contain copies of recently written rows. World-readable journal files leak that data even when the main database file is locked down.",
    remediation:
      "Ensure the directory containing the database restricts access to the application user, so the `-wal`, `-shm`, and `-journal` sidecar files inherit safe permissions.",
    cwe: ["CWE-312"],
  },
  {
    rule: "sqlite-temp-store-world-writable",
    when: (c) => c.temp_store_directory_world_writable === true,
    severity: "low",
    title: "SQLite temporary-store directory is world-writable",
    description:
      "When SQLite spills temporary indexes / results to disk, a world-writable temp directory exposes that data to other users and risks a symlink or file-swap attack on the temp files.",
    remediation:
      "Point the temp store at a directory owned by and restricted to the application user, or use an in-memory temp store (`PRAGMA temp_store = MEMORY`).",
    cwe: ["CWE-377"],
  },
];

/** Audit a SQLite configuration. */
export function auditSqlite(input: SqliteInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
