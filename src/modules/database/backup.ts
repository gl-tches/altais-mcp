// altais_audit_backup — database backup configuration audit.
//
// Reviews automated-backup configuration, encryption at rest, retention,
// point-in-time recovery, off-site copies, restore testing, backup
// access control, and inline credentials.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://cwe.mitre.org/data/definitions/312.html",
];

export const backupSchema = z.object({
  config: z.object({
    automated_backups_enabled: z
      .boolean()
      .optional()
      .describe("Whether automated, scheduled backups are configured."),
    backups_encrypted: z.boolean().optional().describe("Whether backups are encrypted at rest."),
    retention_days: z
      .number()
      .int()
      .min(0)
      .max(36500)
      .optional()
      .describe("Backup retention period in days, if known."),
    point_in_time_recovery_enabled: z
      .boolean()
      .optional()
      .describe("Whether point-in-time recovery is enabled."),
    offsite_copy_enabled: z
      .boolean()
      .optional()
      .describe("Whether backups are copied to a separate location / region / account."),
    restore_tested: z
      .boolean()
      .optional()
      .describe("Whether backup restores are periodically tested."),
    backup_access_restricted: z
      .boolean()
      .optional()
      .describe("Whether access to backup storage is restricted to least privilege."),
    credentials_inline: z
      .boolean()
      .optional()
      .describe("Whether the backup configuration contains hard-coded credentials."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type BackupInput = z.infer<typeof backupSchema>;
type BackupConfig = BackupInput["config"];

const CHECKS: readonly ConfigCheck<BackupConfig>[] = [
  {
    rule: "backup-not-automated",
    when: (c) => c.automated_backups_enabled === false,
    severity: "high",
    title: "Automated database backups are not configured",
    description:
      "Without scheduled automated backups, recovery depends on manual action that is easily forgotten. A hardware failure, bad migration, or ransomware event then means permanent data loss.",
    remediation:
      "Configure automated, scheduled backups (managed-service automated backups or a cron-driven dump) and monitor that each run succeeds.",
  },
  {
    rule: "backup-not-encrypted",
    when: (c) => c.backups_encrypted === false,
    severity: "high",
    title: "Database backups are not encrypted at rest",
    description:
      "A backup is a complete copy of the database. An unencrypted backup on object storage, tape, or a snapshot exposes every record if that storage is accessed or a copy is leaked.",
    remediation:
      "Encrypt backups at rest with a managed KMS key, and ensure backup copies in other regions/accounts are encrypted too.",
    cwe: ["CWE-312"],
  },
  {
    rule: "backup-short-retention",
    when: (c) => c.retention_days !== undefined && c.retention_days < 7,
    severity: "medium",
    title: "Database backup retention is very short",
    description:
      "A retention window under a week means a problem discovered late — silent corruption, a slow-burn ransomware event, or a bad deploy noticed after the weekend — can no longer be recovered from.",
    remediation:
      "Set a retention period that matches the recovery objectives and the realistic detection time for data issues (commonly 30 days or more for production).",
  },
  {
    rule: "backup-no-point-in-time-recovery",
    when: (c) => c.point_in_time_recovery_enabled === false,
    severity: "medium",
    title: "Point-in-time recovery is not enabled",
    description:
      "Periodic snapshots alone lose every write since the last snapshot. Without point-in-time recovery, the recovery point can be hours of data behind the incident.",
    remediation:
      "Enable point-in-time recovery (continuous backup / WAL or binlog archival) so the database can be restored to a moment just before an incident.",
  },
  {
    rule: "backup-no-offsite-copy",
    when: (c) => c.offsite_copy_enabled === false,
    severity: "medium",
    title: "Backups are not copied off-site",
    description:
      "Backups stored only alongside the primary database share its failure domain: a region outage, account compromise, or ransomware event that reaches the database can destroy the backups too.",
    remediation:
      "Copy backups to a separate region and, ideally, a separate account with restricted, write-once (object-lock) access.",
  },
  {
    rule: "backup-restore-not-tested",
    when: (c) => c.restore_tested === false,
    severity: "medium",
    title: "Backup restores are not tested",
    description:
      "An untested backup is an assumption, not a recovery plan. Corrupt archives, missing dependencies, and incomplete dumps are routinely discovered only during a real incident.",
    remediation:
      "Periodically restore backups into an isolated environment, verify integrity and row counts, and record the restore time against the recovery-time objective.",
  },
  {
    rule: "backup-access-not-restricted",
    when: (c) => c.backup_access_restricted === false,
    severity: "high",
    title: "Access to database backups is not restricted",
    description:
      "Backup storage that is broadly readable or deletable lets an attacker exfiltrate the whole database, or destroy the backups to defeat recovery, without touching the live system.",
    remediation:
      "Restrict backup storage to least privilege, separate backup-read from backup-delete permissions, and apply object-lock / immutability to defend against deletion.",
    cwe: ["CWE-732"],
  },
  {
    rule: "backup-credentials-inline",
    when: (c) => c.credentials_inline === true,
    severity: "high",
    title: "Backup configuration contains hard-coded credentials",
    description:
      "Credentials embedded in backup scripts or configuration (database passwords, storage keys) end up in source control and artifacts, where they are widely exposed.",
    remediation:
      "Source backup credentials from a secret manager or instance role at run time; keep no secret literal in the backup configuration.",
    cwe: ["CWE-798"],
  },
];

/** Audit a database backup configuration. */
export function auditBackup(input: BackupInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
