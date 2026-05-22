# `altais_audit_backup`

Audits a database backup configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied backup configuration object for automated-backup coverage, encryption, retention, point-in-time recovery, off-site copies, restore testing, access control, and inline credentials. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known backup settings (automated backups, encryption, `retention_days`, PITR, off-site copy, restore testing, access restriction, inline credentials). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- No automated backups; backups not encrypted at rest (CWE-312).
- Short retention; point-in-time recovery disabled; no off-site copy.
- Restores never tested; backup storage not access-restricted (CWE-732); hard-coded credentials (CWE-798).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
