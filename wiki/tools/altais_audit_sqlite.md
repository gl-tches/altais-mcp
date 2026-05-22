# `altais_audit_sqlite`

Audits a SQLite configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied SQLite configuration object. Because SQLite has no network authentication layer, file permissions and runtime features are the access control. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known SQLite settings (database- and journal-file permissions, encryption at rest, extension loading, ATTACH exposure, temp-store directory). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- A world-readable database or WAL / journal file (CWE-732, CWE-312).
- No encryption at rest for sensitive data (CWE-312); runtime extension loading enabled (CWE-94).
- `ATTACH DATABASE` from a caller-influenced path (CWE-73); an insecure temporary-store directory (CWE-377).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
