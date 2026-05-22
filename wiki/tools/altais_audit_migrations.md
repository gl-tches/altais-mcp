# `altais_audit_migrations`

Detects destructive or unsafe database migrations.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans migration source — raw SQL or a migration-tool script — for operations that destroy data or break a running deployment. The detection patterns ship in `data/database-patterns.json`.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` | Yes | Migration source to scan. |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Table, column, constraint, database, and schema drops; `TRUNCATE`.
- `DELETE` with no `WHERE` clause.
- `NOT NULL` column additions, column renames, and column type changes that can lose data or break a running deployment.

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
