# `altais_audit_queries`

Detects unsafe query construction across the supported ORMs and raw drivers.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code for raw, non-parameterized SQL construction. The detection patterns ship in `data/database-patterns.json` and cover string concatenation, template-literal / f-string interpolation, and `format!`-built SQL.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` | Yes | Source code to scan. |
| `language` | `enum` | No | `javascript`, `typescript`, `python`, `rust`, or `go`. When omitted, every pattern runs. |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

Unsafe query building (CWE-89) across Prisma (`$queryRawUnsafe`), Drizzle, TypeORM, Sequelize, Knex, pg, mysql2, better-sqlite3 (TS/JS); SQLAlchemy, Django ORM, psycopg (Python); diesel, sqlx, sea-orm (Rust); and GORM, `database/sql`, pgx (Go).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
