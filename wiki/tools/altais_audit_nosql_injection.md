# `altais_audit_nosql_injection`

Detects NoSQL injection sinks (MongoDB, Elasticsearch, Redis).

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code for NoSQL-specific injection sinks. The detection patterns ship in `data/database-patterns.json`.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` | Yes | Source code to scan. |
| `language` | `enum` | No | `javascript`, `typescript`, or `python`. When omitted, every pattern runs. |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

NoSQL injection (CWE-943): MongoDB operator injection — request data reaching `find` / `update` / `aggregate`, the `$where` operator, `mapReduce`; Elasticsearch `query_string` injection; and Redis Lua-script injection.

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
