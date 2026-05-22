# `altais_audit_mysql`

Audits a MySQL / MariaDB configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied MySQL / MariaDB configuration object for authentication-bypass settings, network exposure, legacy hashing, file access, transport security, account hygiene, and SQL mode. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known MySQL settings (`skip-grant-tables`, `bind-address`, `secure_auth` / `old_passwords`, `local_infile`, `require_secure_transport`, anonymous and wildcard-host accounts, application-account privileges, `sql_mode`). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- `--skip-grant-tables` authentication bypass (CWE-287); binding to all interfaces (CWE-1327).
- Legacy password hashing (CWE-327); `LOAD DATA LOCAL INFILE` enabled (CWE-22).
- TLS not required (CWE-319); anonymous accounts (CWE-1392).
- An over-privileged application account (CWE-250); wildcard-host accounts (CWE-284); non-strict `sql_mode`.

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
