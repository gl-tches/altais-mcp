# `altais_audit_db_logging`

Audits a database's audit-logging configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied database logging configuration object for audit, connection, failed-login, and slow-query logging, the security of the log destination, sensitive data in logs, and log retention. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known logging settings (audit / connection / failed-login / slow-query logging, log-destination security, sensitive data in logs, retention). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Audit, connection, and failed-login logging disabled (CWE-778); slow-query log disabled.
- An unsecured log destination (CWE-532); sensitive data captured in logs (CWE-532).
- Inadequate log retention (CWE-778).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
