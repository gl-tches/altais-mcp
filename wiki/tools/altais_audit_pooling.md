# `altais_audit_pooling`

Audits a database connection-pool configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied connection-pool configuration object for size bounds, timeouts, leak detection, TLS enforcement, and inline credentials. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known pool settings (size limit and maximum, idle / acquire / max-lifetime timeouts, leak detection, TLS enforcement, inline credentials). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- An unbounded or excessively large pool (CWE-770).
- Missing idle (CWE-770), acquire (CWE-400), and max-lifetime timeouts; disabled leak detection.
- TLS not enforced in the pool configuration (CWE-319); hard-coded credentials (CWE-798).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
