# `altais_audit_connection`

Audits database connection strings for credential, TLS, and scheme weaknesses.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Inspects one or more database connection strings / URIs (PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, and cloud-managed databases) for security weaknesses. Passwords in evidence are masked so the secret is not echoed back.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `connection_strings` | `string[]` (1–64) | Yes | Connection strings / URIs to audit. |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Credentials embedded in the URI (CWE-798) and empty passwords (CWE-258).
- Default / well-known credentials (CWE-798, CWE-1392).
- TLS disabled or weakened — `sslmode=disable/allow/prefer/require`, `ssl=false` (CWE-319, CWE-295).
- Plaintext schemes (`redis://`, `http://`) and connection strings that do not explicitly require TLS (CWE-319).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
