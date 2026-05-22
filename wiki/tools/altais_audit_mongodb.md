# `altais_audit_mongodb`

Audits a MongoDB configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied MongoDB configuration object for access control, network exposure, the authentication mechanism, transport security, durability, the application role, and server-side JavaScript. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known MongoDB settings (authorization, `bind_ip`, auth mechanism, TLS, journaling, application role, server-side JavaScript). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Access control disabled (CWE-306); binding to all interfaces (CWE-1327).
- A legacy authentication mechanism — MONGODB-CR / SCRAM-SHA-1 (CWE-327); TLS disabled (CWE-319).
- Journaling disabled; an over-broad application role (CWE-250); server-side JavaScript enabled (CWE-94).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
