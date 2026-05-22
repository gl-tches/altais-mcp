# `altais_audit_redis`

Audits a Redis / Memcached configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied Redis / Memcached configuration object for authentication, protected mode, network exposure, ACLs, dangerous-command exposure, transport security, and password strength. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known Redis settings (`requirepass`, `protected-mode`, `bind`, ACLs, dangerous-command restrictions, TLS, password strength). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- No authentication (CWE-306); `protected-mode` disabled (CWE-284); binding to all interfaces (CWE-1327).
- A single shared password instead of ACLs (CWE-272); unrestricted dangerous commands (CWE-250).
- TLS disabled (CWE-319); a weak password (CWE-521).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
