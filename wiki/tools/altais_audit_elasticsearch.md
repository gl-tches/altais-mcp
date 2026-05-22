# `altais_audit_elasticsearch`

Audits an Elasticsearch configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied Elasticsearch configuration object for the security plugin, anonymous access, transport and HTTP TLS, dynamic scripting, network binding, audit logging, and the built-in superuser password. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known Elasticsearch settings (`xpack.security`, anonymous access, transport / HTTP TLS, dynamic scripting, `network.host`, audit logging, default `elastic` password). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- The security feature disabled (CWE-306); anonymous access enabled (CWE-306).
- Transport- and HTTP-layer TLS disabled (CWE-319); dynamic scripting enabled (CWE-94).
- Binding to all interfaces (CWE-1327); audit logging disabled (CWE-778); an unchanged built-in `elastic` password (CWE-1392).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
