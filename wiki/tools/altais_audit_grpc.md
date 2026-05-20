# `altais_audit_grpc`

Audits a gRPC service or client for security weaknesses.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a gRPC service or client from source code, a structured config, or both. It flags an insecure (plaintext) channel with no TLS, no authentication interceptor, no deadline / timeout propagation, server reflection enabled in production, and unbounded message size. An agent calls it when reviewing a gRPC service's transport and access controls.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No* | gRPC service/client source code, scanned with pattern matching. |
| `config` | `object` | No* | Structured description of the gRPC posture (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

*At least one of `source` or `config` must be provided.

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `tls_enabled` | `boolean` | Whether the channel uses TLS credentials. |
| `insecure_channel` | `boolean` | Whether an explicitly insecure channel is used. |
| `auth_interceptor` | `boolean` | Whether a server authentication interceptor is installed. |
| `deadline_propagation` | `boolean` | Whether calls set and propagate a deadline. |
| `reflection_enabled` | `boolean` | Whether gRPC server reflection is registered. |
| `max_message_size` | `boolean` | Whether a bounded maximum message size is enforced. |
| `production` | `boolean` | Whether this configuration is a production deployment. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "insecure_channel": true, "auth_interceptor": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "grpc-insecure-channel", "severity": "high", "title": "Insecure plaintext gRPC channel" },
    { "rule": "grpc-no-auth-interceptor", "severity": "medium", "title": "No authentication interceptor" }
  ]
}
```

## Detections

- `grpc-insecure-channel` — insecure (plaintext) channel with no TLS (CWE-319)
- `grpc-no-auth-interceptor` — no server authentication interceptor (CWE-306)
- `grpc-no-deadline-propagation` — no deadline / timeout propagation (CWE-400)
- `grpc-reflection-enabled` — server reflection enabled in production (CWE-200)
- `grpc-unbounded-message-size` — unbounded message size (CWE-400)

## Related tools

- [`altais_audit_graphql`](altais_audit_graphql.md) — auditing a GraphQL API
- [`altais_audit_tls_config`](altais_audit_tls_config.md) — deeper TLS / mTLS configuration review

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
