# `altais_audit_graphql`

Audits a GraphQL API for security weaknesses.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a GraphQL API from source code, a structured config, or both. It flags introspection enabled in production, no query-depth limit, no complexity / cost limit, query batching enabled, field suggestions enabled (schema leak), and no rate limiting. An agent calls it when reviewing a GraphQL endpoint's exposure to abuse and information disclosure.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No* | GraphQL server source code, scanned with pattern matching. |
| `config` | `object` | No* | Structured description of the GraphQL posture (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

*At least one of `source` or `config` must be provided.

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `introspection_enabled` | `boolean` | Whether schema introspection is enabled. |
| `query_depth_limit` | `boolean` | Whether a maximum query depth is enforced. |
| `query_complexity_limit` | `boolean` | Whether a query complexity / cost limit is enforced. |
| `batching_enabled` | `boolean` | Whether array-form query batching is enabled. |
| `field_suggestions` | `boolean` | Whether 'did you mean' field suggestions are returned. |
| `rate_limiting` | `boolean` | Whether the GraphQL endpoint is rate limited. |
| `production` | `boolean` | Whether this configuration is a production deployment. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "introspection_enabled": true, "production": true, "query_depth_limit": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "graphql-introspection-enabled", "severity": "medium", "title": "Introspection enabled in production" },
    { "rule": "graphql-no-depth-limit", "severity": "medium", "title": "No query-depth limit" }
  ]
}
```

## Detections

- `graphql-introspection-enabled` — schema introspection enabled in production (CWE-200)
- `graphql-debug-playground` — debug playground / IDE exposed (CWE-200)
- `graphql-no-depth-limit` — no query-depth limit (CWE-770)
- `graphql-no-complexity-limit` — no query complexity / cost limit (CWE-770, CWE-799)
- `graphql-batching-enabled` — array-form query batching enabled (batching attacks) (CWE-799)
- `graphql-field-suggestions-enabled` — field suggestions enabled (schema leak) (CWE-200)
- `graphql-no-rate-limiting` — no rate limiting on the endpoint (CWE-770)

## Related tools

- [`altais_audit_rate_limiting`](altais_audit_rate_limiting.md) — deeper rate-limiting configuration review
- [`altais_audit_grpc`](altais_audit_grpc.md) — auditing a gRPC service

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
