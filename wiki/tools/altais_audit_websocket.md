# `altais_audit_websocket`

Reviews a WebSocket server or client for security weaknesses.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews a WebSocket server or client from source code, a structured config, or both. It flags plaintext `ws://` instead of `wss://`, missing Origin validation on the upgrade handshake (Cross-Site WebSocket Hijacking), missing authentication, unbounded message size, missing rate limiting, and a missing per-session CSRF token. An agent calls it when reviewing a real-time WebSocket endpoint.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No* | WebSocket server/client source code, scanned with pattern matching. |
| `config` | `object` | No* | Structured description of the WebSocket posture (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

*At least one of `source` or `config` must be provided.

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `tls` | `boolean` | Whether the endpoint uses `wss://` (TLS). |
| `origin_validation` | `boolean` | Whether the upgrade handshake validates the Origin header. |
| `authentication` | `boolean` | Whether the connection is authenticated. |
| `message_size_limit` | `boolean` | Whether a maximum message / frame size is enforced. |
| `rate_limiting` | `boolean` | Whether per-connection rate limiting is applied. |
| `csrf_protection` | `boolean` | Whether a per-session CSRF token is required on the handshake. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "tls": false, "origin_validation": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "websocket-plaintext-ws", "severity": "medium", "title": "Plaintext ws:// endpoint" },
    { "rule": "websocket-no-origin-check", "severity": "high", "title": "No Origin validation on upgrade" }
  ]
}
```

## Detections

- `websocket-plaintext-ws` — plaintext `ws://` instead of `wss://` (CWE-319)
- `websocket-no-origin-check` — no Origin validation on the upgrade handshake / Cross-Site WebSocket Hijacking (CWE-346, CWE-1385)
- `websocket-no-authentication` — connection not authenticated (CWE-306)
- `websocket-unbounded-message-size` — unbounded message size (CWE-770, CWE-400)
- `websocket-no-rate-limiting` — no per-connection rate limiting (CWE-770, CWE-400)
- `websocket-no-csrf-token` — no per-session CSRF token on the handshake (CWE-352)

## Related tools

- [`altais_audit_sse`](altais_audit_sse.md) — auditing a Server-Sent Events stream
- [`altais_audit_graphql`](altais_audit_graphql.md) — auditing a GraphQL transport

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
