# `altais_audit_sse`

Audits a Server-Sent Events endpoint for security weaknesses.

| Property | Value |
|----------|-------|
| Module | [`protocol`](../modules/protocol.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a Server-Sent Events (`text/event-stream`) endpoint from source code, a structured config, or both. It flags missing Origin validation, missing authentication, plaintext `http://` instead of `https://`, no reconnection backoff (reconnection storms), unrestricted CORS on the event-stream endpoint, and no per-client connection cap. An agent calls it when reviewing an SSE streaming endpoint.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No* | SSE endpoint source code, scanned with pattern matching. |
| `config` | `object` | No* | Structured description of the Server-Sent Events posture (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

*At least one of `source` or `config` must be provided.

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `origin_validation` | `boolean` | Whether the SSE endpoint validates the Origin header. |
| `authentication` | `boolean` | Whether the SSE endpoint is authenticated. |
| `tls` | `boolean` | Whether the SSE endpoint is served over HTTPS. |
| `reconnection_backoff` | `boolean` | Whether a reconnection backoff / `retry:` interval is used. |
| `cors_restricted` | `boolean` | Whether CORS on the endpoint is restricted to an allowlist. |
| `per_connection_limit` | `boolean` | Whether a per-client concurrent connection cap is enforced. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "tls": false, "authentication": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "sse-plaintext-http", "severity": "medium", "title": "Plaintext http:// SSE endpoint" },
    { "rule": "sse-no-authentication", "severity": "high", "title": "SSE endpoint not authenticated" }
  ]
}
```

## Detections

- `sse-plaintext-http` — plaintext `http://` instead of `https://` (CWE-319)
- `sse-no-origin-check` — no Origin validation (CWE-346)
- `sse-no-authentication` — SSE endpoint not authenticated (CWE-306)
- `sse-no-reconnection-backoff` — no reconnection backoff (reconnection storms) (CWE-400)
- `sse-wildcard-cors` / `sse-unrestricted-cors` — unrestricted CORS on the event-stream endpoint (CWE-942, CWE-346)
- `sse-no-connection-limit` — no per-client concurrent connection cap (CWE-400)

## Related tools

- [`altais_audit_websocket`](altais_audit_websocket.md) — auditing a WebSocket transport
- [`altais_check_webhook`](altais_check_webhook.md) — auditing a webhook receiver

## See also

- [`protocol` module](../modules/protocol.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
