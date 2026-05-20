# `altais_audit_headers`

Check a response header map against current HTTP security best practice.

| Property | Value |
|----------|-------|
| Module | [`headers`](../modules/headers.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Evaluates a map of HTTP response headers against current best practice and emits one finding per problem. It validates the presence and configuration of CSP, HSTS, framing, content-type, referrer, and permissions headers, plus cookie attributes and server-identity leaks. An agent calls this to audit a service's response headers.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `headers` | `object` (string keys 1–256 chars, string values up to 8192 chars) | Yes | HTTP response headers as a case-insensitive key/value map. |
| `context` | `string` enum `html-app` \| `api` \| `static-asset` | No (default `html-app`) | Hint that adjusts which headers are required. |
| `source` | `string` (1–512 chars) | No | Label (URL or filename) used for finding location. |

## Output

`{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape. Findings are appended to the session report.

## Example

**Request**

```json
{ "headers": { "Content-Type": "text/html" }, "context": "html-app" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [{ "rule": "missing-hsts", "severity": "medium" }]
}
```

## Detections

- Missing or weak Content-Security-Policy
- Missing HSTS (`Strict-Transport-Security`)
- Missing `X-Frame-Options` framing protection
- Missing `X-Content-Type-Options`
- Missing or weak `Referrer-Policy`
- Missing `Permissions-Policy`
- Basic CORS misconfiguration
- Insecure `Set-Cookie` attributes
- Server-identity leaks (e.g. `Server`, `X-Powered-By`)

## Related tools

- [`altais_generate_csp`](altais_generate_csp.md) — builds a strict CSP to fix a missing/weak policy
- [`altais_check_cors`](altais_check_cors.md) — deeper validation of a CORS policy

## See also

- [`headers` module](../modules/headers.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
