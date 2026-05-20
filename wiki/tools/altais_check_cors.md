# `altais_check_cors`

Validate a CORS policy expressed as an HTTP header map or a structured config.

| Property | Value |
|----------|-------|
| Module | [`headers`](../modules/headers.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Evaluates a Cross-Origin Resource Sharing policy supplied either as a map of HTTP headers or as a structured config object. It flags the dangerous combinations — wildcard origins with credentials, unsafe origin reflection, the literal `null` origin, and more. An agent calls this to confirm a CORS policy is not overly permissive. Provide either `headers` or `config`.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `headers` | `object` (string keys 1–256 chars, string values up to 8192 chars) | No | HTTP response headers as a case-insensitive key/value map. Provide this or `config`. |
| `config` | `object` (see below) | No | Structured CORS policy. Provide this or `headers`. |
| `source` | `string` (1–512 chars) | No | Label used for finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `allowed_origins` | `string[]` (up to 128 items, each 1–256 chars) | Origins permitted by the policy. |
| `reflect_origin` | `boolean` | Whether the server reflects the request `Origin` header. |
| `allow_credentials` | `boolean` | Whether `Access-Control-Allow-Credentials` is enabled. |
| `allowed_methods` | `string[]` (up to 16 items, each 1–16 chars) | Permitted HTTP methods. |
| `allowed_headers` | `string[]` (up to 64 items, each 1–128 chars) | Permitted request headers. |
| `expose_headers` | `string[]` (up to 64 items, each 1–128 chars) | Headers exposed to the browser. |
| `max_age_seconds` | `integer` (0–31,536,000) | Preflight cache lifetime. |
| `vary_origin` | `boolean` | Whether `Vary: Origin` is set. |

## Output

`{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape. Findings are appended to the session report. If neither `headers` nor `config` is supplied, an error result is returned.

## Example

**Request**

```json
{ "config": { "allowed_origins": ["*"], "allow_credentials": true } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [{ "rule": "wildcard-origin-with-credentials", "severity": "high" }]
}
```

## Detections

- Wildcard origin combined with credentials
- Unsafe reflection of the request `Origin` header
- The literal `null` origin being allowed
- Wildcard allowed methods
- Wildcard allowed headers
- Excessive `max-age` on preflight caching
- Missing `Vary: Origin`

## Related tools

- [`altais_audit_headers`](altais_audit_headers.md) — broader HTTP security-header audit
- [`altais_generate_csp`](altais_generate_csp.md) — generates a related cross-origin content policy

## See also

- [`headers` module](../modules/headers.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
