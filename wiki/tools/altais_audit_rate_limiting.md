# `altais_audit_rate_limiting`

Checks a rate-limiting configuration for coverage gaps.

| Property | Value |
|----------|-------|
| Module | [`api`](../modules/api.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews a rate-limiting configuration object for gaps that leave an API exposed to abuse. It flags rate limiting that is disabled or absent, a global-only scope a single client can exhaust, authentication endpoints left unthrottled, a budget too large to constrain abuse, a missing `429` response, and a missing `Retry-After` header. It can optionally scan source for known limiter libraries. An agent calls it when reviewing brute-force and denial-of-service defenses for an API.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The rate-limiting configuration to audit (see below). |
| `source` | `string` (1–1048576 chars) | No | Source code to scan for known rate-limiting libraries. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `boolean` | Whether rate limiting is enabled. |
| `strategy` | enum: `fixed_window` \| `sliding_window` \| `token_bucket` \| `leaky_bucket` \| `none` | The rate-limiting algorithm in use. |
| `scope` | enum: `global` \| `per_ip` \| `per_user` \| `per_api_key` | The dimension the limit is keyed on. |
| `limit` | `number` (int, 0–1000000000) | Maximum requests allowed per window. |
| `window_seconds` | `number` (int, 0–86400) | Length of the rate-limit window in seconds. |
| `applies_to_auth_endpoints` | `boolean` | Whether authentication endpoints are rate-limited. |
| `burst` | `number` (int, 0–1000000) | Burst allowance above the steady-state limit. |
| `returns_429` | `boolean` | Whether throttled requests return HTTP 429. |
| `has_retry_after_header` | `boolean` | Whether throttled responses include a `Retry-After` header. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "enabled": true, "scope": "global", "applies_to_auth_endpoints": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "rate-limit-auth-endpoints-unprotected", "severity": "high", "title": "Auth endpoints unthrottled" }
  ]
}
```

## Detections

- `rate-limit-disabled` — rate limiting disabled or absent (CWE-770)
- `rate-limit-global-scope-only` — global-only scope a single client can exhaust (CWE-770)
- `rate-limit-auth-endpoints-unprotected` — authentication endpoints unthrottled (CWE-307)
- `rate-limit-budget-too-high` — budget too large to constrain abuse (CWE-770)
- `rate-limit-no-429-response` — throttled requests do not return HTTP 429 (CWE-770)
- `rate-limit-no-retry-after` — no `Retry-After` header on throttled responses (CWE-770)
- `rate-limit-no-limiter-library` — no known limiter library detected in supplied source (CWE-770)

## Related tools

- [`altais_audit_openapi_spec`](altais_audit_openapi_spec.md) — checks whether `429` rate limiting is documented in the contract
- [`altais_audit_api_gateway`](altais_audit_api_gateway.md) — audits gateway-level rate limiting

## See also

- [`api` module](../modules/api.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
