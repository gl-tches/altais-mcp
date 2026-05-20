# `altais_audit_api_gateway`

Reviews an API gateway's security configuration.

| Property | Value |
|----------|-------|
| Module | [`api`](../modules/api.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews an API gateway's security configuration object for edge-hardening weaknesses. It flags disabled authentication or authorization, disabled or weak TLS, a missing WAF, no edge request validation, no request size limit, missing or over-long timeouts, disabled rate limiting and access logging, a wildcard CORS origin combined with credentials, and cleartext gateway-to-backend traffic. An agent calls it when reviewing the configuration of an API gateway or ingress edge.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The API gateway configuration to audit (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `authentication_enabled` | `boolean` | Whether the gateway enforces authentication. |
| `authorization_enabled` | `boolean` | Whether the gateway enforces authorization. |
| `tls_enabled` | `boolean` | Whether the gateway terminates TLS. |
| `min_tls_version` | `string` (1–32 chars) | Minimum accepted TLS version, e.g. `1.2` or `TLSv1.3`. |
| `waf_enabled` | `boolean` | Whether a web application firewall is enabled. |
| `request_validation` | `boolean` | Whether the gateway validates requests against a schema. |
| `request_size_limit_bytes` | `number` (int, 0–1000000000000) | Maximum allowed request body size in bytes. |
| `timeout_seconds` | `number` (int, 0–86400) | Request timeout in seconds. |
| `rate_limiting_enabled` | `boolean` | Whether the gateway enforces rate limiting. |
| `logging_enabled` | `boolean` | Whether the gateway logs access requests. |
| `cors` | `object` `{ allow_all_origins?: boolean, allow_credentials?: boolean }` | The gateway's CORS policy. |
| `ip_allowlist_enabled` | `boolean` | Whether an IP allowlist is enforced. |
| `mtls_enabled` | `boolean` | Whether mutual TLS is enabled for clients. |
| `api_keys_rotated` | `boolean` | Whether API keys are rotated on a schedule. |
| `backend_tls` | `boolean` | Whether gateway-to-backend traffic is encrypted. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "authentication_enabled": false, "waf_enabled": false, "backend_tls": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 3, "by_severity": { "high": 2, "medium": 1 } },
  "findings": [
    { "rule": "gateway-authentication-disabled", "severity": "high", "title": "Gateway authentication disabled" },
    { "rule": "gateway-cleartext-backend", "severity": "high", "title": "Cleartext gateway-to-backend traffic" }
  ]
}
```

## Detections

- `gateway-authentication-disabled` / `gateway-authorization-disabled` — auth or authz disabled (CWE-306, CWE-862)
- `gateway-tls-disabled` — TLS termination disabled (CWE-319)
- `gateway-weak-tls-version` — TLS pinned below 1.2 (CWE-326)
- `gateway-waf-disabled` — no web application firewall (CWE-20)
- `gateway-no-request-validation` — no edge request validation (CWE-20)
- `gateway-no-request-size-limit` — no request size limit (CWE-770)
- `gateway-no-timeout` / `gateway-long-timeout` — missing or over-long request timeout (CWE-400)
- `gateway-rate-limiting-disabled` — rate limiting disabled (CWE-770)
- `gateway-logging-disabled` — access logging disabled (CWE-778)
- `gateway-cors-wildcard-origin` / `gateway-cors-wildcard-with-credentials` — wildcard CORS origin, especially with credentials (CWE-942, CWE-346)
- `gateway-cleartext-backend` — cleartext gateway-to-backend traffic (CWE-319)

## Related tools

- [`altais_audit_openapi_spec`](altais_audit_openapi_spec.md) — audits the API contract the gateway fronts
- [`altais_audit_rate_limiting`](altais_audit_rate_limiting.md) — deeper rate-limiting configuration review

## See also

- [`api` module](../modules/api.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
