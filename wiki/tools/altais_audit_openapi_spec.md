# `altais_audit_openapi_spec`

Validates a JSON OpenAPI 3.x specification for security gaps.

| Property | Value |
|----------|-------|
| Module | [`api`](../modules/api.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a JSON OpenAPI 3.x contract and audits it for security gaps in its declared design. It flags missing or weak security schemes, operations with no security requirement, cleartext server URLs, operations missing error responses, request schemas open to mass assignment, request bodies with no schema, and undocumented rate limiting. An agent calls it when reviewing an API contract before publishing or generating client/server stubs. YAML is not supported — the spec must be JSON.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `spec` | `string` (1–1048576 chars) | Yes | A JSON OpenAPI 3.x document (the contract text). YAML is not supported. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`. If the `spec` is not parseable JSON, the tool returns `isError: true` with an actionable message.

## Example

**Request**

```json
{ "spec": "{ \"openapi\": \"3.0.0\", \"servers\": [{ \"url\": \"http://api.example.com\" }], \"paths\": {} }" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "openapi-no-security", "severity": "high", "title": "No security scheme defined" },
    { "rule": "openapi-cleartext-server-url", "severity": "medium", "title": "Cleartext http:// server URL" }
  ]
}
```

## Detections

- `openapi-no-security` — no security scheme defined (CWE-306)
- `openapi-basic-auth-scheme` — HTTP Basic auth scheme (CWE-522)
- `openapi-apikey-in-query` — API key carried in the query string (CWE-598)
- `openapi-operation-no-security` — operation with no security requirement (CWE-306)
- `openapi-cleartext-server-url` — cleartext `http://` server URL (CWE-319)
- `openapi-operation-no-error-response` — operation missing 4xx/5xx error responses (CWE-1059)
- `openapi-additional-properties-open` — request schema allows arbitrary extra properties / mass assignment (CWE-915)
- `openapi-request-body-no-schema` — request body with no schema (CWE-20)
- `openapi-no-rate-limit-documented` — no documented rate limiting (`429`) (CWE-770)

## Related tools

- [`altais_audit_rate_limiting`](altais_audit_rate_limiting.md) — audits the runtime rate-limiting configuration
- [`altais_audit_api_gateway`](altais_audit_api_gateway.md) — audits the gateway fronting the API

## See also

- [`api` module](../modules/api.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
