# `altais_audit_oauth`

Audits an OAuth 2.1 / OIDC implementation from source code or a structured config.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool runs OAuth 2.1 / OIDC security checks against either inline source code (pattern-based) or a structured config object. It flags insecure grant types (implicit, password), missing or downgraded PKCE, wildcard redirect URIs, missing CSRF/replay defenses (`state`, `nonce`), tokens stored in browser storage, and refresh-token rotation gaps. An agent calls it when reviewing an authorization-server or OAuth-client integration.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `config` | `object` | No | Structured OAuth/OIDC configuration (see below). |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `flow` | enum: `authorization_code` \| `client_credentials` \| `device_code` \| `implicit` \| `password` | The OAuth grant flow in use. |
| `pkce` | `object` `{ used: boolean, method?: "S256" \| "plain" }` | PKCE configuration. |
| `redirect_uris` | `string[]` (each 1–2048 chars, max 32) | Registered redirect URIs. |
| `uses_state` | `boolean` | Whether the `state` parameter is used. |
| `uses_nonce_for_oidc` | `boolean` | Whether the OIDC `nonce` is used. |
| `token_endpoint_auth` | enum: `client_secret_post` \| `client_secret_basic` \| `private_key_jwt` \| `none` | Token-endpoint client authentication method. |
| `token_storage` | enum: `httponly_cookie` \| `memory` \| `localStorage` \| `sessionStorage` | Where access tokens are stored. |
| `refresh_token_rotation` | `boolean` | Whether refresh tokens rotate on use. |
| `scope` | `string[]` (each 1–64 chars, max 64) | Requested scopes. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "flow": "authorization_code", "pkce": { "used": false }, "token_storage": "localStorage" } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "missing-pkce", "severity": "high", "title": "Authorization code flow without PKCE" },
    { "rule": "token-in-localstorage", "severity": "high", "title": "Access token stored in localStorage" }
  ]
}
```

## Detections

- Implicit / password grant in use — deprecated in OAuth 2.1 (CWE-1390)
- Missing PKCE or PKCE method set to `plain` (CWE-1390)
- Wildcard / overly broad redirect URIs (CWE-601)
- Missing `state` parameter — CSRF on the authorization request (CWE-352)
- Missing OIDC `nonce` — ID-token replay (CWE-294)
- Access / refresh tokens stored in `localStorage` or `sessionStorage` (CWE-922)
- Refresh-token rotation not enabled (CWE-613)

## Related tools

- [`altais_audit_jwt`](altais_audit_jwt.md) — audits the JWTs that OAuth flows issue
- [`altais_audit_session`](altais_audit_session.md) — audits the session cookies tokens may back

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
