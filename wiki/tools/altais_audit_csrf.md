# `altais_audit_csrf`

Verifies that state-changing endpoints are defended against cross-site request forgery.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool checks that state-changing HTTP endpoints carry adequate CSRF protection: `SameSite` cookies, a synchronizer or double-submit CSRF token, or an `Origin`/`Referer` header check. It accepts inline source code or a structured config describing how requests are authenticated and defended. An agent calls it when reviewing web request handlers that mutate state.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `config` | `object` | No | Structured CSRF configuration (see below). |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `auth_via` | enum: `cookie` \| `bearer` \| `mixed` | How requests are authenticated. |
| `samesite` | enum: `Strict` \| `Lax` \| `None` \| `false` | The `SameSite` attribute on the auth cookie. |
| `csrf_token` | enum: `synchronizer` \| `double_submit` \| `none` | CSRF-token strategy in use. |
| `checks_origin_header` | `boolean` | Whether the `Origin`/`Referer` header is validated. |
| `state_changing_methods` | array of enum: `POST` \| `PUT` \| `PATCH` \| `DELETE` (max 8) | HTTP methods treated as state-changing. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "auth_via": "cookie", "samesite": false, "csrf_token": "none" } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "no-csrf-protection", "severity": "high", "title": "Cookie-authenticated endpoints lack CSRF defense" }
  ]
}
```

## Detections

- No CSRF protection on cookie-authenticated, state-changing endpoints (CWE-352)
- `SameSite` absent or set to `None` without a compensating token (CWE-352)
- CSRF token strategy set to `none` (CWE-352)
- Missing `Origin` / `Referer` header validation (CWE-346)

## Related tools

- [`altais_audit_session`](altais_audit_session.md) — audits the session cookies CSRF targets
- [`altais_audit_oauth`](altais_audit_oauth.md) — audits OAuth `state` CSRF defense

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
