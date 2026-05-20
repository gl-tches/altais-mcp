# `altais_audit_session`

Checks session cookie flags, regeneration, invalidation, timeouts, and session-ID entropy.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits server-side session management. It checks cookie security attributes (`Secure`, `HttpOnly`, `SameSite`), whether the session ID is regenerated on login and invalidated on logout, absolute and idle timeouts, and the entropy of the session identifier. It accepts inline source code patterns or a structured config. An agent calls it when reviewing authentication and session-handling code.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `config` | `object` | No | Structured session configuration (see below). |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `cookie` | `object` | Session cookie attributes (see nested fields below). |
| `regenerate_on_login` | `boolean` | Whether the session ID is regenerated after login. |
| `invalidate_on_logout` | `boolean` | Whether the session is invalidated on logout. |
| `absolute_timeout_seconds` | `integer` (0–31536000) | Absolute session lifetime. |
| `idle_timeout_seconds` | `integer` (0–31536000) | Idle session timeout. |
| `id_entropy_bits` | `integer` (0–1024) | Entropy of the session identifier in bits. |

The nested `cookie` object accepts: `secure` (`boolean`), `httpOnly` (`boolean`), `sameSite` (`"Strict"` \| `"Lax"` \| `"None"` \| `false`), `maxAgeSeconds` (`integer` 0–31536000), `domain` (`string` 1–256 chars).

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "cookie": { "secure": false, "httpOnly": false }, "regenerate_on_login": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 3, "by_severity": { "high": 1, "medium": 2 } },
  "findings": [
    { "rule": "cookie-missing-secure", "severity": "medium", "title": "Session cookie missing the Secure flag" },
    { "rule": "cookie-missing-httponly", "severity": "medium", "title": "Session cookie missing HttpOnly" },
    { "rule": "no-session-regeneration", "severity": "high", "title": "Session ID not regenerated on login" }
  ]
}
```

## Detections

- Session cookie missing `Secure` — cleartext transmission (CWE-614)
- Session cookie missing `HttpOnly` — script-readable cookie (CWE-1004)
- `SameSite` absent or set to `None` (CWE-352)
- No session-ID regeneration on login — session fixation (CWE-384)
- No session invalidation on logout (CWE-613)
- Missing absolute / idle timeouts (CWE-613)
- Low session-ID entropy (CWE-330)

## Related tools

- [`altais_audit_csrf`](altais_audit_csrf.md) — audits CSRF defenses for cookie-backed sessions
- [`altais_audit_oauth`](altais_audit_oauth.md) — audits token-based authentication

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
