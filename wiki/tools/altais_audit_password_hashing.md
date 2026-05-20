# `altais_audit_password_hashing`

Scans source code for password-hashing patterns and flags fast hashes used in a password context.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool scans source code for password-hashing usage. It flags fast cryptographic hashes (MD5, SHA-family) applied in a password context, and notes whether a proper password-hashing function (Argon2, bcrypt, scrypt) is present or absent. An agent calls it when reviewing user-credential storage or authentication code.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | Yes | Code to scan for password-hashing patterns. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. Findings note the detected hash and the presence or absence of a slow password hash. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "source": "const hash = md5(password)" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "weak-password-hash", "severity": "high", "cwe": ["CWE-916"], "title": "Fast hash used for password storage" }
  ]
}
```

## Detections

- Fast hash (MD5 / SHA-1 / SHA-256, etc.) used in a password context — use of a password hash with insufficient computational effort (CWE-916)
- Use of a broken or risky cryptographic algorithm for credentials (CWE-327)
- Absence of Argon2 / bcrypt / scrypt where password hashing is expected

## Related tools

- [`altais_audit_oauth`](altais_audit_oauth.md) — audits token-based authentication flows
- [`altais_check_secret_lifecycle`](altais_check_secret_lifecycle.md) — audits stored credentials more broadly

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
