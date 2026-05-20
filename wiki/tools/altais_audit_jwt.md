# `altais_audit_jwt`

Scans code for JWT library misuse, decodes an actual token, and/or audits the verifier configuration.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool inspects JSON Web Token usage three ways: it pattern-matches source code for JWT library misuse, decodes a supplied token to inspect its claims, and audits a structured verifier config. It flags `alg:none` acceptance, a missing algorithms allowlist, HS/RS algorithm confusion, and missing or unverified `exp` / `aud` / `iss` claims. An agent calls it when reviewing token issuance or verification code.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `token` | `string` (1–16384 chars) | No | An actual JWT to decode and check. |
| `config` | `object` | No | Structured verifier configuration (see below). |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `accepted_algorithms` | `string[]` (each 1–16 chars, max 32) | The algorithms the verifier accepts. |
| `required_iss` | `string[]` (each 1–256 chars, max 16) | Required issuer values. |
| `required_aud` | `string[]` (each 1–256 chars, max 16) | Required audience values. |
| `clock_skew_seconds` | `integer` (0–3600) | Allowed clock skew. |
| `verify_exp` | `boolean` | Whether expiry is verified. |
| `verify_nbf` | `boolean` | Whether the not-before claim is verified. |
| `jwks_uri` | `string` (1–1024 chars) | JWKS endpoint URL. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. When a `token` is supplied, decoded claim details surface in finding evidence. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "accepted_algorithms": ["none", "HS256"], "verify_exp": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "critical": 1, "high": 1 } },
  "findings": [
    { "rule": "alg-none-accepted", "severity": "critical", "title": "Verifier accepts the 'none' algorithm" },
    { "rule": "exp-not-verified", "severity": "high", "title": "Token expiry is not verified" }
  ]
}
```

## Detections

- `alg:none` accepted by the verifier — signature bypass (CWE-347)
- Missing algorithms allowlist (CWE-347)
- HS-with-RS algorithm confusion (CWE-347)
- Expiry (`exp`) not verified — long-lived / replayable tokens (CWE-613)
- Missing `aud` / `iss` validation (CWE-287)
- Long-lived tokens with no expiry constraint (CWE-613)

## Related tools

- [`altais_audit_oauth`](altais_audit_oauth.md) — audits the OAuth flow that issues JWTs
- [`altais_audit_session`](altais_audit_session.md) — audits cookie-based session alternatives

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
