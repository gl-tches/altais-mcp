# `altais_audit_passkey_impl`

Audits a FIDO2 / passkey (WebAuthn) implementation.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool checks WebAuthn / passkey configuration and source code for common implementation flaws: `rp_id`-to-origin alignment, the `userVerification` requirement, challenge entropy, the attestation policy, sign-count tracking, and the use of server-issued challenges. An agent calls it when reviewing a FIDO2 registration or authentication ceremony.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2 MiB) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `config` | `object` | No | Structured passkey configuration (see below). |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `rp_id` | `string` (1–256 chars) | The Relying Party identifier. |
| `user_verification` | enum: `required` \| `preferred` \| `discouraged` | The `userVerification` requirement. |
| `resident_key` | enum: `required` \| `preferred` \| `discouraged` | The resident-key (discoverable credential) requirement. |
| `attestation` | enum: `none` \| `indirect` \| `direct` \| `enterprise` | The attestation conveyance preference. |
| `origins` | `string[]` (each 1–512 chars, max 32) | Allowed origins. |
| `challenge_entropy_bits` | `integer` (0–4096) | Entropy of the registration / authentication challenge. |
| `stores_credential_id` | `boolean` | Whether the credential ID is persisted. |
| `stores_aaguid` | `boolean` | Whether the authenticator AAGUID is persisted. |
| `stores_sign_count` | `boolean` | Whether the signature counter is persisted. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "user_verification": "discouraged", "stores_sign_count": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "user-verification-discouraged", "severity": "medium", "title": "userVerification set to discouraged" },
    { "rule": "no-sign-count-tracking", "severity": "medium", "title": "Signature counter not tracked" }
  ]
}
```

## Detections

- `rp_id` not aligned with the application origin (CWE-346)
- `userVerification` set to `discouraged` (CWE-308)
- Low challenge entropy or non-server-issued challenge — replay risk (CWE-330 / CWE-294)
- Permissive attestation policy where verification is expected (CWE-287)
- Signature counter not tracked — cloned-authenticator detection disabled (CWE-294)

## Related tools

- [`altais_audit_oauth`](altais_audit_oauth.md) — audits OAuth-based authentication
- [`altais_audit_session`](altais_audit_session.md) — audits the session created post-authentication

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
