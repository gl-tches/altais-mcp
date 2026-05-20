# `altais_check_secret_lifecycle`

Audits a structured list of secrets for rotation, expiry, and revocation gaps.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a structured inventory of secrets — API keys, OAuth client secrets, signing and encryption keys, passwords, webhooks — for lifecycle hygiene. It flags secrets rotated past their kind-specific threshold, never-rotated long-lived secrets, missing expiry, expired-but-still-listed secrets, undocumented revocation procedures, and missing audit logging. An agent calls it when reviewing secret management practices.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `secrets` | `object[]` (1–2000 items) | Yes | The secrets to audit (see below). |

Each entry in `secrets` accepts:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` (1–256 chars) | Yes | Secret name. |
| `kind` | enum: `api_key` \| `oauth_client_secret` \| `signing_key` \| `encryption_key` \| `password` \| `webhook` | Yes | Secret type. |
| `owner` | `string` (1–256 chars) | No | Accountable owner. |
| `created_at` | `string` (1–64 chars) | No | Creation timestamp. |
| `last_rotated_at` | `string` (1–64 chars) | No | Last rotation timestamp. |
| `expires_at` | `string` (1–64 chars) | No | Expiry timestamp. |
| `rotation_period_days` | `integer` (0–10000) | No | Configured rotation interval. |
| `revocation_procedure_documented` | `boolean` | No | Whether a revocation procedure is documented. |
| `audit_logged` | `boolean` | No | Whether secret usage is audit-logged. |
| `stored_in` | enum: `vault` \| `secrets_manager` \| `env_var` \| `repo` \| `file_on_disk` | No | Where the secret is stored. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "secrets": [ { "name": "api-signing-key", "kind": "signing_key", "last_rotated_at": "2021-01-01" } ] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "rotation-overdue", "severity": "high", "title": "api-signing-key rotation is overdue" },
    { "rule": "no-expiry", "severity": "medium", "title": "api-signing-key has no expiry" }
  ]
}
```

## Detections

- Rotation past the kind-specific threshold (CWE-262)
- Never-rotated long-lived secret (CWE-262)
- Missing expiry (CWE-613)
- Expired but still-listed secret (CWE-672)
- Undocumented revocation procedure
- Missing audit logging (CWE-778)

## Related tools

- [`altais_audit_nhi`](altais_audit_nhi.md) — audits the identities that hold these secrets
- [`altais_check_nhi_isolation`](altais_check_nhi_isolation.md) — audits cross-environment identity access

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
