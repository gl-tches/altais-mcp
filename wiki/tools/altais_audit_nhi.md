# `altais_audit_nhi`

Audits non-human identities against the OWASP Non-Human Identities Top 10.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool audits a list of non-human identities — service accounts, API keys, CI runners, workload identities, bot accounts — against the OWASP NHI Top 10. For each identity it checks for a missing owner, static long-lived keys, overdue rotation, wildcard scope, credentials committed to a repository, missing expiry, and password-type credentials. An agent calls it when reviewing machine-identity inventories.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `identities` | `object[]` (1–1000 items) | Yes | The non-human identities to audit (see below). |

Each entry in `identities` accepts:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` (1–256 chars) | Yes | Identity name. |
| `kind` | enum: `service_account` \| `api_key` \| `machine_user` \| `ci_runner` \| `workload_identity` \| `bot_account` \| `other` | Yes | Identity type. |
| `environment` | `string` (1–64 chars) | No | Deployment environment. |
| `owner` | `string` (1–256 chars) | No | Accountable owner. |
| `credential_type` | enum: `static_key` \| `oidc` \| `workload_identity` \| `mTLS` \| `password` | No | Credential mechanism. |
| `credential_age_days` | `integer` (0–10000) | No | Age of the current credential. |
| `rotation_period_days` | `integer` (0–10000) | No | Configured rotation interval. |
| `scopes` | `string[]` (each 1–256 chars, max 256) | No | Granted scopes / permissions. |
| `scoped_to_resources` | `string[]` (each 1–256 chars, max 256) | No | Resources the identity is bound to. |
| `expires_at` | `string` (1–64 chars) | No | Credential expiry timestamp. |
| `mfa_enabled` | `boolean` | No | Whether MFA is enabled. |
| `stored_in_repo` | `boolean` | No | Whether the credential is committed to a repository. |
| `stored_in_env_vars` | `boolean` | No | Whether the credential lives in environment variables. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "identities": [ { "name": "ci-deployer", "kind": "ci_runner", "credential_type": "static_key", "stored_in_repo": true } ] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "critical": 1, "high": 1 } },
  "findings": [
    { "rule": "credentials-in-repo", "severity": "critical", "title": "ci-deployer credential committed to a repository" },
    { "rule": "static-key", "severity": "high", "title": "ci-deployer uses a static long-lived key" }
  ]
}
```

## Detections

- Credentials committed to a repository (CWE-798)
- Static long-lived key where short-lived / OIDC credentials are preferable (CWE-798)
- Overdue or missing credential rotation (CWE-262)
- Wildcard / overly broad scope (CWE-269)
- Missing credential expiry (CWE-613)
- Password-type credential for a machine identity (CWE-287)
- Missing accountable owner

## Related tools

- [`altais_check_nhi_isolation`](altais_check_nhi_isolation.md) — verifies environment isolation of NHIs
- [`altais_check_secret_lifecycle`](altais_check_secret_lifecycle.md) — audits secret rotation and revocation

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
