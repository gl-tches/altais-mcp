# `altais_check_nhi_isolation`

Verifies that non-human identities are scoped to a single environment, namespace, or project.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool verifies that each non-human identity is bound to a single environment, namespace, and project. It flags any pre-production identity that can reach production (or the reverse), which collapses the blast-radius boundary between environments. An agent calls it when reviewing how machine identities are partitioned across deployment tiers.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `identities` | `object[]` (1–1000 items) | Yes | The non-human identities to check (see below). |

Each entry in `identities` accepts:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` (1–256 chars) | Yes | Identity name. |
| `environment` | `string` (1–64 chars) | No | The environment the identity belongs to. |
| `namespace` | `string` (1–128 chars) | No | The namespace the identity belongs to. |
| `project` | `string` (1–128 chars) | No | The project the identity belongs to. |
| `scopes` | `string[]` (each 1–256 chars, max 256) | No | Granted scopes / permissions. |
| `cross_environment_access` | `string[]` (each 1–64 chars, max 16) | No | Other environments this identity can reach. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "identities": [ { "name": "staging-bot", "environment": "staging", "cross_environment_access": ["prod"] } ] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "cross-environment-access", "severity": "high", "title": "staging-bot can reach the prod environment" }
  ]
}
```

## Detections

- Cross-environment access — a pre-prod identity reaching prod, or vice versa (CWE-668)
- An identity not scoped to a single environment / namespace / project (CWE-269)

## Related tools

- [`altais_audit_nhi`](altais_audit_nhi.md) — broader NHI audit against the OWASP NHI Top 10
- [`altais_check_secret_lifecycle`](altais_check_secret_lifecycle.md) — audits secret rotation and revocation

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
