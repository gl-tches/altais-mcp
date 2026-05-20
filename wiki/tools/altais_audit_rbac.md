# `altais_audit_rbac`

Inspects a structured RBAC / ABAC policy for privilege-escalation paths.

| Property | Value |
|----------|-------|
| Module | [`auth`](../modules/auth.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool inspects a structured authorization policy for privilege-escalation and misconfiguration risks: default-allow posture, superuser roles holding `*:*`, wildcards on dangerous resources, self-elevation paths (a role that can grant roles), role-inheritance cycles, and dangling parent references. An agent calls it when reviewing an access-control policy definition.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filename` | `string` (1–512 chars) | No | Filename for finding location. |
| `policy` | `object` | Yes | The structured RBAC / ABAC policy (see below). |

The `policy` object has these fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | enum: `rbac` \| `abac` \| `rebac` | No | The access-control model. |
| `default` | enum: `allow` \| `deny` | No | Default decision when no rule matches. |
| `roles` | `object[]` (max 256) | Yes | The roles defined in the policy (see below). |
| `assignments` | `object[]` (max 2000) | No | User-to-role assignments, each `{ user, role }`. |

Each entry in `roles` is `{ name: string (1–128), description?: string (≤1024), inherits?: string[] (each 1–128, max 32), permissions: array }`. Each `permissions` entry is either a `string` (1–128 chars) or an object `{ resource: string (1–128), action: string (1–64) }`; up to 256 permissions per role.

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }` with the standard finding shape. All findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "policy": { "default": "allow", "roles": [ { "name": "admin", "permissions": ["*:*"] } ] } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "default-allow", "severity": "high", "title": "Policy defaults to allow" },
    { "rule": "superuser-role", "severity": "high", "title": "Role 'admin' holds wildcard *:* permission" }
  ]
}
```

## Detections

- Default-allow policy posture (CWE-1188 / CWE-276)
- Superuser role holding `*:*` permission (CWE-269)
- Wildcards on dangerous resources (CWE-269)
- Self-elevation path — a role that can grant roles (CWE-269)
- Role-inheritance cycle (CWE-674)
- Dangling parent reference in `inherits` (CWE-271)

## Related tools

- [`altais_audit_nhi`](altais_audit_nhi.md) — audits non-human identity scoping
- [`altais_check_nhi_isolation`](altais_check_nhi_isolation.md) — audits cross-environment access

## See also

- [`auth` module](../modules/auth.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
