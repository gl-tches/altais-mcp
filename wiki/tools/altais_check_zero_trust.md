# `altais_check_zero_trust`

Assesses an architecture against the NIST SP 800-207 zero-trust tenets.

| Property | Value |
|----------|-------|
| Module | [`infra`](../modules/infra.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool assesses a structured architecture description against the tenets of NIST SP 800-207 (Zero Trust Architecture). It emits a finding for each missing tenet — explicit verification, least privilege, assume breach, enforced MFA, microsegmentation, device-trust verification, continuous verification, no implicit network trust, encrypted east-west traffic, per-request authorization, and a centralized policy engine — and returns a maturity summary. An agent calls it when measuring how closely an architecture follows zero-trust principles.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The zero-trust architecture description to assess (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional boolean fields:

| Field | Type | Description |
|-------|------|-------------|
| `verify_explicitly` | `boolean` | Every request is verified explicitly. |
| `least_privilege_access` | `boolean` | Access is scoped to least privilege. |
| `assume_breach` | `boolean` | The architecture assumes breach. |
| `mfa_enforced` | `boolean` | Multi-factor authentication is enforced. |
| `microsegmentation` | `boolean` | The network is microsegmented. |
| `device_trust_verification` | `boolean` | Device trust / posture is verified before access. |
| `continuous_verification` | `boolean` | Sessions are continuously re-verified. |
| `no_implicit_network_trust` | `boolean` | Network location confers no implicit trust. |
| `encrypted_internal_traffic` | `boolean` | Internal (east-west) traffic is encrypted. |
| `per_request_authorization` | `boolean` | Authorization is evaluated per request. |
| `centralized_policy_engine` | `boolean` | A centralized policy engine governs access decisions. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...], maturity: {...} }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). The `maturity` block summarizes how many tenets are satisfied. All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "mfa_enforced": false, "microsegmentation": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "zt-mfa-not-enforced", "severity": "high", "title": "MFA not enforced" }
  ],
  "maturity": { "satisfied": 0, "total": 11 }
}
```

## Detections

- `zt-verify-explicitly-missing` — requests not verified explicitly (CWE-284, CWE-285)
- `zt-least-privilege-missing` — access not scoped to least privilege (CWE-272, CWE-269)
- `zt-assume-breach-missing` — architecture does not assume breach (CWE-284)
- `zt-mfa-not-enforced` — MFA not enforced (CWE-308, CWE-287)
- `zt-microsegmentation-missing` — network not microsegmented (CWE-1008, CWE-668)
- `zt-device-trust-missing` — device trust / posture not verified (CWE-287)
- `zt-continuous-verification-missing` — sessions not continuously re-verified (CWE-613, CWE-287)
- `zt-implicit-network-trust` — network location confers implicit trust (CWE-284, CWE-668)
- `zt-internal-traffic-unencrypted` — east-west traffic not encrypted (CWE-319)
- `zt-per-request-authz-missing` — authorization not evaluated per request (CWE-285, CWE-284)
- `zt-policy-engine-missing` — no centralized policy engine (CWE-284)

## Related tools

- [`altais_audit_network`](altais_audit_network.md) — segmentation and microsegmentation review
- [`altais_check_hardening`](altais_check_hardening.md) — CIS-benchmark platform hardening

## See also

- [`infra` module](../modules/infra.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
