# `altais_audit_key_mgmt`

Scans source for hardcoded keys and audits a structured key inventory for insecure storage and rotation gaps.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code for hardcoded keys and embedded PEM private keys, and audits a structured key inventory for insecure storage, high-value keys kept outside an HSM/KMS, missing or overdue rotation, never-rotated keys, and undersized RSA keys. An agent calls this when reviewing how cryptographic keys are stored, sized, and rotated across a system.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `as_of` | `string` (1–64 chars) | No | ISO date used as "now" for key-age math. Defaults to the current date. |
| `keys` | `array` (max 1000) | No | Key inventory entries. |
| `keys[].name` | `string` (1–256 chars) | Yes | Key name. |
| `keys[].type` | `enum` | No | One of `signing`, `encryption`, `root_ca`, `tls`, `api`, `master`. |
| `keys[].algorithm` | `string` (1–64 chars) | No | Key algorithm. |
| `keys[].key_size_bits` | `integer` (0–65536) | No | Key size in bits. |
| `keys[].storage` | `enum` | No | One of `hsm`, `kms`, `vault`, `secrets_manager`, `env_var`, `config_file`, `source_code`, `repo`. |
| `keys[].rotation_period_days` | `integer` (0–36500) | No | Rotation interval in days. |
| `keys[].last_rotated_at` | `string` (1–64 chars) | No | ISO date the key was last rotated. |
| `keys[].created_at` | `string` (1–64 chars) | No | ISO date the key was created. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "keys": [{ "name": "root-ca", "type": "root_ca", "storage": "config_file" }] }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "high-value-key-not-in-hsm",
      "severity": "high",
      "title": "High-value key stored outside an HSM/KMS",
      "status": "open"
    }
  ]
}
```

## Detections

- Hardcoded keys and embedded PEM private keys in source (CWE-321, CWE-798)
- Insecure key storage — env var, config file, source code, repo (CWE-312, CWE-798)
- High-value keys outside an HSM/KMS (CWE-320)
- Missing or overdue key rotation (CWE-324)
- Keys that have never been rotated (CWE-324)
- Undersized RSA keys (CWE-326)

## Related tools

- [`altais_audit_crypto`](altais_audit_crypto.md) — audits cryptographic algorithm usage
- [`altais_audit_randomness`](altais_audit_randomness.md) — finds non-cryptographic PRNGs in key generation
- [`altais_assess_crypto_agility`](altais_assess_crypto_agility.md) — assesses whether primitives can be swapped without code changes

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
