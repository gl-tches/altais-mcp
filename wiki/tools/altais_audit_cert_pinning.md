# `altais_audit_cert_pinning`

Reviews certificate pinning for the dead HPKP header, leaf pinning, missing backup pins, and non-enforcement.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews certificate pinning: flags the dead HPKP `Public-Key-Pins` header, leaf-certificate pinning (versus SPKI/public-key pinning), pinning with no backup pin (which risks bricking clients), and report-only or non-enforcing pinning. It also notes absent pinning for mobile platforms. An agent calls this when reviewing how a mobile app or backend pins TLS certificates.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured certificate-pinning configuration. |
| `config.pinning_enabled` | `boolean` | No | Whether certificate pinning is enabled. |
| `config.pin_type` | `enum` | No | One of `leaf_certificate`, `public_key`, `ca_certificate`. |
| `config.pin_count` | `integer` (0–64) | No | Number of pins configured. |
| `config.has_backup_pin` | `boolean` | No | Whether a backup pin is configured. |
| `config.enforced` | `boolean` | No | Whether pinning is enforced (vs. report-only). |
| `config.platform` | `enum` | No | One of `android`, `ios`, `web`, `backend`. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "pinning_enabled": true, "pin_type": "leaf_certificate", "has_backup_pin": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "leaf-certificate-pinning", "severity": "medium", "status": "open" },
    { "rule": "no-backup-pin", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Use of the dead HPKP `Public-Key-Pins` header (CWE-1104)
- Leaf-certificate pinning instead of SPKI/public-key pinning (CWE-295)
- Pinning with no backup pin — client brick risk (CWE-295)
- Report-only or non-enforcing pinning (CWE-295)
- Absent pinning for mobile platforms (CWE-295)

## Related tools

- [`altais_audit_ct_logs`](altais_audit_ct_logs.md) — checks Certificate Transparency monitoring
- [`altais_audit_tls`](altais_audit_tls.md) — reviews TLS configuration

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
