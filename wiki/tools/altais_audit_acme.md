# `altais_audit_acme`

Reviews an ACME / Let's Encrypt configuration for renewal, challenge, and key-storage weaknesses.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews an ACME setup for missing renewal automation, a renewal threshold too close to expiry, `http-01` used for a wildcard certificate (which requires `dns-01`), missing CAA records, weak certificate keys, use of the staging endpoint in production, and insecure account-key storage. An agent calls this when reviewing how a system obtains and renews certificates from a CA such as Let's Encrypt.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | Yes | Structured ACME configuration. |
| `config.provider` | `string` (1–128 chars) | No | ACME provider name. |
| `config.challenge_type` | `enum` | No | One of `http-01`, `dns-01`, `tls-alpn-01`. |
| `config.auto_renewal` | `boolean` | No | Whether renewal is automated. |
| `config.renewal_threshold_days` | `integer` (0–365) | No | Days before expiry that renewal is attempted. |
| `config.wildcard` | `boolean` | No | Whether a wildcard certificate is issued. |
| `config.caa_configured` | `boolean` | No | Whether CAA DNS records are configured. |
| `config.key_type` | `enum` | No | One of `rsa`, `ecdsa`. |
| `config.key_size_bits` | `integer` (0–65536) | No | Certificate key size in bits. |
| `config.staging_endpoint` | `boolean` | No | Whether the ACME staging endpoint is in use. |
| `config.account_key_storage` | `enum` | No | One of `hsm`, `kms`, `vault`, `file`, `repo`. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "challenge_type": "http-01", "wildcard": true, "auto_renewal": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "http01-for-wildcard", "severity": "high", "status": "open" },
    { "rule": "no-renewal-automation", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Missing renewal automation (CWE-324)
- Renewal threshold too close to expiry (CWE-324)
- `http-01` challenge used for a wildcard certificate (CWE-295)
- Missing CAA records (CWE-295)
- Weak certificate keys (CWE-326)
- Staging endpoint used in production (CWE-295)
- Insecure account-key storage — file or repo (CWE-312, CWE-798)

## Related tools

- [`altais_audit_tls`](altais_audit_tls.md) — reviews TLS configuration
- [`altais_audit_ct_logs`](altais_audit_ct_logs.md) — checks Certificate Transparency monitoring
- [`altais_audit_key_mgmt`](altais_audit_key_mgmt.md) — audits key storage and rotation

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
