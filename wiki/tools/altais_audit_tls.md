# `altais_audit_tls`

Reviews a TLS configuration or client/server source for deprecated protocols, weak ciphers, and disabled certificate verification.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits a structured TLS configuration or TLS client/server source code for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1), a too-low minimum version, weak cipher suites, disabled certificate verification (`rejectUnauthorized:false`, `verify=False`, `InsecureSkipVerify`), TLS compression (CRIME), and missing HSTS. An agent calls this when reviewing how an application terminates or initiates TLS connections.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured TLS configuration. |
| `config.min_version` | `enum` | No | Minimum TLS version: `SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`. |
| `config.enabled_versions` | `array` of version `enum` (max 8) | No | Explicitly enabled protocol versions. |
| `config.cipher_suites` | `array` of `string` (1–128 chars, max 128) | No | Enabled cipher suites. |
| `config.verify_certificates` | `boolean` | No | Whether peer certificates are verified. |
| `config.hsts` | `boolean` | No | Whether HSTS is enabled. |
| `config.compression` | `boolean` | No | Whether TLS compression is enabled. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "min_version": "TLSv1.0", "verify_certificates": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "deprecated-tls-version", "severity": "high", "status": "open" },
    { "rule": "certificate-verification-disabled", "severity": "high", "status": "open" }
  ]
}
```

## Detections

- Deprecated protocols — SSLv3, TLS 1.0, TLS 1.1 (CWE-326, CWE-327)
- Minimum TLS version set too low (CWE-326)
- Weak cipher suites (CWE-327)
- Disabled certificate verification — `rejectUnauthorized:false`, `verify=False`, `InsecureSkipVerify` (CWE-295)
- TLS compression enabled — CRIME exposure (CWE-310)
- Missing HSTS (CWE-319)

## Related tools

- [`altais_audit_crypto`](altais_audit_crypto.md) — audits algorithm usage beyond TLS
- [`altais_audit_cert_pinning`](altais_audit_cert_pinning.md) — reviews certificate pinning
- [`altais_audit_acme`](altais_audit_acme.md) — reviews ACME certificate issuance

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
