# `altais_audit_crypto`

Audits cryptographic algorithm usage for weak ciphers, deprecated hashes, ECB mode, and static IVs or salts.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code and/or a structured algorithm inventory for weak cryptographic primitives — broken hashes and ciphers (MD5, SHA-1, DES, 3DES, RC4, Blowfish), ECB block-cipher mode, static IVs and salts, the broken `crypto.createCipher` API, and undersized RSA or symmetric keys. An agent calls this when reviewing encryption, hashing, or signing code, or when verifying that an algorithm inventory uses only modern primitives.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured algorithm inventory. |
| `config.algorithms` | `array` (max 256) | No | Algorithm entries, each `{ name, purpose?, key_size_bits? }`. |
| `config.algorithms[].name` | `string` (1–128 chars) | Yes | Algorithm name. |
| `config.algorithms[].purpose` | `enum` | No | One of `hashing`, `encryption`, `signing`, `key_exchange`, `mac`, `kdf`. |
| `config.algorithms[].key_size_bits` | `integer` (0–65536) | No | Key size in bits. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "crypto.createHash('md5')" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "weak-hash",
      "severity": "high",
      "cwe": ["CWE-327"],
      "title": "Use of a broken cryptographic hash (MD5)",
      "status": "open"
    }
  ]
}
```

## Detections

- Broken/deprecated hashes — MD5, SHA-1 (CWE-327, CWE-328)
- Weak ciphers — DES, 3DES, RC4, Blowfish (CWE-327)
- ECB block-cipher mode (CWE-327)
- Static or hardcoded IVs and salts (CWE-329, CWE-760)
- Use of the broken `crypto.createCipher` API (CWE-327)
- Undersized RSA or symmetric keys (CWE-326)

## Related tools

- [`altais_assess_pq_readiness`](altais_assess_pq_readiness.md) — flags quantum-vulnerable asymmetric primitives
- [`altais_audit_randomness`](altais_audit_randomness.md) — finds non-cryptographic PRNGs
- [`altais_audit_key_mgmt`](altais_audit_key_mgmt.md) — audits key storage and rotation

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
