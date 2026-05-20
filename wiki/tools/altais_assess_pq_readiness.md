# `altais_assess_pq_readiness`

Flags quantum-vulnerable cryptographic primitives and assesses harvest-now-decrypt-later exposure.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Flags quantum-vulnerable classical asymmetric primitives (RSA, ECDSA, ECDH, DH, X25519) broken by Shor's algorithm, assesses "harvest now, decrypt later" exposure for long-retention data, and checks for hybrid key exchange and NIST PQC algorithms (ML-KEM, ML-DSA, SLH-DSA). An agent calls this to gauge how prepared a system is for the migration to post-quantum cryptography.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured post-quantum readiness configuration. |
| `config.algorithms` | `array` of `string` (1–128 chars, max 256) | No | Algorithms in use. |
| `config.data_retention_years` | `integer` (0–200) | No | How many years sensitive data must remain confidential. |
| `config.uses_hybrid` | `boolean` | No | Whether hybrid (classical + PQC) key exchange is in use. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "algorithms": ["RSA-2048", "ECDH"], "data_retention_years": 25 } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 1, "high": 1 } },
  "findings": [
    { "rule": "quantum-vulnerable-primitive", "severity": "medium", "status": "open" },
    { "rule": "harvest-now-decrypt-later", "severity": "high", "status": "open" }
  ]
}
```

## Detections

- Quantum-vulnerable asymmetric primitives — RSA, ECDSA, ECDH, DH, X25519 (CWE-327)
- Harvest-now-decrypt-later exposure for long-retention data (CWE-327)
- Missing hybrid key exchange (CWE-327)
- Absence of NIST PQC algorithms — ML-KEM, ML-DSA, SLH-DSA

## Related tools

- [`altais_audit_crypto`](altais_audit_crypto.md) — audits classical algorithm weaknesses
- [`altais_assess_crypto_agility`](altais_assess_crypto_agility.md) — assesses whether primitives can be swapped for PQC without code changes

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
