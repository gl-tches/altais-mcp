# `altais_assess_crypto_agility`

Assesses whether a system can swap a cryptographic primitive without code changes.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Assesses whether the system can swap a cryptographic primitive without code changes. It flags algorithm names hardcoded across the codebase, ciphertext with no version identifier (which blocks data migration), the absence of an abstraction layer, the absence of a cryptographic inventory (CBOM), and rotation that requires a redeploy. An agent calls this when evaluating readiness for algorithm migration, including the move to post-quantum cryptography.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | No | Source code to scan with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured crypto-agility configuration. |
| `config.algorithm_from_config` | `boolean` | No | Whether the algorithm choice is read from configuration. |
| `config.versioned_ciphertext` | `boolean` | No | Whether ciphertext carries a version identifier. |
| `config.abstraction_layer` | `boolean` | No | Whether crypto calls go through an abstraction layer. |
| `config.inventory_exists` | `boolean` | No | Whether a cryptographic inventory (CBOM) exists. |
| `config.rotation_without_redeploy` | `boolean` | No | Whether primitives can be rotated without a redeploy. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "versioned_ciphertext": false, "abstraction_layer": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 2 } },
  "findings": [
    { "rule": "unversioned-ciphertext", "severity": "medium", "status": "open" },
    { "rule": "no-crypto-abstraction", "severity": "medium", "status": "open" }
  ]
}
```

## Detections

- Algorithm names hardcoded across the codebase (CWE-1395)
- Ciphertext with no version identifier — blocks data migration (CWE-757)
- No cryptographic abstraction layer (CWE-757)
- No cryptographic inventory / CBOM (CWE-1059)
- Rotation that requires a redeploy (CWE-757)

## Related tools

- [`altais_assess_pq_readiness`](altais_assess_pq_readiness.md) — flags quantum-vulnerable primitives
- [`altais_audit_crypto`](altais_audit_crypto.md) — audits algorithm usage
- [`altais_audit_key_mgmt`](altais_audit_key_mgmt.md) — audits key storage and rotation

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
