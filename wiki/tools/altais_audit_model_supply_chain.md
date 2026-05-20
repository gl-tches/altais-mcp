# `altais_audit_model_supply_chain`

Verifies the provenance and integrity of a model artifact.

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Verifies the provenance and integrity of a model artifact: `pickle`-format models (insecure deserialization), unsigned models, missing checksum or revision pinning, models from untrusted or external sources, and artifacts not scanned for malicious payloads. An agent calls this when reviewing a model pulled from a hub or registry before it is loaded.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` (strict) | Yes | Structured description of the model artifact and its provenance. |
| `config.source` | `string` (1–256 chars) | No | Where the model artifact comes from. |
| `config.format` | `string` (1–64 chars) | No | The model artifact format (e.g. `pickle`, `safetensors`). |
| `config.signed` | `boolean` | No | Whether the artifact is cryptographically signed. |
| `config.checksum_verified` | `boolean` | No | Whether the artifact checksum is verified. |
| `config.scanned_for_malware` | `boolean` | No | Whether the artifact is scanned for malicious payloads. |
| `config.pinned_revision` | `boolean` | No | Whether an immutable revision is pinned. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "format": "pickle", "signed": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 2 } },
  "findings": [
    { "rule": "pickle-format-model", "severity": "high", "cwe": ["CWE-502"], "title": "Model is in pickle format", "status": "open" }
  ]
}
```

## Detections

- `pickle`-format model — insecure deserialization (CWE-502)
- Unsigned model (CWE-347)
- Missing checksum or revision pinning (CWE-1357)
- Model from an untrusted or external source (OWASP ML06)
- Artifact not scanned for malicious payloads

## Related tools

- [`altais_audit_ml_pipeline`](altais_audit_ml_pipeline.md) — audits the training pipeline that produced the model
- [`altais_check_owasp_ml`](altais_check_owasp_ml.md) — maps the system to the OWASP ML Top 10

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
