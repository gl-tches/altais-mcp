# `altais_audit_ml_pipeline`

Audits an ML training pipeline for data poisoning, insecure model deserialization, and provenance gaps.

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits a machine-learning training pipeline for data poisoning (untrusted or unvalidated training data), insecure deserialization of model files (`pickle.load`, `joblib.load`, `torch.load` without `weights_only=True`), unsigned models, secrets baked into notebooks, unpinned dependencies, and missing data lineage or provenance. An agent calls this when reviewing how a model is trained and packaged.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for risky patterns. |
| `config` | `object` (strict) | No | Structured description of the training pipeline. |
| `config.training_data_source` | `string` (1–256 chars) | No | Where the training data comes from. |
| `config.data_validation` | `boolean` | No | Whether training data is validated before use. |
| `config.data_provenance_tracked` | `boolean` | No | Whether data provenance is tracked. |
| `config.model_format` | `string` (1–64 chars) | No | The serialized model format (e.g. `pickle`, `safetensors`). |
| `config.model_signed` | `boolean` | No | Whether the model artifact is signed. |
| `config.pinned_dependencies` | `boolean` | No | Whether dependencies are pinned to exact versions. |
| `config.secrets_in_notebooks` | `boolean` | No | Whether secrets appear in notebooks. |
| `config.lineage_tracked` | `boolean` | No | Whether data and model lineage is tracked. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "model = torch.load('m.pt')" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "insecure-model-deserialization", "severity": "high", "cwe": ["CWE-502"], "title": "Insecure deserialization of a model file", "status": "open" }
  ]
}
```

## Detections

- Data poisoning — untrusted or unvalidated training data (CWE-1395)
- Insecure model deserialization — `pickle.load`, `joblib.load`, `torch.load` without `weights_only=True` (CWE-502)
- Unsigned model artifact
- Secrets baked into notebooks (CWE-798)
- Unpinned dependencies
- Missing data lineage / provenance

## Related tools

- [`altais_audit_model_supply_chain`](altais_audit_model_supply_chain.md) — verifies a model artifact's provenance and integrity
- [`altais_check_owasp_ml`](altais_check_owasp_ml.md) — maps the system to the OWASP ML Top 10
- [`altais_audit_inference_api`](altais_audit_inference_api.md) — audits the model-serving API

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
