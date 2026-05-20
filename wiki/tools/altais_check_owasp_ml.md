# `altais_check_owasp_ml`

Checks an ML system against the OWASP Machine Learning Security Top 10 (ML01–ML10).

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Checks an ML system against the OWASP Machine Learning Security Top 10 (ML01 Input Manipulation, ML02 Data Poisoning, ML03 Model Inversion, ML04 Membership Inference, ML05 Model Theft, ML06 AI Supply Chain, ML07 Transfer Learning Attack, ML08 Model Skewing, ML09 Output Integrity, ML10 Model Poisoning). It returns per-category coverage status with detection hints and emits a finding for each category needing review. An agent calls this for a structured ML Top 10 coverage report.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` (strict) | No | Controls in place, keyed to OWASP ML Top 10 categories. |
| `config.input_validation` | `boolean` | No | Whether inference inputs are validated (ML01). |
| `config.data_validation` | `boolean` | No | Whether training data is validated (ML02). |
| `config.inversion_defenses` | `boolean` | No | Whether model-inversion defenses are applied (ML03). |
| `config.membership_inference_defenses` | `boolean` | No | Whether membership-inference defenses are applied (ML04). |
| `config.model_theft_controls` | `boolean` | No | Whether model-theft controls exist (ML05). |
| `config.supply_chain_verified` | `boolean` | No | Whether the AI supply chain is verified (ML06). |
| `config.transfer_learning_reviewed` | `boolean` | No | Whether transfer-learning risk is assessed (ML07). |
| `config.skewing_monitored` | `boolean` | No | Whether model skewing is monitored (ML08). |
| `config.output_integrity_verified` | `boolean` | No | Whether output integrity is verified (ML09). |
| `config.training_access_controlled` | `boolean` | No | Whether the training process is access-controlled (ML10). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, categories: [...], findings: [...] }`. `categories` is a per-ML-category array of coverage status (e.g. `{ id: "ML01", status: "needs_review" }`) with detection hints. Findings have the standard shape and are appended to the session report.

## Example

**Request**

```json
{ "config": { "input_validation": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "categories": [ { "id": "ML01", "status": "needs_review" } ],
  "findings": [ { "rule": "ml01-input-manipulation", "status": "open" } ]
}
```

## Detections

- ML01 Input Manipulation — missing inference input validation
- ML02 Data Poisoning — unvalidated training data
- ML03 Model Inversion — no inversion defenses
- ML04 Membership Inference — no membership-inference defenses
- ML05 Model Theft — no model-theft controls
- ML06 AI Supply Chain — unverified supply chain
- ML07 Transfer Learning Attack — transfer-learning risk not assessed
- ML08 Model Skewing — skewing not monitored
- ML09 Output Integrity — output integrity not verified
- ML10 Model Poisoning — training process not access-controlled

## Related tools

- [`altais_check_llm_top10`](altais_check_llm_top10.md) — the LLM-application equivalent (LLM01–LLM10)
- [`altais_audit_ml_pipeline`](altais_audit_ml_pipeline.md) — audits the training pipeline in detail
- [`altais_audit_inference_api`](altais_audit_inference_api.md) — audits the model-serving API in detail

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
