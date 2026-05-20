# `altais_audit_inference_api`

Checks a model-serving API for model-extraction and adversarial-evasion risk.

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Checks a model-serving / inference API for model-extraction and adversarial-evasion risk: missing rate limiting (model theft), missing authentication, exposed confidence scores or raw logits (which ease model extraction and inversion), absent input validation (adversarial evasion), and missing abuse monitoring. An agent calls this when reviewing how a model is exposed to callers.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for risky patterns. |
| `config` | `object` (strict) | No | Structured description of the inference API. |
| `config.rate_limited` | `boolean` | No | Whether the prediction endpoint is rate limited. |
| `config.authentication` | `boolean` | No | Whether callers must authenticate. |
| `config.returns_confidence_scores` | `boolean` | No | Whether responses include confidence scores. |
| `config.returns_logits` | `boolean` | No | Whether responses include raw logits. |
| `config.input_validation` | `boolean` | No | Whether inference inputs are validated. |
| `config.batch_endpoint` | `boolean` | No | Whether a batch prediction endpoint is exposed. |
| `config.monitoring` | `boolean` | No | Whether the API has abuse / anomaly monitoring. |
| `config.query_logging` | `boolean` | No | Whether queries are logged for forensics. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "rate_limited": false, "returns_logits": true } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "no-rate-limiting", "severity": "high", "cwe": ["CWE-770"], "title": "Inference endpoint is not rate limited", "status": "open" }
  ]
}
```

## Detections

- Missing rate limiting — model theft (OWASP ML05, CWE-770)
- Missing authentication (CWE-306)
- Exposed confidence scores / raw logits — eases model extraction and inversion
- Absent input validation — adversarial evasion (OWASP ML01)
- Missing abuse / anomaly monitoring

## Related tools

- [`altais_audit_ml_pipeline`](altais_audit_ml_pipeline.md) — audits the training pipeline
- [`altais_audit_model_supply_chain`](altais_audit_model_supply_chain.md) — verifies model provenance
- [`altais_check_owasp_ml`](altais_check_owasp_ml.md) — maps the system to the OWASP ML Top 10

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
