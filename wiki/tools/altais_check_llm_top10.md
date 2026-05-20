# `altais_check_llm_top10`

Audits an LLM application against the OWASP Top 10 for LLM Applications (2025).

| Property | Value |
|----------|-------|
| Module | [`ml_security`](../modules/ml_security.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an LLM application against the OWASP Top 10 for LLM Applications (2025): LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption. It returns per-category coverage and emits findings for gaps. An agent calls this for a structured LLM Top 10 coverage report.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code to scan for risky patterns. |
| `config` | `object` (strict) | No | Controls in place, keyed to OWASP LLM Top 10 categories. |
| `config.prompt_injection_defenses` | `boolean` | No | Whether prompt-injection defenses exist (LLM01). |
| `config.output_pii_filtering` | `boolean` | No | Whether output is filtered for sensitive data (LLM02). |
| `config.supply_chain_verified` | `boolean` | No | Whether the model / plugin supply chain is verified (LLM03). |
| `config.data_validation` | `boolean` | No | Whether training / RAG data is validated (LLM04). |
| `config.output_sanitization` | `boolean` | No | Whether LLM output is sanitized downstream (LLM05). |
| `config.agency_limited` | `boolean` | No | Whether agent agency is limited (LLM06). |
| `config.system_prompt_protected` | `boolean` | No | Whether the system prompt is protected (LLM07). |
| `config.vector_store_secured` | `boolean` | No | Whether the vector store / RAG inputs are secured (LLM08). |
| `config.grounding_enabled` | `boolean` | No | Whether output is grounded to limit misinformation (LLM09). |
| `config.consumption_limited` | `boolean` | No | Whether token / cost consumption is bounded (LLM10). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, categories: [...], findings: [...] }`. `categories` is a per-LLM-category array of coverage status (e.g. `{ id: "LLM01", status: "needs_review" }`). Findings have the standard shape and are appended to the session report.

## Example

**Request**

```json
{ "config": { "prompt_injection_defenses": false, "agency_limited": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "categories": [ { "id": "LLM01", "status": "needs_review" } ],
  "findings": [ { "rule": "llm01-prompt-injection", "status": "open" } ]
}
```

## Detections

- LLM01 Prompt Injection — no prompt-injection defenses
- LLM02 Sensitive Information Disclosure — output not filtered for sensitive data
- LLM03 Supply Chain — model / plugin supply chain unverified
- LLM04 Data and Model Poisoning — training / RAG data unvalidated
- LLM05 Improper Output Handling — LLM output not sanitized downstream
- LLM06 Excessive Agency — agent agency not limited
- LLM07 System Prompt Leakage — system prompt unprotected
- LLM08 Vector and Embedding Weaknesses — vector store / RAG inputs insecure
- LLM09 Misinformation — output not grounded
- LLM10 Unbounded Consumption — token / cost consumption unbounded

## Related tools

- [`altais_audit_prompt_injection`](altais_audit_prompt_injection.md) — deep-dive on LLM01
- [`altais_audit_agent_permissions`](altais_audit_agent_permissions.md) — deep-dive on LLM06
- [`altais_audit_output_handling`](altais_audit_output_handling.md) — deep-dive on LLM05
- [`altais_check_owasp_ml`](altais_check_owasp_ml.md) — the ML-system equivalent (ML01–ML10)

## See also

- [`ml_security` module](../modules/ml_security.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
