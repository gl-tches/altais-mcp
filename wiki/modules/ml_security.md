# `ml_security` module

ML and LLM application security audits. The module ships eight auditors covering training-pipeline integrity (data poisoning, insecure model deserialization, provenance gaps), inference-API hardening (model extraction, adversarial evasion), model supply-chain provenance, OWASP ML Security Top 10 and OWASP Top 10 for LLM Applications coverage, prompt-injection analysis, agent excessive-agency review, and LLM output-handling. An agent enables this module to review how a system trains, serves, and consumes machine-learning models.

| Property | Value |
|----------|-------|
| Module name | `ml_security` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] ml_security` in `altais.config.toml` |
| Tools | 8 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_ml_pipeline`](../tools/altais_audit_ml_pipeline.md) | Audits an ML training pipeline for data poisoning, insecure model deserialization, and provenance gaps. |
| [`altais_audit_inference_api`](../tools/altais_audit_inference_api.md) | Checks a model-serving API for model-extraction and adversarial-evasion risk. |
| [`altais_audit_model_supply_chain`](../tools/altais_audit_model_supply_chain.md) | Verifies the provenance and integrity of a model artifact. |
| [`altais_check_owasp_ml`](../tools/altais_check_owasp_ml.md) | Checks an ML system against the OWASP ML Security Top 10 (ML01–ML10). |
| [`altais_check_llm_top10`](../tools/altais_check_llm_top10.md) | Audits an LLM application against the OWASP Top 10 for LLM Applications (2025). |
| [`altais_audit_prompt_injection`](../tools/altais_audit_prompt_injection.md) | Analyzes prompt construction for injection vulnerabilities (OWASP LLM01). |
| [`altais_audit_agent_permissions`](../tools/altais_audit_agent_permissions.md) | Checks an LLM agent for excessive agency (OWASP LLM06). |
| [`altais_audit_output_handling`](../tools/altais_audit_output_handling.md) | Verifies LLM output is sanitized before downstream use (OWASP LLM05). |

## Enabling this module

All three of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `agentic` also has an `[agentic]` config section.

```toml
[modules]
ml_security = true
```

## See also

- [Wiki home](../Home.md)
