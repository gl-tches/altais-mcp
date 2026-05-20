# `altais_recommend_rasp`

Recommends a Runtime Application Self-Protection (RASP) configuration for an application's stack.

| Property | Value |
|----------|-------|
| Module | [`runtime`](../modules/runtime.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a Runtime Application Self-Protection recommendation for an application's language, framework, deployment model, and risk tolerance. It returns the RASP product category to evaluate, the protections to enable (unsafe deserialization, OS command injection, SQL injection, path traversal, SSRF) each with a block-vs-monitor recommendation, stack-specific instrumentation and agent setup steps, blocking-vs-monitoring guidance keyed to risk tolerance, and deployment-specific performance considerations. An agent calls this when planning in-process runtime defense.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The RASP recommendation configuration. |
| `config.language` | `enum` | Yes | Primary application language — drives the instrumentation mechanism: `java`, `dotnet`, `node`, `python`, `ruby`, or `go`. |
| `config.framework` | `string` (1–128 chars) | Yes | Application framework, e.g. `spring-boot`, `express`, `django`. |
| `config.deployment` | `enum` | Yes | Deployment model — drives agent packaging and performance guidance: `container`, `vm`, or `serverless`. |
| `config.risk_tolerance` | `enum` | Yes | Team risk tolerance: `low` favors aggressive blocking, `high` favors monitor-first. Accepts `low`, `medium`, or `high`. |

## Output

Returns a generated artifact as JSON. It includes the `product_category` to evaluate, a `protections` array (each with a `name` and a `block`-vs-`monitor` `mode`), an `instrumentation_steps` list of stack-specific agent setup steps, and `performance_considerations` keyed to the deployment model. Blocking-vs-monitoring defaults are keyed to the risk tolerance. No findings are emitted.

## Example

**Request**

```json
{ "config": { "language": "java", "framework": "spring-boot", "deployment": "container", "risk_tolerance": "medium" } }
```

**Response (excerpt)**

```json
{
  "product_category": "JVM bytecode-instrumentation RASP agent",
  "protections": [{ "name": "sql-injection", "mode": "block" }],
  "instrumentation_steps": ["Attach the RASP agent via -javaagent in the container entrypoint."],
  "performance_considerations": ["Pre-warm the agent to avoid cold-start latency."]
}
```

## Detections

This is a generator. The artifact is a RASP recommendation: the product category to evaluate, the protections to enable (unsafe deserialization, OS command injection, SQL injection, path traversal, SSRF) each with a block-vs-monitor recommendation, stack-specific instrumentation and agent setup steps, blocking-vs-monitoring guidance keyed to risk tolerance, and deployment-specific performance considerations.

## Related tools

- [`altais_generate_waf_rules`](altais_generate_waf_rules.md) — generates edge WAF rules
- [`altais_audit_monitoring`](altais_audit_monitoring.md) — audits monitoring and alerting coverage
- [`altais_recommend_siem`](altais_recommend_siem.md) — recommends SIEM detections for runtime events

## See also

- [`runtime` module](../modules/runtime.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
