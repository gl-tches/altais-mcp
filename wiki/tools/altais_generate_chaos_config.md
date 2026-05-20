# `altais_generate_chaos_config`

Generates a security chaos-engineering / fault-injection configuration.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a security chaos-engineering / fault-injection configuration: experiment definitions shaped after Chaos Mesh, LitmusChaos, or AWS Fault Injection Service, each with a steady-state hypothesis, an explicit blast-radius limit, and rollback guidance. It supports network-latency, dependency-failure, credential-expiry, pod-kill, and IAM-revocation experiments. An agent calls this when designing resilience and security-failure-mode testing.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The chaos-engineering configuration. |
| `config.platform` | `enum` | Yes | The platform the experiments run against: `kubernetes`, `aws`, `linux-host`, or `application`. |
| `config.experiments` | `array` of `enum` (1–20 items) | Yes | The fault-injection experiments: `network-latency`, `dependency-failure`, `credential-expiry`, `pod-kill`, and/or `iam-revocation`. |

## Output

Returns a generated artifact as JSON. It includes the target `platform` and an `experiments` array; each experiment carries a `name`, a `steady_state_hypothesis`, an explicit `blast_radius` limit, and `rollback` guidance. No findings are emitted.

## Example

**Request**

```json
{ "config": { "platform": "kubernetes", "experiments": ["pod-kill"] } }
```

**Response (excerpt)**

```json
{
  "platform": "kubernetes",
  "experiments": [
    {
      "name": "pod-kill",
      "steady_state_hypothesis": "Service stays available when one pod is terminated.",
      "blast_radius": "One pod in a single namespace.",
      "rollback": "Halt the experiment and let the ReplicaSet reschedule."
    }
  ]
}
```

## Detections

This is a generator. The artifact is a security chaos-engineering configuration: experiment definitions shaped after Chaos Mesh, LitmusChaos, or AWS Fault Injection Service, each with a steady-state hypothesis, an explicit blast-radius limit, and rollback guidance — covering network latency, dependency failure, credential expiry, pod kill, and IAM revocation.

## Related tools

- [`altais_generate_pentest_scope`](altais_generate_pentest_scope.md) — generates penetration-test scopes
- [`altais_scope_red_team`](altais_scope_red_team.md) — scopes adversary-simulation engagements
- [`altais_generate_security_tests`](altais_generate_security_tests.md) — generates vulnerability-class test cases

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
