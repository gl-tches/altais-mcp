# `altais_generate_iast_config`

Generates an Interactive Application Security Testing (IAST) setup.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces an Interactive Application Security Testing (IAST) setup: agent setup steps, an instrumentation configuration, a CI/CD integration workflow, and coverage guidance. It supports Contrast, Seeker, Dynatrace, and open-source IAST. It flags that IAST is not applicable to natively compiled languages (C, C++, Rust) and recommends DAST plus fuzzing instead. An agent calls this when adding runtime interactive testing to an application.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool` | `enum` | Yes | The IAST product: `contrast`, `seeker`, `dynatrace`, or `open-source`. |
| `language` | `enum` | Yes | The language of the application being instrumented: `c`, `cpp`, `rust`, `go`, `python`, `javascript`, or `java`. |
| `framework` | `string` (1–48 chars) | No | The application framework, e.g. `spring-boot`, `django`, `express`. Must be a short identifier. |

## Output

Returns a generated artifact as JSON. It includes the selected `tool`, an `agent_setup` list of setup steps, an `instrumentation_config`, a `ci_workflow` for CI/CD integration, and `coverage_guidance`. When the language is natively compiled (C, C++, Rust), the artifact notes IAST is not applicable and recommends DAST plus fuzzing instead. No findings are emitted.

## Example

**Request**

```json
{ "tool": "contrast", "language": "java", "framework": "spring-boot" }
```

**Response (excerpt)**

```json
{
  "tool": "contrast",
  "agent_setup": ["Add the Contrast Java agent to the JVM launch args."],
  "instrumentation_config": "contrast.yaml: ...",
  "ci_workflow": "Run integration tests with the agent attached.",
  "coverage_guidance": "Exercise every route to maximize sink coverage."
}
```

## Detections

This is a generator. The artifact is an IAST setup: agent setup steps, an instrumentation configuration, a CI/CD integration workflow, and coverage guidance — for Contrast, Seeker, Dynatrace, or open-source IAST. For natively compiled languages (C, C++, Rust) it flags that IAST does not apply and recommends DAST plus fuzzing.

## Related tools

- [`altais_generate_fuzz_config`](altais_generate_fuzz_config.md) — generates fuzz-testing setups (recommended for compiled languages)
- [`altais_generate_sast_config`](altais_generate_sast_config.md) — generates static-analysis tool configs
- [`altais_generate_security_tests`](altais_generate_security_tests.md) — generates vulnerability-class test cases

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
