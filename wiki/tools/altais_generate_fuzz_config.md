# `altais_generate_fuzz_config`

Generates a fuzz-testing setup — harness skeleton, runner script, sanitizer recommendation, and corpus guidance.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a fuzz-testing setup for a chosen language and fuzzing engine: a fuzz harness skeleton, a runner script, a sanitizer recommendation (ASan / UBSan / MSan or the language equivalent), and corpus / seed and dictionary guidance. It supports libFuzzer, AFL++, cargo-fuzz, Go native fuzzing, Atheris, Jazzer, and jsfuzz. The tool generates static text only — it does not compile or run the harness. An agent calls this when adding fuzzing to a project.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `language` | `enum` | Yes | The language of the code being fuzzed: `c`, `cpp`, `rust`, `go`, `python`, `javascript`, or `java`. |
| `fuzzer` | `enum` | No | The fuzzing engine: `libfuzzer`, `afl++`, `cargo-fuzz`, `go-fuzz`, `atheris`, `jazzer`, or `jsfuzz`. Defaults to the idiomatic engine for the language. |
| `target_function` | `string` (1–128 chars) | No | Name of the function under test, used in the generated harness. Must be a plain identifier. |

## Output

Returns a generated artifact as JSON. It includes the selected `fuzzer`, a `harness` skeleton, a `runner_script`, a `sanitizers` list (the recommended sanitizer set for the language), and `corpus_guidance` covering seed corpus and dictionary setup. No findings are emitted.

## Example

**Request**

```json
{ "language": "rust", "fuzzer": "cargo-fuzz", "target_function": "parse_header" }
```

**Response (excerpt)**

```json
{
  "fuzzer": "cargo-fuzz",
  "harness": "fuzz_target!(|data: &[u8]| { let _ = parse_header(data); });",
  "sanitizers": ["AddressSanitizer"],
  "corpus_guidance": "Seed the corpus with valid header samples."
}
```

## Detections

This is a generator. The artifact is a fuzz-testing setup: a harness skeleton, a runner script, a sanitizer recommendation (ASan / UBSan / MSan or the language equivalent), and corpus / seed and dictionary guidance. It supports libFuzzer, AFL++, cargo-fuzz, Go native fuzzing, Atheris, Jazzer, and jsfuzz. It does not compile or run the harness.

## Related tools

- [`altais_generate_sast_config`](altais_generate_sast_config.md) — generates static-analysis tool configs
- [`altais_generate_security_tests`](altais_generate_security_tests.md) — generates vulnerability-class test cases
- [`altais_generate_iast_config`](altais_generate_iast_config.md) — generates IAST setups for interpreted languages

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
