# `altais_generate_security_tests`

Generates security-focused test cases for a chosen vulnerability class.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces security-focused test cases for a vulnerability class — injection, XSS, auth, access control, SSRF, CSRF, crypto, or business logic. It returns runnable-shaped test code with both positive cases (benign input is accepted) and negative cases (malicious input is rejected), so the suite asserts the vulnerability is mitigated. It supports Python, JavaScript, Go, Rust, Java, and C/C++. An agent calls this when adding regression coverage for a specific weakness.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vulnerability_class` | `enum` | Yes | The vulnerability class the tests assert is mitigated: `injection`, `xss`, `auth`, `access-control`, `ssrf`, `csrf`, `crypto`, or `business-logic`. |
| `language` | `enum` | Yes | The language of the test code: `c`, `cpp`, `rust`, `go`, `python`, `javascript`, or `java`. |
| `framework` | `string` (1–48 chars) | No | The test framework, e.g. `jest`, `pytest`, `go-test`. Must be a short identifier. |

## Output

Returns a generated artifact as JSON. It includes the resolved `framework`, the `test_code` (runnable-shaped test source), a `positive_cases` list (benign input accepted), and a `negative_cases` list (malicious input rejected). No findings are emitted.

## Example

**Request**

```json
{ "vulnerability_class": "xss", "language": "javascript", "framework": "jest" }
```

**Response (excerpt)**

```json
{
  "framework": "jest",
  "test_code": "test('rejects script payload', () => { ... });",
  "positive_cases": ["plain text is rendered unchanged"],
  "negative_cases": ["<script> payload is neutralized"]
}
```

## Detections

This is a generator. The artifact is security-focused test code for one vulnerability class (injection, XSS, auth, access control, SSRF, CSRF, crypto, or business logic), with both positive cases (benign input accepted) and negative cases (malicious input rejected). It supports Python, JavaScript, Go, Rust, Java, and C/C++.

## Related tools

- [`altais_generate_fuzz_config`](altais_generate_fuzz_config.md) — generates fuzz-testing setups
- [`altais_generate_sast_config`](altais_generate_sast_config.md) — generates static-analysis tool configs
- [`altais_generate_pentest_scope`](altais_generate_pentest_scope.md) — generates penetration-test scopes

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
