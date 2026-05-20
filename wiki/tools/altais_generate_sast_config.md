# `altais_generate_sast_config`

Generates a ready-to-use static-analysis (SAST) tool configuration.

| Property | Value |
|----------|-------|
| Module | [`testing`](../modules/testing.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Produces a ready-to-use static-analysis configuration for a chosen tool: the config file body (a Semgrep ruleset, a CodeQL config and workflow, a `.bandit`, a `.gosec.json`, an ESLint security config, or a Brakeman config), the recommended rule packs, and a CI invocation snippet. It supports Semgrep, CodeQL, Bandit, gosec, eslint-plugin-security, and Brakeman. An agent calls this when wiring SAST into a project or CI pipeline.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tool` | `enum` | Yes | The static-analysis tool: `semgrep`, `codeql`, `bandit`, `gosec`, `eslint-security`, or `brakeman`. |
| `languages` | `array` of `string` (1–48 chars, 1–40 items) | Yes | The target languages, e.g. `python`, `javascript`. |

## Output

Returns a generated artifact as JSON. It includes the selected `tool`, a `config_file` body (the configuration syntax for the chosen tool), a `rule_packs` list of recommended rule packs, and a `ci_snippet` for invoking the tool in CI. No findings are emitted.

## Example

**Request**

```json
{ "tool": "semgrep", "languages": ["python"] }
```

**Response (excerpt)**

```json
{
  "tool": "semgrep",
  "config_file": "rules:\n  - id: ...\n",
  "rule_packs": ["p/security-audit", "p/python"],
  "ci_snippet": "semgrep --config .semgrep.yml --error"
}
```

## Detections

This is a generator. The artifact is a SAST tool configuration: the config file body for the chosen tool (Semgrep ruleset, CodeQL config + workflow, `.bandit`, `.gosec.json`, ESLint security config, or Brakeman config), the recommended rule packs, and a CI invocation snippet. It supports Semgrep, CodeQL, Bandit, gosec, eslint-plugin-security, and Brakeman.

## Related tools

- [`altais_generate_fuzz_config`](altais_generate_fuzz_config.md) — generates fuzz-testing setups
- [`altais_generate_iast_config`](altais_generate_iast_config.md) — generates IAST setups
- [`altais_generate_security_tests`](altais_generate_security_tests.md) — generates vulnerability-class test cases

## See also

- [`testing` module](../modules/testing.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
