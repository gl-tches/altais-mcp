# `testing` module

The `testing` module is a set of seven generators for security-testing artifacts: fuzz-testing configuration, SAST tool configuration, penetration-test scoping, security-focused test cases, security chaos-engineering configuration, red-team engagement scoping, and IAST setup. Every tool parses a request and returns a generated configuration, scope, or artifact as JSON — none of these tools analyze code or push findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `testing` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] testing` in `altais.config.toml` |
| Tools | 7 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_generate_fuzz_config`](../tools/altais_generate_fuzz_config.md) | Generates a fuzz-testing setup — harness skeleton, runner, sanitizer recommendation, and corpus guidance. |
| [`altais_generate_sast_config`](../tools/altais_generate_sast_config.md) | Generates a ready-to-use static-analysis (SAST) tool configuration. |
| [`altais_generate_pentest_scope`](../tools/altais_generate_pentest_scope.md) | Generates a penetration-test scoping document. |
| [`altais_generate_security_tests`](../tools/altais_generate_security_tests.md) | Generates security-focused test cases for a vulnerability class. |
| [`altais_generate_chaos_config`](../tools/altais_generate_chaos_config.md) | Generates a security chaos-engineering / fault-injection configuration. |
| [`altais_scope_red_team`](../tools/altais_scope_red_team.md) | Generates a red-team / adversary-simulation engagement scope. |
| [`altais_generate_iast_config`](../tools/altais_generate_iast_config.md) | Generates an Interactive Application Security Testing (IAST) setup. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `testing = true`).

## See also

- [Wiki home](../Home.md)
