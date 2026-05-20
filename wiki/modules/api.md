# `api` module

The `api` module provides API-layer security audits. It validates JSON OpenAPI 3.x specifications for security gaps, reviews rate-limiting configurations for coverage gaps, and reviews API gateway configurations for edge-hardening weaknesses. Every tool is a static analyzer that emits findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `api` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] api` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_openapi_spec`](../tools/altais_audit_openapi_spec.md) | Validate a JSON OpenAPI 3.x specification for security gaps. |
| [`altais_audit_rate_limiting`](../tools/altais_audit_rate_limiting.md) | Check a rate-limiting configuration for coverage gaps. |
| [`altais_audit_api_gateway`](../tools/altais_audit_api_gateway.md) | Review an API gateway's security configuration. |

## Enabling this module

All five of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `iac` also has an `[iac]` config section, and `compliance` has a `[compliance]` section.

## See also

- [Wiki home](../Home.md)
