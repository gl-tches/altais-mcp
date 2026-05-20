# `container` module

The `container` module audits container image security: Dockerfile best practices, Docker Compose misconfigurations, and base-image hygiene including version and digest pinning, end-of-life images, and image bloat. Every tool is an auditor that emits CWE-tagged findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `container` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] container` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_dockerfile`](../tools/altais_audit_dockerfile.md) | Analyze a Dockerfile for security best-practice violations. |
| [`altais_audit_compose`](../tools/altais_audit_compose.md) | Review a Docker Compose file for security misconfigurations. |
| [`altais_check_base_image`](../tools/altais_check_base_image.md) | Assess a base-image reference for pinning, end-of-life, and bloat. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `container = true`).

## See also

- [Wiki home](../Home.md)
