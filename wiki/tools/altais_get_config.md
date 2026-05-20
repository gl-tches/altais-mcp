# `altais_get_config`

Return the active server configuration and the list of currently loaded modules.

| Property | Value |
|----------|-------|
| Module | [`core`](../modules/core.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reports the running `altais-mcp` instance's server settings (name, transport, port, log level), the full module enable/disable map from `altais.config.toml`, the list of modules actually loaded this session, and the package version. An agent calls this first to verify which security checks are available before deciding which scanning tools to run.

## Input parameters

This tool takes no input parameters.

## Output

A JSON object with:

- `server` — `{ name, transport, port, log_level }`.
- `modules` — the configured module enable/disable map (every module name to a boolean).
- `active_modules` — array of module names actually loaded this session.
- `package_version` — the `altais-mcp` package version string.

## Example

**Request**

```json
{}
```

**Response (excerpt)**

```json
{
  "server": { "name": "altais-mcp", "transport": "stdio", "port": 3100, "log_level": "info" },
  "modules": { "scan": true, "secrets": true, "crypto": false },
  "active_modules": ["core", "scan", "secrets", "headers", "threat_model", "owasp", "supply_chain", "auth"],
  "package_version": "0.1.0"
}
```

## Detections

Not an auditor. Returns the live server configuration and module-load state:

- Server transport, port, and log level.
- Per-module enable flags from the config file.
- The set of modules loaded for the current session.
- The package version.

## Related tools

- [`altais_report`](altais_report.md) — aggregates findings produced by the active modules
- [`altais_risk_summary`](altais_risk_summary.md) — composite risk score for the current session

## See also

- [`core` module](../modules/core.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
