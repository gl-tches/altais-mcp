# `scan` module

The `scan` module performs static analysis security scanning of source code across TypeScript, JavaScript, Python, Go, and Rust. It applies a pattern engine that detects 15 vulnerability classes — from injection and XSS to ReDoS and request smuggling — by reading code as text, never executing it. Findings flow into the shared session report.

| Property | Value |
|----------|-------|
| Module name | `scan` |
| Status | Default-enabled |
| Config key | `[modules] scan` in `altais.config.toml` |
| Tools | 3 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_scan_code`](../tools/altais_scan_code.md) | Run security pattern detection against inline source code. |
| [`altais_scan_file`](../tools/altais_scan_file.md) | Read a file from disk (within `scan_root`) and run the scan patterns against it. |
| [`altais_scan_diff`](../tools/altais_scan_diff.md) | Parse a unified diff and scan the touched hunks, reporting only added-line findings. |

## Enabling this module

The `scan` module is one of the seven default-enabled modules, so it is active out of the box. To disable it, set `scan = false` under `[modules]` in `altais.config.toml`. The default-enabled set is `scan`, `threat_model`, `owasp`, `secrets`, `headers`, `supply_chain`, and `auth`; `core` is always loaded; all other modules are opt-in.

## See also

- [Wiki home](../Home.md)
