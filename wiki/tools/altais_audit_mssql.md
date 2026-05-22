# `altais_audit_mssql`

Audits a Microsoft SQL Server configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied Microsoft SQL Server configuration object for the sa account, code-execution surfaces, linked servers, transport encryption, the application login's privileges, and contained databases. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known SQL Server settings (`sa` account, `xp_cmdshell`, CLR integration, OLE Automation, linked servers, Force Encryption, application-login role, contained databases). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- The `sa` account enabled (CWE-1392); `xp_cmdshell` enabled — OS command execution (CWE-78).
- CLR integration and OLE Automation procedures enabled (CWE-78); linked servers with saved credentials (CWE-522).
- Force Encryption disabled (CWE-319); the application login in the sysadmin role (CWE-250); contained databases (CWE-284).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
