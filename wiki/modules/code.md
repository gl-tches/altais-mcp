# `code` module

The `code` module reviews source-code security: CERT secure-coding standards, Rust `unsafe` soundness, sensitive-information leakage in error handling, input-validation coverage, and memory-safety defects in C, C++, and Rust. Every tool is an auditor that emits CWE-tagged findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `code` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] code` in `altais.config.toml` |
| Tools | 5 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_review_secure_coding`](../tools/altais_review_secure_coding.md) | Review source against CERT secure-coding guidance. |
| [`altais_audit_unsafe`](../tools/altais_audit_unsafe.md) | Audit Rust `unsafe` blocks and functions for soundness. |
| [`altais_check_error_handling`](../tools/altais_check_error_handling.md) | Detect error handling that leaks sensitive information or hides failures. |
| [`altais_check_input_validation`](../tools/altais_check_input_validation.md) | Verify that request and external input is validated before use. |
| [`altais_check_memory_safety`](../tools/altais_check_memory_safety.md) | Detect memory-safety defects in C / C++ / Rust. |

## Enabling this module

All four of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml` (e.g. `code = true`).

## See also

- [Wiki home](../Home.md)
