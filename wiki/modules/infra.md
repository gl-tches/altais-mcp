# `infra` module

The `infra` module provides infrastructure security audits. It reviews network segmentation and firewall rules, checks DNS zone configurations, assesses architectures against the NIST SP 800-207 zero-trust tenets, and checks platform settings against CIS-Benchmark-style controls. Every tool is a static analyzer that emits findings into the session report.

| Property | Value |
|----------|-------|
| Module name | `infra` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] infra` in `altais.config.toml` |
| Tools | 4 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_network`](../tools/altais_audit_network.md) | Review a network configuration for segmentation and firewall weaknesses. |
| [`altais_audit_dns`](../tools/altais_audit_dns.md) | Check a DNS zone configuration for security weaknesses. |
| [`altais_check_zero_trust`](../tools/altais_check_zero_trust.md) | Assess an architecture against the NIST SP 800-207 zero-trust tenets. |
| [`altais_check_hardening`](../tools/altais_check_hardening.md) | Check a system's settings against CIS-Benchmark-style controls. |

## Enabling this module

All five of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `iac` also has an `[iac]` config section, and `compliance` has a `[compliance]` section.

## See also

- [Wiki home](../Home.md)
