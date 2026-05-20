# `iac` module

The `iac` module provides infrastructure-as-code security audits. It scans Terraform HCL for misconfigurations, checks Kubernetes manifests against the Pod Security Standards, reviews Helm charts for insecure defaults, and validates OPA/Rego and Kyverno policy-as-code files. Every tool is a static analyzer that reads configuration as text — it never executes or applies any infrastructure.

| Property | Value |
|----------|-------|
| Module name | `iac` |
| Status | Opt-in (disabled by default) |
| Config key | `[modules] iac` in `altais.config.toml` |
| Tools | 4 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_terraform`](../tools/altais_audit_terraform.md) | Scan Terraform HCL for security misconfigurations — world-open ingress, public storage, unencrypted resources, hardcoded secrets, IAM wildcards. |
| [`altais_audit_k8s_manifest`](../tools/altais_audit_k8s_manifest.md) | Check a Kubernetes manifest against the Pod Security Standards. |
| [`altais_audit_helm_chart`](../tools/altais_audit_helm_chart.md) | Review a Helm chart's `values.yaml` (optionally with templates) for insecure defaults. |
| [`altais_check_policy_as_code`](../tools/altais_check_policy_as_code.md) | Validate an OPA/Rego or Kyverno policy. |

## Enabling this module

All five of these modules are opt-in. Enable one by setting its key to `true` under `[modules]` in `altais.config.toml`. Note `iac` also has an `[iac]` config section, and `compliance` has a `[compliance]` section.

## See also

- [Wiki home](../Home.md)
