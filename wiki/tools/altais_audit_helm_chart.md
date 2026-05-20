# `altais_audit_helm_chart`

Reviews a Helm chart's `values.yaml` for insecure defaults.

| Property | Value |
|----------|-------|
| Module | [`iac`](../modules/iac.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews a Helm chart's `values.yaml` (optionally with concatenated templates) for insecure defaults that ship to every install. It flags privileged pods, empty or `latest` image tags, publicly exposing service types, disabled RBAC creation, disabled security contexts, hardcoded passwords, and secrets passed via `--set` or rendered into ConfigMaps. An agent calls it when reviewing a chart before packaging or deployment.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the chart (`values.yaml`, optionally with templates). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "image:\n  tag: latest\nrbac:\n  create: false\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "medium": 1, "high": 1 } },
  "findings": [
    { "rule": "helm-rbac-disabled", "severity": "high", "title": "RBAC creation disabled" }
  ]
}
```

## Detections

- `helm-privileged-default` — privileged pods enabled by default (CWE-250, CWE-269)
- `helm-rbac-disabled` — RBAC creation disabled (CWE-284, CWE-16)
- `helm-loadbalancer-service` — `LoadBalancer` / `NodePort` service publicly exposes the workload (CWE-668, CWE-284)
- `helm-security-context-disabled` — security context disabled (CWE-250, CWE-16)
- `helm-set-secret` — secrets passed via `--set` or rendered into a ConfigMap; also covers default / hardcoded passwords (CWE-798, CWE-532)

## Related tools

- [`altais_audit_k8s_manifest`](altais_audit_k8s_manifest.md) — audits the rendered Kubernetes manifests
- [`altais_audit_terraform`](altais_audit_terraform.md) — audits the Terraform that may provision the cluster

## See also

- [`iac` module](../modules/iac.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
