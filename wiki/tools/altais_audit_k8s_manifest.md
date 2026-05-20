# `altais_audit_k8s_manifest`

Checks a Kubernetes manifest against the Pod Security Standards.

| Property | Value |
|----------|-------|
| Module | [`iac`](../modules/iac.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a Kubernetes manifest (Pod, Deployment, or similar workload YAML) and checks it against the Pod Security Standards. It flags privileged containers, privilege escalation, root execution, shared host namespaces, dangerous Linux capabilities, missing security contexts and resource limits, auto-mounted service-account tokens, hostPath volumes, writable root filesystems, mutable image tags, and wildcard RBAC. An agent calls it when reviewing workload definitions before they reach a cluster.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the Kubernetes manifest YAML to audit. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "spec:\n  containers:\n  - securityContext:\n      privileged: true\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "k8s-privileged-container", "severity": "high", "title": "Privileged container" }
  ]
}
```

## Detections

- `k8s-privileged-container` — privileged container (CWE-250, CWE-269)
- `k8s-allow-privilege-escalation` — `allowPrivilegeEscalation` not disabled (CWE-250, CWE-269)
- `k8s-run-as-root-explicit` — container explicitly runs as root (CWE-250, CWE-269)
- `k8s-run-as-non-root-false` — `runAsNonRoot: false` (CWE-250, CWE-269)
- `k8s-host-network` / `k8s-host-pid` / `k8s-host-ipc` — shared host namespaces (CWE-668)
- `k8s-dangerous-capability` — dangerous added Linux capabilities (CWE-250, CWE-269)
- `k8s-automount-sa-token` — service-account token auto-mounted (CWE-250, CWE-668)
- `k8s-hostpath-volume` — hostPath volume mounted (CWE-668, CWE-250)
- `k8s-mutable-image-tag` — mutable `:latest` image tag (CWE-1357, CWE-829)
- `k8s-wildcard-rbac` — wildcard RBAC rule (CWE-284, CWE-732)

## Related tools

- [`altais_audit_helm_chart`](altais_audit_helm_chart.md) — audits the Helm charts that render manifests
- [`altais_check_hardening`](altais_check_hardening.md) — CIS-benchmark hardening for `kubernetes`

## See also

- [`iac` module](../modules/iac.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
