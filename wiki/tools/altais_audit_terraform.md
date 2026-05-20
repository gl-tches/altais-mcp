# `altais_audit_terraform`

Scans Terraform HCL for security misconfigurations.

| Property | Value |
|----------|-------|
| Module | [`iac`](../modules/iac.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reads Terraform HCL configuration as text and applies pattern matching to flag insecure cloud resource definitions. It detects security-group ingress open to the world, public object storage, unencrypted resources, hardcoded provider credentials, IAM wildcards, publicly reachable databases, and disabled audit logging. An agent calls it when reviewing Terraform before a `plan` or `apply`, or when auditing existing infrastructure code.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the Terraform HCL file to audit. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "resource \"aws_security_group_rule\" \"x\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n  from_port   = 22\n}" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "critical": 1 } },
  "findings": [
    { "rule": "tf-world-open-admin-port", "severity": "critical", "title": "SSH/RDP port open to 0.0.0.0/0" }
  ]
}
```

## Detections

- `tf-world-open-admin-port` — ingress from `0.0.0.0/0` to SSH (22) / RDP (3389) (CWE-284, CWE-668)
- `tf-world-open-ingress` — ingress rule using the `0.0.0.0/0` CIDR (CWE-284, CWE-668)
- `tf-public-storage-acl` — `public-read` ACL on object storage (CWE-732, CWE-284)
- `tf-public-access-block-disabled` — disabled public-access blocking (CWE-732, CWE-284)
- `tf-unencrypted-resource` — resource with encryption disabled (CWE-311, CWE-312)
- `tf-publicly-accessible-db` — database reachable from the public internet (CWE-284, CWE-668)
- `tf-hardcoded-secret` — hardcoded secret in HCL (CWE-798, CWE-312)
- `tf-plaintext-provider-credential` — plaintext provider credentials (CWE-798, CWE-312)
- `tf-iam-wildcard` — IAM `*` action / resource wildcard (CWE-284, CWE-732)
- `tf-logging-disabled` — disabled audit logging (CWE-778, CWE-16)

## Related tools

- [`altais_audit_k8s_manifest`](altais_audit_k8s_manifest.md) — audits the Kubernetes manifests Terraform may deploy
- [`altais_check_policy_as_code`](altais_check_policy_as_code.md) — validates the OPA/Kyverno policies that gate Terraform

## See also

- [`iac` module](../modules/iac.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
