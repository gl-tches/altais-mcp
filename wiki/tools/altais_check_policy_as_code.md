# `altais_check_policy_as_code`

Validates an OPA/Rego or Kyverno policy-as-code file.

| Property | Value |
|----------|-------|
| Module | [`iac`](../modules/iac.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool validates a policy-as-code file in either OPA/Rego or Kyverno form. For Rego it flags insecure `default allow = true`, policies with no `deny` / `violation` rules, and `http.send` network calls in the decision path. For Kyverno it flags `validationFailureAction: Audit`, disabled background scanning, policies with no `validate` / `deny` rules, and rules with no `match` selector. An agent calls it when reviewing the policies that gate infrastructure changes.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | `string` (1–524288 chars) | Yes | Full text of the policy file to validate. |
| `policy_type` | `string` enum: `rego` \| `kyverno` | Yes | The policy language: `rego` for OPA/Rego, `kyverno` for Kyverno YAML. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "content": "package authz\ndefault allow = true\n", "policy_type": "rego" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "rego-default-allow", "severity": "high", "title": "Insecure default allow" }
  ]
}
```

## Detections

- `rego-default-allow` — insecure `default allow = true` (CWE-1188, CWE-284)
- `rego-no-deny-rules` — Rego policy with no `deny` / `violation` rules (CWE-1188, CWE-284)
- `rego-http-send` — `http.send` network call in the decision path (CWE-829, CWE-16)
- `kyverno-audit-action` — `validationFailureAction: Audit` instead of `Enforce` (CWE-1188, CWE-16)
- `kyverno-background-disabled` — background scanning disabled (CWE-778, CWE-16)
- `kyverno-no-validate-rules` — Kyverno policy with no `validate` / `deny` rules (CWE-1188, CWE-284)
- `kyverno-missing-match` — rule with no `match` selector (CWE-284, CWE-16)

## Related tools

- [`altais_audit_k8s_manifest`](altais_audit_k8s_manifest.md) — audits the manifests these policies govern
- [`altais_audit_terraform`](altais_audit_terraform.md) — audits the Terraform these policies gate

## See also

- [`iac` module](../modules/iac.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
