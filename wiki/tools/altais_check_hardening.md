# `altais_check_hardening`

Checks a system's settings against CIS-benchmark-style controls.

| Property | Value |
|----------|-------|
| Module | [`infra`](../modules/infra.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool checks a system's observed settings against a curated set of high-value CIS-Benchmark-style controls for the chosen platform. It flags every control whose settings show non-compliance or that the supplied settings do not report. An agent calls it when reviewing host, container, cluster, or cloud-account hardening.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `platform` | `string` enum: `linux` \| `windows` \| `docker` \| `kubernetes` \| `aws` \| `gcp` \| `azure` | Yes | The platform whose CIS-style hardening controls should be checked. |
| `settings` | `object` (record) | Yes | Map of hardening-relevant setting keys (1–128 chars) to observed values. |

Each value in `settings` is a `boolean`, a `number`, or a `string` (max 512 chars).

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "platform": "linux", "settings": { "ssh_root_login": "yes", "firewall_enabled": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "cis-linux-ssh-root-login", "severity": "high", "title": "SSH root login enabled" }
  ]
}
```

## Detections

The control set is platform-specific. Representative checks include:

- **linux** — `cis-linux-ssh-root-login`, `cis-linux-ssh-password-auth`, `cis-linux-automatic-updates`, `cis-linux-audit-daemon`, `cis-linux-firewall`, `cis-linux-world-writable-files` (CWE-250, CWE-287, CWE-308, CWE-778, CWE-1008, CWE-1104, CWE-732)
- **windows** — `cis-windows-smbv1`, `cis-windows-disk-encryption`, `cis-windows-firewall`, `cis-windows-automatic-updates`, `cis-windows-uac` (CWE-311, CWE-250, CWE-1008, CWE-1104)
- **docker** — `cis-docker-privileged`, `cis-docker-userns-remap`, `cis-docker-host-mounts`, `cis-docker-content-trust`, `cis-docker-live-restore` (CWE-250, CWE-269, CWE-668, CWE-494, CWE-1188)
- **kubernetes** — `cis-k8s-anonymous-auth`, `cis-k8s-rbac`, `cis-k8s-audit-logging`, `cis-k8s-privileged-pods`, `cis-k8s-network-policy` (CWE-306, CWE-284, CWE-285, CWE-778, CWE-1008)
- **aws** — `cis-aws-root-mfa`, `cis-aws-cloudtrail`, `cis-aws-s3-public-access`, `cis-aws-default-vpc`, `cis-aws-password-policy` (CWE-308, CWE-778, CWE-284, CWE-1008, CWE-521)
- **gcp** — `cis-gcp-audit-logging`, `cis-gcp-sa-keys`, `cis-gcp-os-login`, `cis-gcp-default-network`, `cis-gcp-bucket-uniform-access` (CWE-778, CWE-798, CWE-321, CWE-284, CWE-1008)
- **azure** — `cis-azure-mfa`, `cis-azure-security-defaults`, `cis-azure-secure-transfer`, `cis-azure-activity-log`, `cis-azure-network-watcher` (CWE-308, CWE-1188, CWE-319, CWE-778)

## Related tools

- [`altais_audit_network`](altais_audit_network.md) — host firewall and segmentation review
- [`altais_check_zero_trust`](altais_check_zero_trust.md) — zero-trust architecture maturity

## See also

- [`infra` module](../modules/infra.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
