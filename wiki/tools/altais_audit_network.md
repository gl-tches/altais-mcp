# `altais_audit_network`

Reviews a network configuration for segmentation and firewall weaknesses.

| Property | Value |
|----------|-------|
| Module | [`infra`](../modules/infra.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool reviews a structured network configuration — firewall / security-group rules plus topology metadata — for segmentation and firewall weaknesses. It flags ingress `allow` rules from any source (especially to admin and database ports), unconstrained `allow any any` rules, a flat topology with no zones or segments, unrestricted egress, and rule sets with no default-deny. An agent calls it when reviewing firewall rules or network design.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | The network configuration to audit (see below). |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

The `config` object accepts these optional fields:

| Field | Type | Description |
|-------|------|-------------|
| `firewall_rules` | `array` (max 2000) of rule objects | The firewall / security-group rule set to review. |
| `zones` | `string[]` (each 1–128 chars, max 256) | Named network zones / trust tiers. |
| `segments` | `string[]` (each 1–128 chars, max 256) | Named network segments / subnets. |
| `egress_filtering` | `boolean` | Whether outbound traffic is filtered against an allow-list. |

Each entry in `firewall_rules` is an object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `direction` | enum: `ingress` \| `egress` | Yes | Traffic direction the rule governs. |
| `source` | `string` (1–256 chars) | Yes | Source CIDR / address / label (e.g. `0.0.0.0/0`, `10.0.0.0/8`, `any`). |
| `destination` | `string` (1–256 chars) | No | Destination CIDR / address / label. |
| `port` | `number` (int, 0–65535) or `string` (1–64 chars) | No | Port or port range (number, `*`, `any`, or a range string). |
| `protocol` | `string` (1–32 chars) | No | Transport protocol (e.g. `tcp`, `udp`, `icmp`, `any`). |
| `action` | enum: `allow` \| `deny` | Yes | Whether the rule permits or blocks the traffic. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape (`id`, `module`, `rule`, `severity`, `cwe`, `title`, `description`, `location?`, `evidence?`, `remediation`, `references`, `tags`, `status`). All findings are also appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "config": { "firewall_rules": [{ "direction": "ingress", "source": "0.0.0.0/0", "port": 22, "action": "allow" }] } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "network-admin-port-exposed", "severity": "high", "title": "Admin port open to the internet" }
  ]
}
```

## Detections

- `network-admin-port-exposed` — ingress to an admin / database port (SSH, RDP, PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch) from any source (CWE-284, CWE-668)
- `network-any-source-ingress` — ingress `allow` rule from `0.0.0.0/0` / `::/0` (CWE-284, CWE-668)
- `network-any-any-ingress` — unconstrained `allow any any` ingress rule (CWE-284, CWE-668)
- `network-flat-topology` — flat topology with no zones or segments (CWE-1008)
- `network-unrestricted-egress-rule` / `network-no-egress-filtering` — unrestricted outbound traffic (CWE-1008)
- `network-no-default-deny` — rule set with no default-deny (CWE-284)

## Related tools

- [`altais_check_hardening`](altais_check_hardening.md) — host-firewall and platform hardening checks
- [`altais_check_zero_trust`](altais_check_zero_trust.md) — microsegmentation and trust-boundary assessment

## See also

- [`infra` module](../modules/infra.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
