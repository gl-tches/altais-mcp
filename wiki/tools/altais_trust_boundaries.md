# `altais_trust_boundaries`

Identify data flows that cross trust zones and emit findings for risky crossings.

| Property | Value |
|----------|-------|
| Module | [`threat_model`](../modules/threat_model.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Walks the data flows in a structured architecture and identifies flows that cross trust zones. It emits findings for cleartext crossings, unauthenticated crossings, and ingress points that need explicit input validation. An agent calls this to spot where data leaves a trust boundary without adequate protection.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `architecture` | `object` (see below) | Yes | Structured architecture description (same shape as `altais_stride`). |

The `architecture` object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `components` | array of component objects (1–64 items) | Yes | The system's components. |
| `data_flows` | array of data-flow objects (up to 256 items) | No | Flows of data between components. |
| `trust_boundaries` | array of trust-boundary objects (up to 32 items) | No | Named trust boundaries. |

Each **component** has: `name` (string 1–128), `type` (enum of supported component types), `description` (string up to 2048, optional), `trust_zone` (string 1–64, optional), `handles_pii` (boolean, optional), `authenticates_clients` (boolean, optional). Each **data flow** has: `from`, `to` (strings 1–128), `data` (string 1–512), `protocol` (string 1–64, optional), `auth` (string 1–128, optional), `encrypted` (boolean, optional). Each **trust boundary** has: `name` (string 1–128), `description` (string up to 1024, optional).

## Output

`{ crossings: [...], summary: { total, by_severity }, findings: [...] }`. `crossings` describes the trust-zone-crossing flows; `findings` carries the standard finding shape and is appended to the session report.

## Example

**Request**

```json
{
  "architecture": {
    "components": [
      { "name": "Browser", "type": "browser", "trust_zone": "public" },
      { "name": "API", "type": "web_service", "trust_zone": "internal" }
    ],
    "data_flows": [{ "from": "Browser", "to": "API", "data": "auth token", "encrypted": false }]
  }
}
```

**Response (excerpt)**

```json
{
  "crossings": ["..."],
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [{ "rule": "cleartext-boundary-crossing", "severity": "high" }]
}
```

## Detections

- Cleartext crossings — data crossing a trust zone without encryption
- Unauthenticated crossings — flows crossing a boundary without authentication
- Ingress points that require explicit input validation

## Related tools

- [`altais_stride`](altais_stride.md) — per-component STRIDE analysis of the same architecture
- [`altais_attack_tree`](altais_attack_tree.md) — attack paths toward an attacker goal

## See also

- [`threat_model` module](../modules/threat_model.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
