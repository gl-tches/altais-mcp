# `altais_stride`

Emit a STRIDE threat breakdown per component from a structured architecture.

| Property | Value |
|----------|-------|
| Module | [`threat_model`](../modules/threat_model.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Takes a structured architecture description (components, data flows, trust boundaries) and produces a STRIDE breakdown for each component, drawing on a knowledge base of typical threats for each component type. It returns structured analysis JSON rather than session findings. An agent calls this to threat-model a system design.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `architecture` | `object` (see below) | Yes | Structured architecture description. |

The `architecture` object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `components` | array of component objects (1–64 items) | Yes | The system's components. |
| `data_flows` | array of data-flow objects (up to 256 items) | No | Flows of data between components. |
| `trust_boundaries` | array of trust-boundary objects (up to 32 items) | No | Named trust boundaries. |

Each **component** has: `name` (string 1–128), `type` (enum of supported component types — drives the STRIDE knowledge base lookup), `description` (string up to 2048, optional), `trust_zone` (string 1–64, optional), `handles_pii` (boolean, optional), `authenticates_clients` (boolean, optional).

Each **data flow** has: `from` (string 1–128), `to` (string 1–128), `data` (string 1–512 — what is sent), `protocol` (string 1–64, optional), `auth` (string 1–128, optional), `encrypted` (boolean, optional).

Each **trust boundary** has: `name` (string 1–128), `description` (string up to 1024, optional).

## Output

Structured analysis JSON: per component, a `stride` object enumerating threats across the six STRIDE categories (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege). This tool does not emit session findings.

## Example

**Request**

```json
{ "architecture": { "components": [{ "name": "API", "type": "web_service" }] } }
```

**Response (excerpt)**

```json
{
  "components": [
    {
      "name": "API",
      "stride": { "spoofing": ["..."], "tampering": ["..."] }
    }
  ]
}
```

## Detections

For each component, threats across the six STRIDE categories:

- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation disclosure
- **D**enial of service
- **E**levation of privilege

Threats are selected from a knowledge base keyed on the component `type`.

## Related tools

- [`altais_trust_boundaries`](altais_trust_boundaries.md) — analyzes the same architecture for risky boundary crossings
- [`altais_dread`](altais_dread.md) — scores the severity of an identified threat

## See also

- [`threat_model` module](../modules/threat_model.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
