# `altais_audit_agentic_supply_chain`

Audits an agent system against OWASP ASI04 — Agentic Supply Chain Vulnerabilities.

| Property | Value |
|----------|-------|
| Module | [`agentic`](../modules/agentic.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Audits an agent system against **ASI04 — Agentic Supply Chain Vulnerabilities**. It flags unsigned manifests, unverified plugins, unverified agent cards, unpinned tool or server registries, no typosquat check, missing provenance attestation, and MCP servers from untrusted sources. An agent calls this when reviewing the trust placed in third-party agent components.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–524288 chars) | No | Source code describing the agent system, scanned with pattern checks. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |
| `config` | `object` | No | Structured description of the agentic supply chain. |
| `config.mcp_servers` | `array` of `object` (max 512) | No | MCP servers in use, each `{ name, source? }`. |
| `config.mcp_servers[].name` | `string` (1–256 chars) | Yes | The MCP server's name. |
| `config.mcp_servers[].source` | `string` (1–256 chars) | No | Where the MCP server comes from. |
| `config.manifests_signed` | `boolean` | No | MCP / plugin manifests are cryptographically signed and verified. |
| `config.plugins_verified` | `boolean` | No | Plugins are verified before loading. |
| `config.agent_cards_verified` | `boolean` | No | Agent cards (A2A / discovery metadata) are verified. |
| `config.registry_pinned` | `boolean` | No | Tool / server registries are pinned to specific versions. |
| `config.typosquat_checked` | `boolean` | No | Component names are checked against typosquatting. |
| `config.provenance_attestation` | `boolean` | No | Provenance attestation is required for components. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape and carries the `owasp:asi04` tag. Findings are appended to the session report.

## Example

**Request**

```json
{ "config": { "manifests_signed": false, "plugins_verified": false } }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 2, "by_severity": { "high": 1, "medium": 1 } },
  "findings": [
    { "rule": "unsigned-manifests", "severity": "high", "tags": ["owasp:asi04"], "title": "MCP / plugin manifests are not signed", "status": "open" }
  ]
}
```

## Detections

All detections tie to **ASI04 — Agentic Supply Chain Vulnerabilities**:

- Unsigned manifests
- Unverified plugins
- Unverified agent cards
- Unpinned tool / server registries
- No typosquat check on component names
- Missing provenance attestation
- MCP servers from untrusted sources

## Related tools

- [`altais_audit_tool_misuse`](altais_audit_tool_misuse.md) — ASI02, unverified MCP tool descriptors
- [`altais_audit_model_supply_chain`](altais_audit_model_supply_chain.md) — the ML model-artifact equivalent

## See also

- [`agentic` module](../modules/agentic.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
