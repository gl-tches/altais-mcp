# `altais_generate_vex`

Emits an OpenVEX 0.2.0 or CycloneDX 1.5 VEX document from a list of statements.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool emits a VEX (Vulnerability Exploitability eXchange) document — OpenVEX 0.2.0 or CycloneDX 1.5 VEX — from a list of `(vulnerability, products, status)` statements. It is used to declare exploitability decisions, most commonly `not_affected`, on advisories that surface in an audit but do not apply to your product. An agent calls it after triaging vulnerability findings to publish a machine-readable disposition.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `format` | enum: `openvex` \| `cyclonedx-vex` | No | Output format. Default `openvex`. |
| `author` | `string` (1–256 chars) | No | The document author. |
| `author_role` | `string` (1–64 chars) | No | The author's role. |
| `statements` | `object[]` (1–256 items) | Yes | The VEX statements (see below). |

Each entry in `statements` accepts:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vulnerability` | `string` (1–128 chars) | Yes | The vulnerability identifier (e.g. a CVE id). |
| `products` | `object[]` (1–64 items) | Yes | Affected products; each `{ identifier: string (1–512), subcomponent_identifiers?: string[] (each 1–512, max 64) }`. |
| `status` | enum: `not_affected` \| `affected` \| `fixed` \| `under_investigation` | Yes | The exploitability status. |
| `justification` | enum: `component_not_present` \| `vulnerable_code_not_present` \| `vulnerable_code_not_in_execute_path` \| `vulnerable_code_cannot_be_controlled_by_adversary` \| `inline_mitigations_already_exist` | No | Justification for a `not_affected` status. |
| `impact_statement` | `string` (≤2048 chars) | No | A free-text impact statement. |
| `action_statement` | `string` (≤2048 chars) | No | A free-text recommended-action statement. |

## Output

Returns the VEX artifact itself — not a findings list. For `openvex` the document carries `@context`, `@id`, `author`, and a `statements` array; for `cyclonedx-vex` a CycloneDX 1.5 VEX document. This tool does not append anything to the session report.

## Example

**Request**

```json
{ "statements": [ { "vulnerability": "CVE-2021-44228", "products": [ { "identifier": "pkg:maven/acme/app@1.0" } ], "status": "not_affected", "justification": "vulnerable_code_not_present" } ] }
```

**Response (excerpt)**

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    { "vulnerability": { "name": "CVE-2021-44228" }, "status": "not_affected", "justification": "vulnerable_code_not_present" }
  ]
}
```

## Detections

This is a generator, not an auditor. The emitted artifact contains:

- Document-level metadata — context / spec identifier, document id, author, and author role
- One statement per input entry, each binding a vulnerability to one or more products (with optional subcomponents) and an exploitability `status`
- For `not_affected` statements, a machine-readable `justification`; optional `impact_statement` and `action_statement` free text

## Related tools

- [`altais_audit_deps`](altais_audit_deps.md) — surfaces the advisories a VEX document responds to
- [`altais_generate_sbom`](altais_generate_sbom.md) — pairs with VEX to describe the product

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
