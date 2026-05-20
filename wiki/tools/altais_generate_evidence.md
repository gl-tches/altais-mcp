# `altais_generate_evidence`

Generates a structured audit evidence pack per compliance control.

| Property | Value |
|----------|-------|
| Module | [`compliance`](../modules/compliance.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool generates a structured evidence pack for an audit against one of 16 bundled compliance frameworks. For each selected control — all controls by default, or those named in `control_ids` — it produces an evidence record with the control id and title, its `addressed` / `gap` status, the findings serving as evidence, and a generated evidence statement. An agent calls it to assemble auditor-facing documentation from the current finding set. When `findings` is omitted, the shared session `FindingStore` is used.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `framework` | `string` enum (16 ids) | Yes | The compliance framework to generate evidence for. |
| `control_ids` | `string[]` (each 1–64 chars, max 200) | No | Control ids to include; when omitted, all controls are included. |
| `findings` | `array` (max 2000) | No | Explicit findings to evaluate; when omitted, the session `FindingStore` is used. |

The `framework` enum accepts: `owasp-asvs`, `owasp-samm`, `owasp-dsomm`, `nist-800-53`, `nist-ssdf`, `nist-ai-rmf`, `iso-27001`, `soc2`, `gdpr`, `pci-dss`, `nis2`, `dora`, `cra`, `cisa-sbd`, `eo-14028`, `fda-524b`.

Each entry in the optional `findings` array is an object:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rule` | `string` (1–128 chars) | Yes | The rule / check that produced the finding. |
| `cwe` | `string[]` (each 1–32 chars, max 32) | No | CWE identifiers associated with the finding. |
| `title` | `string` (1–512 chars) | No | Human-readable finding title. |
| `severity` | enum: `critical` \| `high` \| `medium` \| `low` \| `info` | No | Finding severity; defaults to `medium`. |

## Output

Returns an evidence-pack object: `framework_id`, `framework_name`, `framework_version`, a `generated_at_note`, a `reference` URL, a `summary` (`{ controls_in_pack, addressed, gap }`), and an `evidence` array. Each evidence record has `control_id`, `control_title`, `control_family`, `status` (`addressed` or `gap`), an `evidence_statement` string, and an `evidence_findings` array (`{ id, rule, title, severity }`). Unlike the other compliance tools, this generator does not push findings into the session report. If `control_ids` matches no control, the tool returns `isError: true` listing the valid ids.

## Example

**Request**

```json
{ "framework": "soc2", "control_ids": ["CC6.1"] }
```

**Response (excerpt)**

```json
{
  "framework_name": "SOC 2",
  "summary": { "controls_in_pack": 1, "addressed": 1, "gap": 0 },
  "evidence": [
    {
      "control_id": "CC6.1",
      "status": "addressed",
      "evidence_statement": "SOC 2 control CC6.1 was assessed; 2 related findings were identified as evidence...",
      "evidence_findings": ["..."]
    }
  ]
}
```

## Detections

This tool generates audit artifacts rather than running security checks. Per selected control it reports:

- `addressed` — an evidence statement citing the findings that serve as evidence
- `gap` — an evidence statement noting no assessment evidence exists; a manual review or compensating control must be documented
- A pack-level summary of how many controls are addressed versus gaps

## Related tools

- [`altais_map_findings`](altais_map_findings.md) — the underlying finding-to-control mapping
- [`altais_gap_analysis`](altais_gap_analysis.md) — coverage statistics for the same framework

## See also

- [`compliance` module](../modules/compliance.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
