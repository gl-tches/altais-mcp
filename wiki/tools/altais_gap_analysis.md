# `altais_gap_analysis`

Generates a coverage and gap report for a compliance framework.

| Property | Value |
|----------|-------|
| Module | [`compliance`](../modules/compliance.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool generates a gap analysis for one of 16 bundled compliance frameworks. Every control is classified as `addressed` (at least one finding maps to it) or `gap` (no finding maps to it — that control area has not been assessed). It returns coverage statistics and the list of gap controls, and emits a finding per gap so unassessed control areas surface in the consolidated report. An agent calls it to measure how completely the current scan covers a framework. When `findings` is omitted, the shared session `FindingStore` is used.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `framework` | `string` enum (16 ids) | Yes | The compliance framework to evaluate against. |
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

Returns a gap-analysis object: `framework_id`, `framework_name`, `framework_version`, a `coverage` block (`{ total_controls, addressed, gap, coverage_pct }`), an `addressed_controls` array (`{ id, title }`), and a `gap_controls` array (`{ id, title, family, description, severity }`). It also emits one finding per gap control into the session `FindingStore` — `high` severity for high-risk control families, `medium` otherwise.

## Example

**Request**

```json
{ "framework": "pci-dss" }
```

**Response (excerpt)**

```json
{
  "framework_name": "PCI-DSS",
  "coverage": { "total_controls": 8, "addressed": 3, "gap": 5, "coverage_pct": 37.5 },
  "gap_controls": [
    { "id": "8.3", "title": "Strong authentication", "family": "Access Control", "severity": "high" }
  ]
}
```

## Detections

This tool classifies framework controls rather than running security checks:

- `addressed` — at least one finding maps to the control
- `gap` — no finding maps to the control; emitted as a finding so unassessed areas surface in the report
- Gap controls in high-risk families are escalated to `high` severity

## Related tools

- [`altais_map_findings`](altais_map_findings.md) — the underlying per-control finding mapping
- [`altais_generate_evidence`](altais_generate_evidence.md) — audit evidence pack for the same framework

## See also

- [`compliance` module](../modules/compliance.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
