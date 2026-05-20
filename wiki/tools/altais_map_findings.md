# `altais_map_findings`

Maps security findings to a compliance framework's controls.

| Property | Value |
|----------|-------|
| Module | [`compliance`](../modules/compliance.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool maps security findings to the controls of one of 16 bundled compliance frameworks. Each finding is matched to controls whose CWE list intersects the finding's CWEs, or whose keywords appear in the finding's rule or title. It returns a per-control list of matched findings plus coverage statistics, and emits an `info` finding per addressed control as an audit trail. An agent calls it to relate scan results to a regulatory or standards framework. When `findings` is omitted, the shared session `FindingStore` is used.

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
| `cwe` | `string[]` (each 1–32 chars, max 32) | No | CWE identifiers associated with the finding (e.g. `CWE-89`). |
| `title` | `string` (1–512 chars) | No | Human-readable finding title. |
| `severity` | enum: `critical` \| `high` \| `medium` \| `low` \| `info` | No | Finding severity; defaults to `medium` when omitted. |

## Output

Returns a framework mapping object: `framework_id`, `framework_name`, `framework_version`, a `mappings` array — each entry has `control` (`{ id, title, family, description, cwes }`), `status` (`addressed` or `gap`), and `matched_findings` — plus a `summary` with coverage statistics. The tool also emits one `info` finding per addressed control into the session `FindingStore` so the mapping appears in the consolidated report.

## Example

**Request**

```json
{ "framework": "nist-800-53" }
```

**Response (excerpt)**

```json
{
  "framework_name": "NIST SP 800-53",
  "mappings": [
    { "control": { "id": "AC-3", "title": "Access Enforcement" }, "status": "addressed", "matched_findings": ["..."] }
  ],
  "summary": { "total_controls": 12, "addressed": 4, "gap": 8, "coverage_pct": 33.3 }
}
```

## Detections

This tool does not run security checks itself — it maps existing findings to framework controls. For each control it reports:

- `addressed` — at least one finding maps to the control by CWE intersection or keyword match
- `gap` — no finding maps to the control (that control area was not assessed)
- The distinct CWE IDs spanning the control and its matched findings

## Related tools

- [`altais_gap_analysis`](altais_gap_analysis.md) — coverage / gap report for the same framework
- [`altais_generate_evidence`](altais_generate_evidence.md) — turns the mapping into an audit evidence pack

## See also

- [`compliance` module](../modules/compliance.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
