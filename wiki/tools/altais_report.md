# `altais_report`

Aggregate every finding produced this session into a consolidated markdown or JSON report.

| Property | Value |
|----------|-------|
| Module | [`core`](../modules/core.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Collects all findings appended to the session `FindingStore` by other tools and renders a consolidated security report. Markdown output includes a module-level summary table plus per-module subsections; JSON output adds a `by_module` array grouping the findings by module. An agent calls this at the end of a review to produce a deliverable.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `format` | `string` enum `markdown` \| `json` | No (default `markdown`) | Output format for the report. |
| `include_info` | `boolean` | No (default `false`) | Include informational-severity findings. |
| `group_by` | `string` enum `module` \| `severity` | No (default `module`) | Markdown layout: `module` groups findings under a per-module section; `severity` returns a flat severity-sorted list. JSON output always includes a `by_module` breakdown. |

## Output

A rendered report. With `format: "markdown"`, a markdown document with a summary table and per-module (or per-severity) sections. With `format: "json"`, a JSON object containing `findings`, a `summary` (`total`, `by_severity`, `by_module`, `risk_score`), and a `by_module` array.

## Example

**Request**

```json
{ "format": "json", "group_by": "module" }
```

**Response (excerpt)**

```json
{
  "findings": ["..."],
  "summary": { "total": 12, "by_severity": { "high": 3, "medium": 9 }, "risk_score": 64 },
  "by_module": ["..."]
}
```

## Detections

Not an auditor. Returns an aggregated view of the session's findings:

- A consolidated list of every finding appended this session.
- A summary with totals, severity breakdown, per-module counts, and a composite risk score.
- A per-module grouping of findings.

## Related tools

- [`altais_risk_summary`](altais_risk_summary.md) — the composite risk score on its own, without the full finding list
- [`altais_get_config`](altais_get_config.md) — shows which modules contributed findings

## See also

- [`core` module](../modules/core.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
