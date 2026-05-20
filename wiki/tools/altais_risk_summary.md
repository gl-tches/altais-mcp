# `altais_risk_summary`

Return a composite risk score and severity breakdown for the current session.

| Property | Value |
|----------|-------|
| Module | [`core`](../modules/core.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Computes a composite risk score (0–100) from every finding accumulated in the session `FindingStore`, alongside the total finding count, a per-severity breakdown, and a per-module breakdown. An agent calls this for a quick risk read without rendering the full report.

## Input parameters

This tool takes no input parameters.

## Output

A JSON object: `{ risk_score, total, by_severity, by_module }`, where `risk_score` is a 0–100 composite, `total` is the finding count, `by_severity` maps each severity to a count, and `by_module` maps each module to its finding count.

## Example

**Request**

```json
{}
```

**Response (excerpt)**

```json
{
  "risk_score": 64,
  "total": 12,
  "by_severity": { "high": 3, "medium": 9 },
  "by_module": { "scan": 8, "secrets": 4 }
}
```

## Detections

Not an auditor. Returns a session-wide risk rollup:

- A composite 0–100 risk score derived from all findings.
- The total finding count.
- A severity breakdown.
- A per-module finding-count breakdown.

## Related tools

- [`altais_report`](altais_report.md) — the full consolidated report including every finding
- [`altais_score`](altais_score.md) — CVSS scoring for an individual vulnerability

## See also

- [`core` module](../modules/core.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
