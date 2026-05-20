# `altais_score`

Calculate a CVSS base score from a vector string.

| Property | Value |
|----------|-------|
| Module | [`core`](../modules/core.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Parses a CVSS vector string and computes its base score and severity. CVSS v3.1 vectors are scored per the FIRST §7.1 base formula; CVSS v4.0 vectors (those starting with `CVSS:4.0/`) are scored via the official MacroVector lookup table with maximal-severity interpolation across all four metric groups. An agent calls this to attach a numeric severity to a vulnerability described as a vector.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vector` | `string` (8–256 chars) | Yes | CVSS vector string, e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. |

## Output

A scoring record. For v3.1: `{ version, base_score, severity }`. For v4.0: the v4.0 calculation result (version, score, severity, and metric-group detail). Malformed vectors return an error result.

## Example

**Request**

```json
{ "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
```

**Response (excerpt)**

```json
{ "version": "3.1", "base_score": 9.8, "severity": "critical" }
```

## Detections

Not an auditor. Returns a computed score:

- CVSS version detected from the vector prefix.
- The numeric base score.
- The qualitative severity band (`none` / `low` / `medium` / `high` / `critical`).

## Related tools

- [`altais_explain_cwe`](altais_explain_cwe.md) — explains the weakness class behind a scored vulnerability
- [`altais_risk_summary`](altais_risk_summary.md) — composite session risk score derived from finding severities

## See also

- [`core` module](../modules/core.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
