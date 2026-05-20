# `altais_dread`

Compute a DREAD risk score from five subjective 1–10 ratings.

| Property | Value |
|----------|-------|
| Module | [`threat_model`](../modules/threat_model.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Computes a DREAD score from five subjective ratings — Damage, Reproducibility, Exploitability, Affected users, and Discoverability — each on a 1–10 scale. It returns the total (5–50), the average, and a qualitative rating. An agent calls this to rank an identified threat against others.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `threat` | `string` (1–512 chars) | Yes | Short threat description. |
| `damage` | `number` (1–10) | Yes | Damage potential rating. |
| `reproducibility` | `number` (1–10) | Yes | Reproducibility rating. |
| `exploitability` | `number` (1–10) | Yes | Exploitability rating. |
| `affected_users` | `number` (1–10) | Yes | Affected-users rating. |
| `discoverability` | `number` (1–10) | Yes | Discoverability rating. |
| `justification` | `string` (up to 2048 chars) | No | Free-text rationale for the ratings. |

## Output

A scoring record: `{ threat, total, average, rating }`, where `total` is the sum of the five ratings (5–50), `average` is the mean, and `rating` is a qualitative band. This tool does not emit session findings.

## Example

**Request**

```json
{
  "threat": "Token theft via XSS",
  "damage": 8,
  "reproducibility": 6,
  "exploitability": 7,
  "affected_users": 9,
  "discoverability": 5
}
```

**Response (excerpt)**

```json
{ "threat": "Token theft via XSS", "total": 35, "average": 7.0, "rating": "high" }
```

## Detections

Not an auditor. Returns a computed risk score:

- The DREAD total (5–50) summing the five ratings.
- The average of the five ratings.
- A qualitative rating band derived from the score.

## Related tools

- [`altais_stride`](altais_stride.md) — identifies threats that this tool can then score
- [`altais_attack_tree`](altais_attack_tree.md) — maps an attacker goal to concrete attack paths

## See also

- [`threat_model` module](../modules/threat_model.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
