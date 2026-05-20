# `altais_calculate_cvss`

Parses and scores a CVSS v3.1 or v4.0 vector string.

| Property | Value |
|----------|-------|
| Module | [`vuln_db`](../modules/vuln_db.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Parses a CVSS vector string and computes its score. For CVSS v3.1 it computes the Base score plus the Temporal and Environmental metric groups when supplied. For CVSS v4.0 it parses and validates all four metric groups (Base, Threat, Environmental, Supplemental), derives the MacroVector, and computes the score with the official FIRST CVSS v4.0 lookup-table algorithm. An agent calls this to score a vulnerability or to adjust an existing score with environmental context.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `vector` | `string` (1–512 chars) | Yes | A CVSS vector string. Must start with a `CVSS:3.1/` or `CVSS:4.0/` prefix. Temporal / Environmental / Threat / Supplemental metrics are scored when present. |

## Output

Returns a JSON object describing the scored vector: the `version` (`3.1` or `4.0`), the numeric `score`, the qualitative `severity`, the subscores, and the parsed metric groups. For v4.0 the response also includes the derived `macro_vector` and a `metric_groups` breakdown. If the vector cannot be parsed, the tool returns an error result pointing to the FIRST CVSS specification.

## Example

**Request**

```json
{ "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }
```

**Response (excerpt)**

```json
{
  "version": "4.0",
  "score": 9.3,
  "severity": "critical",
  "macro_vector": "000000"
}
```

## Detections

This is a calculation tool — it derives a score from a vector string and performs no network calls. It returns the CVSS version, numeric score, qualitative severity, subscores, and the parsed metric groups. CVSS v4.0 scoring uses the official FIRST lookup-table algorithm with a derived MacroVector.

## Related tools

- [`altais_lookup_cve`](altais_lookup_cve.md) — returns the published CVSS vector for a known CVE
- [`altais_score`](altais_score.md) — the core module's CVSS scorer
- [`altais_map_attack`](altais_map_attack.md) — maps a vulnerability to ATT&CK techniques

## See also

- [`vuln_db` module](../modules/vuln_db.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
