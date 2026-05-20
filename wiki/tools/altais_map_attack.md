# `altais_map_attack`

Maps a CWE identifier and/or a free-text vulnerability description to MITRE ATT&CK techniques.

| Property | Value |
|----------|-------|
| Module | [`vuln_db`](../modules/vuln_db.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Maps a CWE identifier and/or a free-text vulnerability description to MITRE ATT&CK techniques using a bundled, curated subset of software-relevant techniques. A CWE match against a technique's related weaknesses is the strongest signal; description keywords add weight. An agent calls this to connect a discovered weakness to adversary tradecraft for threat modeling, detection engineering, or red-team planning.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cwe` | `string` (1–32 chars) | No | A CWE identifier to map, e.g. `CWE-89`. At least one of `cwe` or `description` must be provided. |
| `description` | `string` (1–4096 chars) | No | A free-text vulnerability description matched against technique keywords. At least one of `cwe` or `description` must be provided. |
| `limit` | `integer` (1–30) | No | Maximum number of ranked techniques to return. Defaults to `10`. |

## Output

Returns a JSON object with a `techniques` array of ranked matches. Each technique includes the ATT&CK `id`, `name`, `tactic`, a normalized `confidence` score, and a `reasons` array explaining why it matched. Techniques are sorted by confidence and truncated to `limit`.

## Example

**Request**

```json
{ "cwe": "CWE-89", "limit": 3 }
```

**Response (excerpt)**

```json
{
  "techniques": [
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "tactic": "initial-access",
      "confidence": 0.82,
      "reasons": ["CWE-89 is a related weakness of this technique"]
    }
  ]
}
```

## Detections

This is a mapping tool backed by a bundled, OFFLINE curated subset of software-relevant MITRE ATT&CK techniques — it performs no network calls. It returns ranked techniques, each with an ATT&CK id, name, tactic, a normalized confidence score, and the reasons it matched. A CWE match against a technique's related weaknesses is weighted more strongly than a description keyword match.

## Related tools

- [`altais_lookup_cwe`](altais_lookup_cwe.md) — resolves the CWE used as the mapping input
- [`altais_lookup_cve`](altais_lookup_cve.md) — supplies the CWEs referenced by a known CVE
- [`altais_scope_red_team`](altais_scope_red_team.md) — uses ATT&CK TTPs to scope adversary simulation

## See also

- [`vuln_db` module](../modules/vuln_db.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
