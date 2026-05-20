# `altais_lookup_cwe`

Performs a full CWE taxonomy lookup with related weaknesses against the bundled CWE database.

| Property | Value |
|----------|-------|
| Module | [`vuln_db`](../modules/vuln_db.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Resolves a CWE identifier against the bundled CWE database and returns the weakness name, description, concrete examples, remediation, and references, plus related CWEs with their parent / child / peer relations. The related-weakness set is derived from a curated relation map and from cross-references in the entry text. This lookup is richer than the core module's `altais_explain_cwe`. An agent calls this to understand a weakness class and navigate the surrounding taxonomy.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cwe_id` | `string` (1–32 chars) | Yes | A CWE identifier in any common form: `79`, `CWE-79`, or `cwe-79`. |

## Output

Returns a JSON object with two top-level fields. `entry` is the CWE record — `{ id, name, description, examples, remediation, references }`. `related` is an array of related CWEs, each `{ id, relation }` where `relation` is one of `parent`, `child`, or `peer`. If the identifier is not in the bundled database, the tool returns an error result explaining that the CWE was not found.

## Example

**Request**

```json
{ "cwe_id": "CWE-79" }
```

**Response (excerpt)**

```json
{
  "entry": {
    "id": "CWE-79",
    "name": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "description": "The product does not neutralize user-controllable input before placing it in output used as a web page.",
    "remediation": "Contextually encode output; apply a strict Content-Security-Policy."
  },
  "related": [
    { "id": "CWE-116", "relation": "peer" },
    { "id": "CWE-20", "relation": "parent" }
  ]
}
```

## Detections

This is a lookup against the bundled, OFFLINE CWE database — it performs no network calls. For a matched CWE it returns the weakness name, description, concrete examples, remediation, and references, plus a set of related CWEs (parent / child / peer) sourced from a curated relation map and entry-text cross-references.

## Related tools

- [`altais_lookup_cve`](altais_lookup_cve.md) — looks up CVEs that reference a CWE
- [`altais_map_attack`](altais_map_attack.md) — maps a CWE to MITRE ATT&CK techniques
- [`altais_explain_cwe`](altais_explain_cwe.md) — the lighter-weight core CWE lookup

## See also

- [`vuln_db` module](../modules/vuln_db.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
