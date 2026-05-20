# `altais_explain_cwe`

Look up a Common Weakness Enumeration (CWE) entry from the bundled CWE database.

| Property | Value |
|----------|-------|
| Module | [`core`](../modules/core.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Resolves a CWE identifier against the bundled top-100 CWE database and returns the weakness name, a description, illustrative examples, and remediation guidance. An agent calls this to explain a CWE referenced by a finding without needing a network lookup.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cwe` | `string` (1–32 chars) | Yes | CWE identifier, e.g. `CWE-79` or `79`. |

## Output

The matching CWE record: `{ id, name, description, examples, remediation }`. If the identifier is not in the bundled database, the tool returns an error result suggesting a known top-100 ID.

## Example

**Request**

```json
{ "cwe": "CWE-89" }
```

**Response (excerpt)**

```json
{
  "id": "CWE-89",
  "name": "SQL Injection",
  "description": "...",
  "examples": ["..."],
  "remediation": "..."
}
```

## Detections

Not an auditor. Returns one CWE record containing:

- The canonical CWE id and name.
- A description of the weakness.
- Examples of how the weakness appears.
- Remediation guidance.

## Related tools

- [`altais_score`](altais_score.md) — computes a CVSS base score for a vulnerability
- [`altais_scan_code`](altais_scan_code.md) — emits findings tagged with CWE IDs you can look up here

## See also

- [`core` module](../modules/core.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
