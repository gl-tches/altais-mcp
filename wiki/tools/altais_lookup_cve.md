# `altais_lookup_cve`

Looks up a CVE by identifier in a bundled, curated offline snapshot of well-known, high-impact CVEs.

| Property | Value |
|----------|-------|
| Module | [`vuln_db`](../modules/vuln_db.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Resolves a CVE identifier against a bundled offline snapshot of curated, high-impact CVEs (Log4Shell, Heartbleed, Spring4Shell, the xz backdoor, and others). It returns the vulnerability description, CVSS v3.1 vector and score, severity, related CWEs, affected versions, publication date, remediation guidance, and references. An agent calls this when it encounters a CVE reference and needs the details to triage or remediate. This is an offline snapshot, not a live feed — no network calls are made.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cve_id` | `string` (1–32 chars) | Yes | A CVE identifier of the form `CVE-YYYY-NNNN`, e.g. `CVE-2021-44228`. Must match the CVE-ID pattern. |

## Output

Returns a single CVE record as JSON — not a findings list. The record includes the CVE `id`, a `description`, a `cvss_v31` object (`{ vector, score }`), a qualitative `severity`, a `cwe` array of related CWE identifiers, affected versions, publication date, `remediation` guidance, and a `references` array. If the identifier is not in the bundled snapshot, the tool returns an error result explaining that the CVE was not found.

## Example

**Request**

```json
{ "cve_id": "CVE-2021-44228" }
```

**Response (excerpt)**

```json
{
  "id": "CVE-2021-44228",
  "description": "Log4Shell — JNDI injection in Apache Log4j 2.",
  "cvss_v31": { "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": 10.0 },
  "severity": "critical",
  "cwe": ["CWE-502"],
  "remediation": "Upgrade Log4j to 2.17.1 or later.",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
}
```

## Detections

This is a lookup against a bundled, OFFLINE snapshot of curated high-impact CVEs — it performs no network calls. For each matched CVE it returns the description, CVSS v3.1 vector and score, qualitative severity, related CWE identifiers, affected versions, publication date, remediation guidance, and references.

## Related tools

- [`altais_lookup_cwe`](altais_lookup_cwe.md) — resolves the CWE identifiers referenced by a CVE
- [`altais_calculate_cvss`](altais_calculate_cvss.md) — re-scores or adjusts a CVSS vector
- [`altais_map_attack`](altais_map_attack.md) — maps a CVE's CWEs to MITRE ATT&CK techniques

## See also

- [`vuln_db` module](../modules/vuln_db.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
