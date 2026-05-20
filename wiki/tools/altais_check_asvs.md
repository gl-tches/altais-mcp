# `altais_check_asvs`

Return OWASP ASVS controls at a given verification level, optionally filtered to one section.

| Property | Value |
|----------|-------|
| Module | [`owasp`](../modules/owasp.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Returns the OWASP Application Security Verification Standard (ASVS) controls applicable at a chosen verification level (1, 2, or 3), optionally filtered to a single section V1–V14. Each control is annotated with related findings from the session (or a supplied list). This is a coarse hint to focus review, not a formal compliance claim. An agent calls this to surface the ASVS controls relevant to its work.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `level` | `1` \| `2` \| `3` | No (default `1`) | ASVS verification level. Level N returns all controls at levels 1..N (1 = baseline, 2 = standard, 3 = critical apps). |
| `section` | `string` (1–8 chars) | No | Section filter, `V1`..`V14`. |
| `findings` | array of finding objects (up to 2000 items) | No | Pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session `FindingStore` is used. |
| `use_session_findings` | `boolean` | No (default `true`) | Read findings from the shared session `FindingStore`. |

Each supplied **finding** object has: `module` (string 1–64), `rule` (string 1–128), `severity` (enum `critical` \| `high` \| `medium` \| `low` \| `info`), `cwe` (`string[]`, each up to 32 chars, optional), `title` (string up to 512, optional).

## Output

An ASVS report: `{ version, level, controls: [...] }`. Each control has an `id` (e.g. `V3.1.1`), a `requirement`, and a `related_findings` array. This tool does not emit session findings.

## Example

**Request**

```json
{ "level": 2, "section": "V3" }
```

**Response (excerpt)**

```json
{
  "version": "4.0.3",
  "level": 2,
  "controls": [
    { "id": "V3.1.1", "requirement": "...", "related_findings": ["..."] }
  ]
}
```

## Detections

A list of ASVS controls scoped to the requested level and (optionally) section V1–V14. Each control carries its requirement text and any session findings related to it by CWE intersection and keyword match. The output is advisory, not a formal compliance attestation.

## Related tools

- [`altais_check_owasp_web`](altais_check_owasp_web.md) — coverage mapping against the Web Top 10
- [`altais_check_owasp_api`](altais_check_owasp_api.md) — coverage mapping against the API Security Top 10

## See also

- [`owasp` module](../modules/owasp.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
