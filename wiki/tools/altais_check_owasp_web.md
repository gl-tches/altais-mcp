# `altais_check_owasp_web`

Map findings to the OWASP Top 10:2025 (Web) categories.

| Property | Value |
|----------|-------|
| Module | [`owasp`](../modules/owasp.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Maps the session's findings (or a supplied list) onto the OWASP Top 10:2025 categories A01–A10 and reports which categories are covered. The 2025 edition promotes Supply Chain to A03, adds A10 Mishandling of Exceptional Conditions, and moves SSRF into A01 Broken Access Control. An agent calls this to see which Top 10 categories its findings touch.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findings` | array of finding objects (up to 2000 items) | No | Pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session `FindingStore` is used. |
| `use_session_findings` | `boolean` | No (default `true`) | Read findings from the shared session `FindingStore`. |

Each supplied **finding** object has: `module` (string 1–64), `rule` (string 1–128), `severity` (enum `critical` \| `high` \| `medium` \| `low` \| `info`), `cwe` (`string[]`, each up to 32 chars, optional), `title` (string up to 512, optional).

## Output

A coverage report: `{ list, categories: [...], summary: {...} }`. `list` is the list label (`Web Top 10:2025`); each entry in `categories` has an `id`, `title`, `status` (`covered` / `not_covered`), and the `matched` findings. This tool does not emit session findings.

## Example

**Request**

```json
{ "use_session_findings": true }
```

**Response (excerpt)**

```json
{
  "list": "Web Top 10:2025",
  "categories": [
    { "id": "A03", "title": "Software Supply Chain Failures", "status": "covered", "matched": ["..."] }
  ],
  "summary": { "covered": 1 }
}
```

## Detections

A coverage report over the OWASP Top 10:2025 (Web) categories A01–A10. For each category it reports a covered/not-covered status and the findings mapped to it by CWE intersection and keyword match.

## Related tools

- [`altais_check_owasp_api`](altais_check_owasp_api.md) — same mapping against the API Security Top 10
- [`altais_check_asvs`](altais_check_asvs.md) — ASVS controls annotated with related findings

## See also

- [`owasp` module](../modules/owasp.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
