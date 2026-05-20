# `altais_check_owasp_api`

Map findings to the OWASP API Security Top 10 (2023) categories.

| Property | Value |
|----------|-------|
| Module | [`owasp`](../modules/owasp.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Maps the session's findings (or a supplied list) onto the OWASP API Security Top 10 (2023) categories and reports which are covered. It covers BOLA, BOPLA, BFLA, unrestricted resource consumption, unsafe consumption of third-party APIs, and improper inventory management, among others. An agent calls this to assess API-specific risk coverage.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findings` | array of finding objects (up to 2000 items) | No | Pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session `FindingStore` is used. |
| `use_session_findings` | `boolean` | No (default `true`) | Read findings from the shared session `FindingStore`. |

Each supplied **finding** object has: `module` (string 1–64), `rule` (string 1–128), `severity` (enum `critical` \| `high` \| `medium` \| `low` \| `info`), `cwe` (`string[]`, each up to 32 chars, optional), `title` (string up to 512, optional).

## Output

A coverage report: `{ list, categories: [...], summary: {...} }`. `list` is `API Top 10:2023`; each `categories` entry has an `id` (e.g. `API1`), `title`, `status`, and `matched` findings. This tool does not emit session findings.

## Example

**Request**

```json
{}
```

**Response (excerpt)**

```json
{
  "list": "API Top 10:2023",
  "categories": [
    { "id": "API1", "title": "Broken Object Level Authorization", "status": "not_covered" }
  ]
}
```

## Detections

A coverage report over the OWASP API Security Top 10 (2023): Broken Object Level Authorization, Broken Object Property Level Authorization, Broken Function Level Authorization, unrestricted resource consumption, unsafe consumption of third-party APIs, improper inventory management, and the remaining API categories. Findings are mapped by CWE intersection and keyword match.

## Related tools

- [`altais_check_owasp_web`](altais_check_owasp_web.md) — same mapping against the Web Top 10
- [`altais_check_owasp_serverless`](altais_check_owasp_serverless.md) — same mapping against the Serverless Top 10

## See also

- [`owasp` module](../modules/owasp.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
