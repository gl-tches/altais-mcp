# `altais_check_owasp_serverless`

Map findings to the OWASP Serverless Top 10 categories.

| Property | Value |
|----------|-------|
| Module | [`owasp`](../modules/owasp.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Maps the session's findings (or a supplied list) onto the OWASP Serverless Top 10 categories and reports which are covered. It covers event-data injection, over-privileged execution roles, secrets in environment variables, financial denial of service, and idempotency / replay risks. An agent calls this to assess serverless-specific risk coverage.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findings` | array of finding objects (up to 2000 items) | No | Pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session `FindingStore` is used. |
| `use_session_findings` | `boolean` | No (default `true`) | Read findings from the shared session `FindingStore`. |

Each supplied **finding** object has: `module` (string 1–64), `rule` (string 1–128), `severity` (enum `critical` \| `high` \| `medium` \| `low` \| `info`), `cwe` (`string[]`, each up to 32 chars, optional), `title` (string up to 512, optional).

## Output

A coverage report: `{ list, categories: [...], summary: {...} }`. `list` is `Serverless Top 10`; each `categories` entry has an `id`, `title`, `status`, and `matched` findings. This tool does not emit session findings.

## Example

**Request**

```json
{}
```

**Response (excerpt)**

```json
{
  "list": "Serverless Top 10",
  "categories": [
    { "id": "SAS-1", "title": "Event Data Injection", "status": "not_covered" }
  ]
}
```

## Detections

A coverage report over the OWASP Serverless Top 10: event-data injection, over-privileged function execution roles, secrets stored in environment variables, financial denial of service, idempotency and replay risks, and the remaining serverless categories. Findings are mapped by CWE intersection and keyword match.

## Related tools

- [`altais_check_owasp_web`](altais_check_owasp_web.md) — same mapping against the Web Top 10
- [`altais_check_owasp_api`](altais_check_owasp_api.md) — same mapping against the API Security Top 10

## See also

- [`owasp` module](../modules/owasp.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
