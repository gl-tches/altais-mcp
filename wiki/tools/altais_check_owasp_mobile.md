# `altais_check_owasp_mobile`

Map findings to the OWASP Mobile Top 10 (2024) categories.

| Property | Value |
|----------|-------|
| Module | [`owasp`](../modules/owasp.md) |
| Tool type | Lookup (returns data) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Maps the session's findings (or a supplied list) onto the OWASP Mobile Top 10 (2024) categories and reports which are covered. It covers credentials, supply chain, authentication/authorization, network communication, privacy controls, binary protections, and insecure data storage. An agent calls this to assess mobile-specific risk coverage.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findings` | array of finding objects (up to 2000 items) | No | Pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session `FindingStore` is used. |
| `use_session_findings` | `boolean` | No (default `true`) | Read findings from the shared session `FindingStore`. |

Each supplied **finding** object has: `module` (string 1–64), `rule` (string 1–128), `severity` (enum `critical` \| `high` \| `medium` \| `low` \| `info`), `cwe` (`string[]`, each up to 32 chars, optional), `title` (string up to 512, optional).

## Output

A coverage report: `{ list, categories: [...], summary: {...} }`. `list` is `Mobile Top 10:2024`; each `categories` entry has an `id`, `title`, `status`, and `matched` findings. This tool does not emit session findings.

## Example

**Request**

```json
{}
```

**Response (excerpt)**

```json
{
  "list": "Mobile Top 10:2024",
  "categories": [
    { "id": "M1", "title": "Improper Credential Usage", "status": "not_covered" }
  ]
}
```

## Detections

A coverage report over the OWASP Mobile Top 10 (2024): credential usage, supply-chain security, insecure authentication/authorization, insecure communication, inadequate privacy controls, insufficient binary protections, insecure data storage, and the remaining mobile categories. Findings are mapped by CWE intersection and keyword match.

## Related tools

- [`altais_check_owasp_web`](altais_check_owasp_web.md) — same mapping against the Web Top 10
- [`altais_check_owasp_api`](altais_check_owasp_api.md) — same mapping against the API Security Top 10

## See also

- [`owasp` module](../modules/owasp.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
