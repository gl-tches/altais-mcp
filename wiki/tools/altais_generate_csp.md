# `altais_generate_csp`

Build a Content-Security-Policy header from a high-level description of what the app loads.

| Property | Value |
|----------|-------|
| Module | [`headers`](../modules/headers.md) |
| Tool type | Generator (returns an artifact) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Generates a Content-Security-Policy header string from a structured description of the app's external resource needs. The generator never emits `'unsafe-inline'` or `'unsafe-eval'`; when inline scripts or styles are needed it instead returns a `recommendations` array suggesting a nonce/hash-based alternative. An agent calls this to produce a hardened CSP for a web app.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | `string` enum `strict` \| `compatible` | No (default `strict`) | `strict` uses `default-src 'none'`; `compatible` uses `default-src 'self'`. |
| `requires_inline_scripts` | `boolean` | No (default `false`) | Whether the app needs inline scripts (triggers a nonce/hash recommendation). |
| `requires_inline_styles` | `boolean` | No (default `false`) | Whether the app needs inline styles (triggers a nonce/hash recommendation). |
| `external_scripts` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed external script sources. |
| `external_styles` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed external style sources. |
| `external_images` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed external image sources. |
| `external_fonts` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed external font sources. |
| `external_connections` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed `connect-src` endpoints. |
| `external_frames` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed `frame-src` sources. |
| `use_workers` | `boolean` | No (default `false`) | Whether the app uses web workers. |
| `allow_form_actions` | `string[]` (up to 128 items, each 1–512 chars) | No | Allowed `form-action` targets. |
| `report_uri` | `string` (1–512 chars) | No | Value for the `report-uri` directive. |
| `report_to` | `string` (1–128 chars) | No | Value for the `report-to` directive. |

## Output

A generated artifact: `{ header, recommendations }`, where `header` is the assembled CSP string and `recommendations` lists suggested follow-ups (such as adopting nonces when inline content is required). This tool does not emit findings.

## Example

**Request**

```json
{ "mode": "strict", "external_scripts": ["https://cdn.example.com"] }
```

**Response (excerpt)**

```json
{
  "header": "default-src 'none'; script-src https://cdn.example.com; ...",
  "recommendations": ["..."]
}
```

## Detections

The generated artifact contains:

- A complete CSP header string with per-resource directives derived from the inputs.
- A `default-src` baseline of `'none'` (strict) or `'self'` (compatible).
- Optional `report-uri` / `report-to` directives.
- A `recommendations` array — notably nonce/hash guidance when inline scripts or styles are requested, since `'unsafe-inline'` and `'unsafe-eval'` are never emitted.

## Related tools

- [`altais_audit_headers`](altais_audit_headers.md) — flags a missing or weak CSP this tool can replace
- [`altais_check_cors`](altais_check_cors.md) — validates the related cross-origin policy

## See also

- [`headers` module](../modules/headers.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
