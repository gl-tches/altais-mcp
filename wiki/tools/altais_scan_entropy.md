# `altais_scan_entropy`

Compute Shannon entropy on candidate tokens and flag those above a threshold.

| Property | Value |
|----------|-------|
| Module | [`secrets`](../modules/secrets.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Extracts candidate tokens from the source, computes their Shannon entropy in bits per character, and flags those above the configured hex or base64 threshold (defaults 4.5 bits/char for hex, 5.0 for base64). It catches random-looking credentials that do not match any known secret pattern. An agent calls this as a complement to `altais_scan_secrets`.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1 char to the configured `max_source_bytes`) | Yes | Source text to scan for high-entropy strings. |
| `filename` | `string` (1–512 chars) | No | Filename used for finding location. |
| `hex_threshold` | `number` (0–8) | No | Override the hex-charset threshold in bits/char (default from config). |
| `base64_threshold` | `number` (0–8) | No | Override the base64-charset threshold in bits/char (default from config). |
| `min_token_length` | `integer` (8–256) | No | Override the minimum token length to consider (default from config). |

## Output

`{ thresholds: { hex, base64, minTokenLength }, summary: { total, by_severity }, findings: [...] }`. The `thresholds` object echoes the effective values used. Findings carry the standard shape and are appended to the session report.

## Example

**Request**

```json
{ "source": "secret = 'f8a3c91d2b4e7a6c5d0e9f1a8b3c2d4e'", "hex_threshold": 3.5 }
```

**Response (excerpt)**

```json
{
  "thresholds": { "hex": 3.5, "base64": 5.0, "minTokenLength": 20 },
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": ["..."]
}
```

## Detections

- High-entropy hex tokens above the hex threshold.
- High-entropy base64 tokens above the base64 threshold.
- Only tokens at least `min_token_length` characters long are considered.

This is a heuristic for credentials that escape known-pattern matching.

## Related tools

- [`altais_scan_secrets`](altais_scan_secrets.md) — pattern-based detection of known credential formats
- [`altais_scan_git_secrets`](altais_scan_git_secrets.md) — applies entropy detection across git history

## See also

- [`secrets` module](../modules/secrets.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
