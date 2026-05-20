# `altais_scan_git_secrets`

Walk `git log -p` or `git diff` output and attribute secret findings to commits and files.

| Property | Value |
|----------|-------|
| Module | [`secrets`](../modules/secrets.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Parses the output of `git log -p` or `git diff`, runs both the secret-pattern registry and the entropy detector against each diff line, and attributes every finding to the originating commit and file. It surfaces credentials present in history, not just the current working tree. An agent calls this when auditing a repository's commit history for leaked secrets.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1 char to the configured `max_source_bytes`) | Yes | Output from `git log -p` or `git diff`. |

## Output

`{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape; commit attribution appears in the finding's `tags` (e.g. `commit:a1b2c3`). Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "commit a1b2c3d4\n+++ b/.env\n+STRIPE_KEY=sk_live_REDACTEDEXAMPLE\n" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    { "rule": "stripe-secret-key", "severity": "high", "tags": ["commit:a1b2c3d4"] }
  ]
}
```

## Detections

Combines two detectors over every added diff line:

- The full secret-pattern registry — AWS, GitHub, Slack, Stripe, GCP, JWT, PEM keys, DSNs, and more.
- The Shannon-entropy detector — high-entropy hex and base64 tokens.

Each finding is attributed to its originating commit and file.

## Related tools

- [`altais_scan_secrets`](altais_scan_secrets.md) — pattern matching on a single block of text
- [`altais_scan_entropy`](altais_scan_entropy.md) — entropy detection on a single block of text

## See also

- [`secrets` module](../modules/secrets.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
