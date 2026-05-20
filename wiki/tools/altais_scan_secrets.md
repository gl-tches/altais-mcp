# `altais_scan_secrets`

Match input text against the bundled secret-pattern database.

| Property | Value |
|----------|-------|
| Module | [`secrets`](../modules/secrets.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans a block of text against the bundled secret-pattern registry covering known credential formats (AWS, GitHub, Slack, Stripe, GCP, JWT, PEM private keys, password-in-config, database DSNs, and more). It emits one finding per match with the literal secret redacted in the evidence field. An agent calls this to catch hardcoded credentials before they reach a commit.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1 char to the configured `max_source_bytes`) | Yes | Source text to scan for credentials and tokens. |
| `filename` | `string` (1–512 chars) | No | Filename used for finding location. |
| `rules` | `string[]` (up to 64 items, each 1–128 chars) | No | Restrict to specific secret-pattern IDs. Empty means all patterns run. |

## Output

`{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape; the `evidence` field shows a redacted form of the matched secret (e.g. `AKIA…MPLE (len 20)`). Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "aws-access-key-id",
      "severity": "high",
      "cwe": ["CWE-798"],
      "evidence": "AKIA…MPLE (len 20)"
    }
  ]
}
```

## Detections

Pattern-based credential matches, including:

- AWS access key IDs and secret keys
- GitHub, Slack, and Stripe tokens
- GCP service-account keys
- JWTs
- PEM private keys
- Passwords embedded in config
- Database connection strings (DSNs)

All emitted findings reference CWE-798 (Use of Hard-coded Credentials).

## Related tools

- [`altais_scan_entropy`](altais_scan_entropy.md) — catches random-looking secrets that match no known pattern
- [`altais_scan_git_secrets`](altais_scan_git_secrets.md) — runs this registry across git history

## See also

- [`secrets` module](../modules/secrets.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
