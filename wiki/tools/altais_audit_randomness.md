# `altais_audit_randomness`

Scans source code for non-cryptographic pseudo-random number generators used in security-sensitive contexts.

| Property | Value |
|----------|-------|
| Module | [`crypto`](../modules/crypto.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Scans source code for non-cryptographic PRNGs — `Math.random`, Python `random`, `java.util.Random`, Go `math/rand`, C `rand`/`mt19937` — and for time-seeded generators. Findings located near a security keyword (token, key, secret, nonce) are escalated to high severity. An agent calls this when reviewing code that generates tokens, identifiers, nonces, or other values that must be unpredictable.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source` | `string` (1–2097152 chars) | Yes | Source code to scan for insecure random number generation. |
| `filename` | `string` (1–512 chars) | No | Filename used for the finding location. |

## Output

Returns `{ summary: { total, by_severity }, findings: [...] }`. Each finding has the standard shape `{ id, module, rule, severity, cwe, title, description, location?, evidence?, remediation, references, tags, status }`. Findings are appended to the session report.

## Example

**Request**

```json
{ "source": "const token = Math.random().toString(36)" }
```

**Response (excerpt)**

```json
{
  "summary": { "total": 1, "by_severity": { "high": 1 } },
  "findings": [
    {
      "rule": "insecure-prng",
      "severity": "high",
      "cwe": ["CWE-338"],
      "title": "Non-cryptographic PRNG used in a security context",
      "status": "open"
    }
  ]
}
```

## Detections

- Non-cryptographic PRNGs — `Math.random`, Python `random`, `java.util.Random`, Go `math/rand`, C `rand`/`mt19937` (CWE-330, CWE-338)
- Time-seeded random generators (CWE-337)
- Severity escalated to high near a security keyword (token, key, secret, nonce)

## Related tools

- [`altais_audit_crypto`](altais_audit_crypto.md) — audits cryptographic algorithm usage
- [`altais_audit_key_mgmt`](altais_audit_key_mgmt.md) — audits key generation and storage

## See also

- [`crypto` module](../modules/crypto.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
