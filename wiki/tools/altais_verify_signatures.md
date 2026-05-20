# `altais_verify_signatures`

Classifies and inspects cosign or GPG signature metadata.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool classifies a signature payload — a cosign bundle, a cosign `.sig`, or an ASCII-armored GPG signature — and reports its metadata (media type, hash algorithm, transparency-log entries), flagging missing or weak fields. It performs no live cryptographic verification. An agent calls it when reviewing the signatures attached to a released artifact or commit.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `signature` | `string` (1–512 KiB) | Yes | A cosign bundle JSON, a raw cosign payload, or an ASCII-armored GPG signature. |

## Output

Returns a structured report — `kind` (the detected signature type), a `metadata` object (media type, hash algorithm, transparency-log entries, and similar), and a `findings` array of standard findings for missing or weak fields. Findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----" }
```

**Response (excerpt)**

```json
{
  "kind": "gpg",
  "metadata": { "hash_algorithm": "SHA-256" },
  "summary": { "total": 1, "by_severity": { "low": 1 } },
  "findings": [
    { "rule": "no-transparency-log", "severity": "low", "title": "Signature has no transparency-log entry" }
  ]
}
```

## Detections

- Weak or deprecated hash algorithm in the signature (CWE-327)
- Missing transparency-log entry — no tamper-evident record (CWE-345)
- Missing or malformed signature metadata fields (CWE-347)

## Related tools

- [`altais_verify_slsa`](altais_verify_slsa.md) — structurally verifies SLSA provenance attestations
- [`altais_check_build_integrity`](altais_check_build_integrity.md) — audits release signing in CI/CD

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
