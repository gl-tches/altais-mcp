# `altais_verify_slsa`

Structurally verifies a SLSA provenance attestation.

| Property | Value |
|----------|-------|
| Module | [`supply_chain`](../modules/supply_chain.md) |
| Tool type | Auditor (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

This tool parses a DSSE-wrapped SLSA v1 provenance attestation (or a bare in-toto Statement) and checks it for required fields: `predicateType`, `builder.id`, `buildDefinition.buildType`, subjects, and signatures. It performs structural verification only — it does not cryptographically verify the signature, which requires a trust store outside this tool. An agent calls it when reviewing build provenance for a released artifact.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `attestation` | `string` (1–1 MiB) | Yes | SLSA provenance: a DSSE envelope JSON, or an in-toto Statement JSON. |

## Output

Returns a structured report — `predicate_type`, a `checks` array (each `{ field, present }`) recording which required fields were located, and a `findings` array of standard findings for missing or malformed fields. Findings are appended to the session report `FindingStore`.

## Example

**Request**

```json
{ "attestation": "{ \"payloadType\": \"application/vnd.in-toto+json\", \"payload\": \"...\", \"signatures\": [] }" }
```

**Response (excerpt)**

```json
{
  "predicate_type": "https://slsa.dev/provenance/v1",
  "checks": [ { "field": "builder.id", "present": true } ],
  "summary": { "total": 1, "by_severity": { "medium": 1 } },
  "findings": [
    { "rule": "missing-signatures", "severity": "medium", "title": "DSSE envelope carries no signatures" }
  ]
}
```

## Detections

- Missing or unexpected `predicateType` (CWE-345)
- Missing `builder.id` — unattributed build (CWE-345)
- Missing `buildDefinition.buildType` (CWE-345)
- Missing subjects — provenance not bound to an artifact (CWE-345)
- Missing DSSE signatures (CWE-347)

## Related tools

- [`altais_verify_signatures`](altais_verify_signatures.md) — inspects cosign / GPG signature metadata
- [`altais_check_build_integrity`](altais_check_build_integrity.md) — audits the CI/CD pipeline that produces provenance

## See also

- [`supply_chain` module](../modules/supply_chain.md)
- [Wiki home](../Home.md) · [Contributing](../Contributing.md) · [Deployment](../Deployment.md)
