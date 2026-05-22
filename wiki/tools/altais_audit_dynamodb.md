# `altais_audit_dynamodb`

Audits an AWS DynamoDB configuration.

| Property | Value |
|----------|-------|
| Module | [`database`](../modules/database.md) |
| Tool type | Analyzer (emits findings) |
| Annotations | `readOnlyHint: true` · `destructiveHint: false` · `idempotentHint: true` · `openWorldHint: false` |

## Description

Reviews a supplied AWS DynamoDB configuration object for encryption at rest and key ownership, point-in-time recovery, VPC-endpoint usage, IAM-policy scoping, deletion protection, and fine-grained access control. Every field is optional.

## Input parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | `object` | Yes | Known DynamoDB settings (encryption-at-rest key type, PITR, VPC endpoint, IAM wildcard actions / resources, deletion protection, fine-grained access control). |
| `filename` | `string` | No | Filename used for the finding location. |

## Detections

- Encryption at rest disabled (CWE-311) or using an AWS-owned key with no auditability.
- Point-in-time recovery disabled; no VPC endpoint.
- IAM policies with wildcard actions (CWE-250) or wildcard resources (CWE-284).
- Deletion protection disabled; no fine-grained, item-level access control (CWE-285).

## See also

- [`database` module](../modules/database.md)
- [Wiki home](../Home.md)
