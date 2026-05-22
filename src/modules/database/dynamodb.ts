// altais_audit_dynamodb — AWS DynamoDB configuration audit.
//
// Reviews encryption at rest and key ownership, point-in-time recovery,
// VPC-endpoint usage, IAM-policy scoping, deletion protection, and
// fine-grained access control.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/security-best-practices.html",
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
];

export const dynamodbSchema = z.object({
  config: z.object({
    encryption_at_rest: z
      .enum(["customer-managed", "aws-managed", "aws-owned", "disabled"])
      .optional()
      .describe("The encryption-at-rest key type for the table."),
    point_in_time_recovery_enabled: z
      .boolean()
      .optional()
      .describe("Whether point-in-time recovery (PITR) is enabled."),
    vpc_endpoint_used: z
      .boolean()
      .optional()
      .describe("Whether access goes through a VPC (gateway) endpoint."),
    iam_wildcard_actions: z
      .boolean()
      .optional()
      .describe("Whether an IAM policy grants wildcard dynamodb:* actions."),
    iam_wildcard_resources: z
      .boolean()
      .optional()
      .describe("Whether an IAM policy grants access to Resource: * (all tables)."),
    deletion_protection_enabled: z
      .boolean()
      .optional()
      .describe("Whether table deletion protection is enabled."),
    fine_grained_access_control: z
      .boolean()
      .optional()
      .describe("Whether item-level access control (dynamodb:LeadingKeys conditions) is used."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type DynamodbInput = z.infer<typeof dynamodbSchema>;
type DynamodbConfig = DynamodbInput["config"];

const CHECKS: readonly ConfigCheck<DynamodbConfig>[] = [
  {
    rule: "dynamodb-encryption-disabled",
    when: (c) => c.encryption_at_rest === "disabled",
    severity: "high",
    title: "DynamoDB table encryption at rest is disabled",
    description:
      "An unencrypted table stores all item data in cleartext at the storage layer, failing the baseline expectation for data at rest.",
    remediation:
      "Enable encryption at rest. Prefer an AWS KMS customer-managed key (CMK) so key usage is auditable and access is independently controlled.",
    cwe: ["CWE-311"],
  },
  {
    rule: "dynamodb-no-customer-managed-key",
    when: (c) => c.encryption_at_rest === "aws-owned",
    severity: "low",
    title: "DynamoDB table uses an AWS-owned encryption key",
    description:
      "An AWS-owned key gives no visibility or control: usage cannot be audited via CloudTrail and access cannot be revoked or scoped with a key policy.",
    remediation:
      "Switch to an AWS KMS customer-managed key (CMK) so key usage is logged and the key policy can enforce least privilege.",
  },
  {
    rule: "dynamodb-no-point-in-time-recovery",
    when: (c) => c.point_in_time_recovery_enabled === false,
    severity: "medium",
    title: "DynamoDB point-in-time recovery is disabled",
    description:
      "Without PITR there is no continuous backup; accidental or malicious deletes and overwrites cannot be rolled back to a recent state.",
    remediation:
      "Enable point-in-time recovery on the table so it can be restored to any second within the retention window.",
  },
  {
    rule: "dynamodb-no-vpc-endpoint",
    when: (c) => c.vpc_endpoint_used === false,
    severity: "low",
    title: "DynamoDB access does not use a VPC endpoint",
    description:
      "Without a VPC gateway endpoint, DynamoDB traffic leaves the VPC to the public service endpoint. A VPC endpoint keeps the traffic on the AWS private network and lets an endpoint policy constrain access.",
    remediation:
      "Create a DynamoDB VPC gateway endpoint and attach an endpoint policy that limits which tables and actions are reachable from the VPC.",
  },
  {
    rule: "dynamodb-iam-wildcard-actions",
    when: (c) => c.iam_wildcard_actions === true,
    severity: "high",
    title: "DynamoDB IAM policy grants wildcard actions",
    description:
      "A policy granting `dynamodb:*` lets the principal create, delete, export, and reconfigure tables — far beyond the read/write an application needs.",
    remediation:
      "Grant only the specific actions the workload uses (`GetItem`, `PutItem`, `Query`, ...). Keep table management actions out of the application role.",
    cwe: ["CWE-250"],
  },
  {
    rule: "dynamodb-iam-wildcard-resources",
    when: (c) => c.iam_wildcard_resources === true,
    severity: "high",
    title: "DynamoDB IAM policy grants access to all tables",
    description:
      "`Resource: *` lets the principal reach every DynamoDB table in the account, so a compromised credential is not contained to one application's data.",
    remediation:
      "Scope the policy `Resource` to the specific table ARNs (and index ARNs) the workload uses.",
    cwe: ["CWE-284"],
  },
  {
    rule: "dynamodb-no-deletion-protection",
    when: (c) => c.deletion_protection_enabled === false,
    severity: "low",
    title: "DynamoDB table deletion protection is disabled",
    description:
      "Without deletion protection, a single API call or misapplied infrastructure change can delete the table and all its data.",
    remediation:
      "Enable deletion protection on production tables so an explicit, deliberate step is required before a table can be removed.",
  },
  {
    rule: "dynamodb-no-fine-grained-access",
    when: (c) => c.fine_grained_access_control === false,
    severity: "medium",
    title: "DynamoDB fine-grained access control is not used",
    description:
      "Without `dynamodb:LeadingKeys` (and attribute) conditions, any principal with table access can read every item, so application-layer scoping is the only thing separating tenants or users.",
    remediation:
      "Add IAM condition keys (`dynamodb:LeadingKeys`, `dynamodb:Attributes`) so each principal can only reach the partition keys and attributes it owns.",
    cwe: ["CWE-285"],
  },
];

/** Audit an AWS DynamoDB configuration. */
export function auditDynamodb(input: DynamodbInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
