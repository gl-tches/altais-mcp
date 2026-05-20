// Terraform HCL auditor (altais_audit_terraform).
//
// Scans Terraform configuration text for the misconfigurations that
// most often turn into real-world cloud incidents: world-open security
// groups, public object storage, unencrypted resources, hardcoded
// secrets, IAM wildcards, publicly accessible databases, disabled
// logging, and plaintext provider credentials. Terraform is HCL, but a
// line-oriented regex scan keeps the module dependency-free while
// covering the attributes that matter.

import type { Finding } from "../../core/types.js";
import { buildIacFinding, lineAt, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface TerraformAuditInput {
  readonly content: string;
  readonly filename?: string;
}

const REFS = [
  "https://developer.hashicorp.com/terraform/language",
  "https://owasp.org/www-project-top-ten/",
  "https://cwe.mitre.org/",
];

const PATTERNS: readonly SourcePattern[] = [
  {
    rule: "tf-public-storage-acl",
    regex: /^[ \t]*acl[ \t]*=[ \t]*"public-read(?:-write)?"/im,
    severity: "high",
    title: "Object storage bucket has a public ACL",
    description:
      "A `public-read` or `public-read-write` ACL exposes bucket objects to the entire internet. Anyone can list and download — and with `public-read-write`, overwrite — stored data.",
    remediation:
      'Set `acl = "private"` and serve content through signed URLs or a CDN. Enable account-level public-access blocking so a stray ACL cannot re-expose the bucket.',
    cwe: ["CWE-732", "CWE-284"],
    tags: ["terraform", "storage"],
  },
  {
    rule: "tf-public-access-block-disabled",
    regex: /^[ \t]*block_public_acls[ \t]*=[ \t]*false/im,
    severity: "high",
    title: "Public-access blocking is disabled on a storage bucket",
    description:
      "`block_public_acls = false` removes the safety net that prevents a bucket policy or ACL from making objects world-readable. A single misconfigured ACL then leaks data.",
    remediation:
      "Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`, and `restrict_public_buckets` all to `true` on the public-access-block resource.",
    cwe: ["CWE-732", "CWE-284"],
    tags: ["terraform", "storage"],
  },
  {
    rule: "tf-unencrypted-resource",
    regex: /^[ \t]*(?:encrypted|storage_encrypted)[ \t]*=[ \t]*false/im,
    severity: "high",
    title: "Resource is created without encryption at rest",
    description:
      "`encrypted = false` / `storage_encrypted = false` stores volume or database data in plaintext on disk. Anyone with access to the underlying storage media or a snapshot reads it directly.",
    remediation:
      "Set the encryption attribute to `true` and supply a customer-managed `kms_key_id`. Encryption at rest cannot be enabled on most resources after creation.",
    cwe: ["CWE-311", "CWE-312"],
    tags: ["terraform", "encryption"],
  },
  {
    rule: "tf-publicly-accessible-db",
    regex: /^[ \t]*publicly_accessible[ \t]*=[ \t]*true/im,
    severity: "critical",
    title: "Database instance is publicly accessible",
    description:
      "`publicly_accessible = true` assigns the database a public endpoint reachable from the internet. Combined with a weak password or an open security group this is a direct path to data exfiltration.",
    remediation:
      "Set `publicly_accessible = false`, place the instance in private subnets, and reach it only from within the VPC or over a bastion / VPN.",
    cwe: ["CWE-284", "CWE-668"],
    tags: ["terraform", "database"],
  },
  {
    rule: "tf-logging-disabled",
    regex: /^[ \t]*enable_logging[ \t]*=[ \t]*false/im,
    severity: "medium",
    title: "Audit or access logging is explicitly disabled",
    description:
      "`enable_logging = false` turns off the access / audit log stream for the resource. Without logs an intrusion is invisible and post-incident forensics are impossible.",
    remediation:
      "Set `enable_logging = true` and ship logs to a centralized, tamper-resistant log store with retention that meets your compliance requirements.",
    cwe: ["CWE-778", "CWE-16"],
    tags: ["terraform", "logging"],
  },
];

// A security-group / firewall ingress block opened to the whole internet.
const WORLD_CIDR_RE = /^[ \t]*cidr_blocks[ \t]*=[ \t]*\[([^\]]*)\]/gim;

// Generic and inline `from_port` / `to_port` extraction for an ingress block.
const PORT_RE = /\b(?:from_port|to_port)[ \t]*=[ \t]*(\d+)/g;

// IAM policy wildcards in both JSON-encoded and native HCL list form.
// The optional `\\?` tolerates JSON embedded in an escaped HCL string.
const IAM_JSON_WILDCARD_RE = /\\?"(?:Action|Resource)\\?"[ \t]*:[ \t]*\\?"\*\\?"/gi;
const IAM_HCL_WILDCARD_RE = /^[ \t]*(?:actions|resources)[ \t]*=[ \t]*\[[ \t]*"\*"[ \t]*\]/gim;

// Hardcoded secret assignments. `password`, `secret`, `access_key`, `token`.
const SECRET_RE =
  /^[ \t]*([A-Za-z0-9_]*(?:password|passwd|secret|access_key|secret_key|token|api_key|private_key)[A-Za-z0-9_]*)[ \t]*=[ \t]*"([^"]*)"/gim;

export function auditTerraform(input: TerraformAuditInput): readonly Finding[] {
  const file = input.filename ?? "main.tf";
  const src = input.content;
  const findings: Finding[] = [...scanWithPatterns(src, PATTERNS, REFS, file)];

  // ── World-open security-group / firewall ingress ──────────────────────
  let cidr: RegExpExecArray | null;
  while ((cidr = WORLD_CIDR_RE.exec(src)) !== null) {
    const list = cidr[1] ?? "";
    if (!list.includes("0.0.0.0/0")) continue;
    const line = lineAt(src, cidr.index);
    // Look at the surrounding ~600 characters for the ingress ports.
    const window = src.slice(Math.max(0, cidr.index - 600), cidr.index + 200);
    const ports = collectPorts(window);
    const ssh = ports.has(22);
    const rdp = ports.has(3389);
    findings.push(
      buildIacFinding(
        {
          rule: ssh || rdp ? "tf-world-open-admin-port" : "tf-world-open-ingress",
          severity: ssh || rdp ? "critical" : "high",
          title:
            ssh || rdp
              ? `Security group exposes ${ssh ? "SSH (22)" : "RDP (3389)"} to the entire internet`
              : "Security group ingress is open to the entire internet",
          description:
            ssh || rdp
              ? "An ingress rule allows `0.0.0.0/0` to reach a remote-administration port. This invites continuous brute-force and exploitation traffic against SSH / RDP from the whole internet."
              : "An ingress rule uses the `0.0.0.0/0` CIDR, so the listed ports are reachable from any host on the internet. This widens the attack surface far beyond what most services need.",
          remediation:
            "Restrict `cidr_blocks` to the specific office / VPN / peer ranges that need access. For administrative access prefer a bastion host or a zero-trust access proxy instead of an open port.",
          cwe: ["CWE-284", "CWE-668"],
          references: REFS,
          evidence: `cidr_blocks = [${list.trim().slice(0, 120)}]`,
          tags: ["terraform", "network"],
          line,
        },
        file,
      ),
    );
  }

  // ── IAM wildcards (JSON-encoded policies) ─────────────────────────────
  let jsonW: RegExpExecArray | null;
  while ((jsonW = IAM_JSON_WILDCARD_RE.exec(src)) !== null) {
    findings.push(iamWildcardFinding(file, lineAt(src, jsonW.index), jsonW[0]));
  }

  // ── IAM wildcards (native HCL list form) ──────────────────────────────
  let hclW: RegExpExecArray | null;
  while ((hclW = IAM_HCL_WILDCARD_RE.exec(src)) !== null) {
    findings.push(iamWildcardFinding(file, lineAt(src, hclW.index), hclW[0].trim()));
  }

  // ── Hardcoded secrets / plaintext provider credentials ────────────────
  let secret: RegExpExecArray | null;
  while ((secret = SECRET_RE.exec(src)) !== null) {
    const name = secret[1] ?? "";
    const value = secret[2] ?? "";
    // Interpolated values (`${var.x}`, `var.x`) and empty strings are not leaks.
    if (value === "" || value.includes("${") || value.startsWith("var.")) continue;
    const line = lineAt(src, secret.index);
    const isProviderCred = /access_key|secret_key/i.test(name);
    findings.push(
      buildIacFinding(
        {
          rule: isProviderCred ? "tf-plaintext-provider-credential" : "tf-hardcoded-secret",
          severity: "critical",
          title: isProviderCred
            ? `Plaintext provider credential in Terraform (\`${name}\`)`
            : `Hardcoded secret in Terraform (\`${name}\`)`,
          description: isProviderCred
            ? "A provider `access_key` / `secret_key` written as a string literal is committed to version control and recorded in plaintext in the Terraform state file."
            : "A literal password, token, or key in Terraform configuration is committed to version control and stored in plaintext in the Terraform state file, readable by anyone with state access.",
          remediation: isProviderCred
            ? "Remove the literal credential. Supply provider credentials via environment variables, a shared credentials file, or an OIDC / instance-role assumption — never inline."
            : "Move the value into a sensitive input variable populated from a secrets manager (Vault, AWS Secrets Manager) and mark the variable `sensitive = true`.",
          cwe: ["CWE-798", "CWE-312"],
          references: REFS,
          evidence: `${name} = "********"`,
          tags: ["terraform", "secrets"],
          line,
        },
        file,
      ),
    );
  }

  return findings;
}

/** Collect every `from_port` / `to_port` value found in a text window. */
function collectPorts(window: string): ReadonlySet<number> {
  const ports = new Set<number>();
  const re = new RegExp(PORT_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(window)) !== null) {
    const n = Number(m[1] ?? "");
    if (Number.isFinite(n)) ports.add(n);
  }
  return ports;
}

function iamWildcardFinding(file: string, line: number, evidence: string): Finding {
  return buildIacFinding(
    {
      rule: "tf-iam-wildcard",
      severity: "high",
      title: "IAM policy grants a wildcard action or resource",
      description:
        "An IAM policy statement uses `*` for `Action` or `Resource`. This grants far more privilege than any single workload needs and breaks the principle of least privilege — a compromised credential can then do anything.",
      remediation:
        "Replace the `*` with the explicit list of actions and resource ARNs the workload actually requires. Generate a tight policy from observed access (e.g. with an access analyzer).",
      cwe: ["CWE-284", "CWE-732"],
      references: REFS,
      evidence: evidence.slice(0, 200),
      tags: ["terraform", "iam"],
      line,
    },
    file,
  );
}
