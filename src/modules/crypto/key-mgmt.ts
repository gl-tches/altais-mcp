// Key management auditor (altais_audit_key_mgmt).
//
// Accepts:
// - source: code pattern-matched for hardcoded keys and embedded PEM blocks
// - keys: a structured inventory of cryptographic keys to audit for
//   storage, rotation, and lifecycle issues

import type { Finding } from "../../core/types.js";
import { buildCryptoFinding, lineAt } from "./finding.js";

export type KeyStorage =
  | "hsm"
  | "kms"
  | "vault"
  | "secrets_manager"
  | "env_var"
  | "config_file"
  | "source_code"
  | "repo";

export interface KeyInventoryEntry {
  readonly name: string;
  readonly type?: "signing" | "encryption" | "root_ca" | "tls" | "api" | "master";
  readonly algorithm?: string;
  readonly key_size_bits?: number;
  readonly storage?: KeyStorage;
  readonly rotation_period_days?: number;
  readonly last_rotated_at?: string;
  readonly created_at?: string;
}

export interface KeyMgmtAuditInput {
  readonly source?: string;
  readonly keys?: readonly KeyInventoryEntry[];
  readonly filename?: string;
  /** ISO date used as "now" for age math; defaults to the current date. */
  readonly as_of?: string;
}

const REFS = [
  "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
  "https://owasp.org/www-project-cheat-sheets/cheatsheets/Key_Management_Cheat_Sheet.html",
  "https://cwe.mitre.org/data/definitions/320.html",
];

const INSECURE_STORAGE: ReadonlySet<KeyStorage> = new Set(["source_code", "repo"]);
const MANAGED_STORAGE: ReadonlySet<KeyStorage> = new Set(["hsm", "kms", "vault"]);
const HIGH_VALUE: ReadonlySet<NonNullable<KeyInventoryEntry["type"]>> = new Set([
  "signing",
  "root_ca",
  "master",
]);

const HARDCODED_KEY_RE =
  /(?:secret|private|signing|encryption|master|api)[_-]?key\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']/gi;
const PEM_PRIVATE_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g;

function daysBetween(fromIso: string, toIso: string): number | undefined {
  const from = Date.parse(fromIso);
  const to = Date.parse(toIso);
  if (Number.isNaN(from) || Number.isNaN(to)) return undefined;
  return Math.floor((to - from) / 86_400_000);
}

export function auditKeyMgmt(input: KeyMgmtAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) findings.push(...scanSource(input.source, input.filename));
  const asOf = input.as_of ?? new Date().toISOString();
  for (const key of input.keys ?? []) {
    findings.push(...auditKey(key, asOf, input.filename));
  }
  return findings;
}

function scanSource(source: string, filename: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  let m: RegExpExecArray | null;
  const keyRe = new RegExp(HARDCODED_KEY_RE.source, "gi");
  while ((m = keyRe.exec(source)) !== null) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-hardcoded-in-source",
          severity: "critical",
          title: "Cryptographic key hardcoded in source",
          description:
            "A key embedded in source is readable by anyone with repo access and cannot be rotated without a code change and redeploy.",
          remediation:
            "Move the key to a KMS / HSM / secrets manager. Reference it at runtime; never commit key material.",
          cwe: ["CWE-321", "CWE-798"],
          references: REFS,
          evidence: m[0].slice(0, 80),
          tags: ["key-storage"],
          line: lineAt(source, m.index),
        },
        filename,
      ),
    );
  }
  const pemRe = new RegExp(PEM_PRIVATE_RE.source, "g");
  while ((m = pemRe.exec(source)) !== null) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-private-pem-in-source",
          severity: "critical",
          title: "PEM private key embedded in source",
          description:
            "A private key block in source code is exposed to everyone with repo access.",
          remediation:
            "Remove the key, rotate it immediately (treat it as compromised), and load it from a secrets manager at runtime.",
          cwe: ["CWE-321", "CWE-798"],
          references: REFS,
          evidence: m[0],
          tags: ["key-storage"],
          line: lineAt(source, m.index),
        },
        filename,
      ),
    );
  }
  return findings;
}

function auditKey(
  key: KeyInventoryEntry,
  asOf: string,
  source: string | undefined,
): readonly Finding[] {
  const findings: Finding[] = [];

  if (key.storage !== undefined && INSECURE_STORAGE.has(key.storage)) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-insecure-storage",
          severity: "critical",
          title: `Key "${key.name}" stored in ${key.storage}`,
          description:
            "Storing key material in source or the repository exposes it to everyone with read access and to anyone who clones history.",
          remediation: "Migrate the key to a KMS / HSM / secrets manager and rotate it.",
          cwe: ["CWE-321", "CWE-798"],
          references: REFS,
          evidence: `${key.name}: storage=${key.storage}`,
          tags: ["key-storage"],
        },
        source,
      ),
    );
  }

  if (
    key.type !== undefined &&
    HIGH_VALUE.has(key.type) &&
    key.storage !== undefined &&
    !MANAGED_STORAGE.has(key.storage)
  ) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-high-value-not-in-hsm",
          severity: "high",
          title: `High-value key "${key.name}" (${key.type}) not in an HSM / KMS`,
          description:
            "Signing, root-CA, and master keys should be non-exportable. Outside an HSM/KMS the raw key can be read and exfiltrated.",
          remediation:
            "Store high-value keys in an HSM or cloud KMS with non-exportable key material; sign/decrypt via the service API.",
          cwe: ["CWE-320"],
          references: REFS,
          evidence: `${key.name}: type=${key.type}, storage=${key.storage}`,
          tags: ["key-storage"],
        },
        source,
      ),
    );
  }

  if (key.rotation_period_days === undefined) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-no-rotation-policy",
          severity: "medium",
          title: `Key "${key.name}" has no rotation policy`,
          description:
            "A key with no defined rotation period accumulates exposure: the longer it lives, the larger the blast radius of a compromise.",
          remediation:
            "Define a rotation period appropriate to the key type (e.g. 90 days for API/TLS keys, ≤1 year for signing keys).",
          cwe: ["CWE-320"],
          references: REFS,
          evidence: `${key.name}: rotation_period_days=unset`,
          tags: ["key-rotation"],
        },
        source,
      ),
    );
  } else if (key.last_rotated_at !== undefined) {
    const age = daysBetween(key.last_rotated_at, asOf);
    if (age !== undefined && age > key.rotation_period_days) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "key-rotation-overdue",
            severity: "high",
            title: `Key "${key.name}" rotation overdue (${age}d since rotation, policy ${key.rotation_period_days}d)`,
            description:
              "The key has not been rotated within its own policy window, extending the exposure of any leaked copy.",
            remediation: "Rotate the key now and automate rotation so it cannot lapse again.",
            cwe: ["CWE-320"],
            references: REFS,
            evidence: `${key.name}: age=${age}d, policy=${key.rotation_period_days}d`,
            tags: ["key-rotation"],
          },
          source,
        ),
      );
    }
  } else if (key.created_at !== undefined) {
    const age = daysBetween(key.created_at, asOf);
    if (age !== undefined && age > key.rotation_period_days) {
      findings.push(
        buildCryptoFinding(
          {
            rule: "key-never-rotated",
            severity: "high",
            title: `Key "${key.name}" never rotated (${age}d old, policy ${key.rotation_period_days}d)`,
            description:
              "The key has a rotation policy but no recorded rotation, and its age already exceeds the policy window.",
            remediation: "Rotate the key and record `last_rotated_at`; automate future rotations.",
            cwe: ["CWE-320"],
            references: REFS,
            evidence: `${key.name}: created ${key.created_at}, never rotated`,
            tags: ["key-rotation"],
          },
          source,
        ),
      );
    }
  }

  const algo = (key.algorithm ?? "").toLowerCase().replace(/[\s_-]/g, "");
  if (algo.startsWith("rsa") && key.key_size_bits !== undefined && key.key_size_bits < 2048) {
    findings.push(
      buildCryptoFinding(
        {
          rule: "key-weak-size",
          severity: "high",
          title: `Key "${key.name}" uses an RSA key below 2048 bits (${key.key_size_bits})`,
          description: "RSA keys under 2048 bits do not meet NIST minimum strength.",
          remediation: "Reissue with RSA-3072, or migrate to Ed25519 / ECDSA-P256.",
          cwe: ["CWE-326"],
          references: REFS,
          evidence: `${key.name}: ${key.algorithm}=${key.key_size_bits}b`,
          tags: ["key-strength"],
        },
        source,
      ),
    );
  }

  return findings;
}
