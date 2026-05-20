// Crypto module: 9 auditors for cryptographic algorithm usage, TLS
// configuration, insecure randomness, key management, post-quantum
// readiness, CT log monitoring, certificate pinning, ACME, and
// cryptographic agility.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditAcme } from "./acme.js";
import { assessCryptoAgility } from "./agility.js";
import { auditCrypto } from "./algorithms.js";
import { auditCertPinning } from "./cert-pinning.js";
import { auditCtLogs } from "./ct-monitoring.js";
import { auditKeyMgmt } from "./key-mgmt.js";
import { assessPqReadiness } from "./post-quantum.js";
import { auditRandomness } from "./randomness.js";
import { auditTls } from "./tls.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface CryptoModuleDeps {
  readonly findingStore: FindingStore;
}

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function summarize(findings: readonly Finding[]): {
  total: number;
  by_severity: Record<string, number>;
} {
  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return { total: findings.length, by_severity: bySeverity };
}

const sourceField = z
  .string()
  .min(1)
  .max(2 * 1024 * 1024)
  .optional()
  .describe("Optional source code to scan with pattern checks.");

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename for finding location.");

function makeRunner<TInput>(
  deps: CryptoModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
  shape: (findings: readonly Finding[], data: TInput) => unknown,
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(shape(findings, parsed.data)));
  };
}

function zodParser<T>(
  schema: z.ZodType<T>,
): (args: unknown) => { success: true; data: T } | { success: false; message: string } {
  return (args) => {
    const r = schema.safeParse(args);
    if (r.success) return { success: true, data: r.data };
    return {
      success: false,
      message: r.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; "),
    };
  };
}

function withSummary(findings: readonly Finding[]): unknown {
  return { summary: summarize(findings), findings };
}

// ─── altais_audit_crypto ───────────────────────────────────────────────────

const cryptoSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      algorithms: z
        .array(
          z.object({
            name: z.string().min(1).max(128),
            purpose: z
              .enum(["hashing", "encryption", "signing", "key_exchange", "mac", "kdf"])
              .optional(),
            key_size_bits: z.number().int().min(0).max(65536).optional(),
          }),
        )
        .max(256)
        .optional(),
    })
    .optional(),
});

function buildCryptoTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_crypto",
    title: "Audit cryptographic algorithm usage",
    description:
      "Scan source and / or a structured algorithm inventory for weak ciphers and deprecated hashes (MD5/SHA-1/DES/3DES/RC4/Blowfish), ECB mode, static IVs / salts, the broken `crypto.createCipher` API, and undersized RSA / symmetric keys.",
    inputSchema: cryptoSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(cryptoSchema),
      (d) => auditCrypto(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_tls ──────────────────────────────────────────────────────

const tlsVersionEnum = z.enum(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]);

const tlsSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      min_version: tlsVersionEnum.optional(),
      enabled_versions: z.array(tlsVersionEnum).max(8).optional(),
      cipher_suites: z.array(z.string().min(1).max(128)).max(128).optional(),
      verify_certificates: z.boolean().optional(),
      hsts: z.boolean().optional(),
      compression: z.boolean().optional(),
    })
    .optional(),
});

function buildTlsTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_tls",
    title: "Audit TLS configuration",
    description:
      "Review a TLS configuration or client/server source for deprecated protocols (SSLv3 / TLS 1.0 / 1.1), a too-low minimum version, weak cipher suites, disabled certificate verification (`rejectUnauthorized:false`, `verify=False`, `InsecureSkipVerify`), TLS compression (CRIME), and missing HSTS.",
    inputSchema: tlsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(tlsSchema),
      (d) => auditTls(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_randomness ───────────────────────────────────────────────

const randomnessSchema = z.object({
  source: z
    .string()
    .min(1)
    .max(2 * 1024 * 1024)
    .describe("Source code to scan for insecure random number generation."),
  filename: filenameField,
});

function buildRandomnessTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_randomness",
    title: "Audit random number generation",
    description:
      "Scan source for non-cryptographic PRNGs (`Math.random`, Python `random`, `java.util.Random`, Go `math/rand`, C `rand`/`mt19937`) and time-seeded generators. Findings near a security keyword (token / key / secret / nonce) are escalated to high severity.",
    inputSchema: randomnessSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(randomnessSchema),
      (d) => auditRandomness(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_key_mgmt ─────────────────────────────────────────────────

const keyMgmtSchema = z.object({
  source: sourceField,
  filename: filenameField,
  as_of: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe("ISO date used as 'now' for key-age math. Defaults to the current date."),
  keys: z
    .array(
      z.object({
        name: z.string().min(1).max(256),
        type: z.enum(["signing", "encryption", "root_ca", "tls", "api", "master"]).optional(),
        algorithm: z.string().min(1).max(64).optional(),
        key_size_bits: z.number().int().min(0).max(65536).optional(),
        storage: z
          .enum([
            "hsm",
            "kms",
            "vault",
            "secrets_manager",
            "env_var",
            "config_file",
            "source_code",
            "repo",
          ])
          .optional(),
        rotation_period_days: z.number().int().min(0).max(36500).optional(),
        last_rotated_at: z.string().min(1).max(64).optional(),
        created_at: z.string().min(1).max(64).optional(),
      }),
    )
    .max(1000)
    .optional(),
});

function buildKeyMgmtTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_key_mgmt",
    title: "Audit key management",
    description:
      "Scan source for hardcoded keys / embedded PEM private keys, and audit a structured key inventory for insecure storage, high-value keys outside an HSM/KMS, missing or overdue rotation, never-rotated keys, and undersized RSA keys.",
    inputSchema: keyMgmtSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(keyMgmtSchema),
      (d) => auditKeyMgmt(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_assess_pq_readiness ────────────────────────────────────────────

const pqSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      algorithms: z.array(z.string().min(1).max(128)).max(256).optional(),
      data_retention_years: z.number().int().min(0).max(200).optional(),
      uses_hybrid: z.boolean().optional(),
    })
    .optional(),
});

function buildPqTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_assess_pq_readiness",
    title: "Assess post-quantum cryptography readiness",
    description:
      "Flag quantum-vulnerable classical asymmetric primitives (RSA / ECDSA / ECDH / DH / X25519) broken by Shor's algorithm, assess 'harvest now, decrypt later' exposure for long-retention data, and check for hybrid key exchange and NIST PQC algorithms (ML-KEM / ML-DSA / SLH-DSA).",
    inputSchema: pqSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(pqSchema),
      (d) => assessPqReadiness(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_ct_logs ──────────────────────────────────────────────────

const ctSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      monitoring_enabled: z.boolean().optional(),
      owned_domains: z.array(z.string().min(1).max(256)).max(512).optional(),
      monitored_domains: z.array(z.string().min(1).max(256)).max(512).optional(),
      alerting_enabled: z.boolean().optional(),
      requires_sct: z.boolean().optional(),
    })
    .optional(),
});

function buildCtLogsTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_ct_logs",
    title: "Audit Certificate Transparency monitoring",
    description:
      "Check whether CT log monitoring is enabled for every owned domain, whether mis-issuance alerts are routed to a responder, whether the server delivers SCTs, and flag reliance on the deprecated `Expect-CT` header.",
    inputSchema: ctSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(ctSchema),
      (d) => auditCtLogs(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_cert_pinning ─────────────────────────────────────────────

const certPinningSchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      pinning_enabled: z.boolean().optional(),
      pin_type: z.enum(["leaf_certificate", "public_key", "ca_certificate"]).optional(),
      pin_count: z.number().int().min(0).max(64).optional(),
      has_backup_pin: z.boolean().optional(),
      enforced: z.boolean().optional(),
      platform: z.enum(["android", "ios", "web", "backend"]).optional(),
    })
    .optional(),
});

function buildCertPinningTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_cert_pinning",
    title: "Audit certificate pinning",
    description:
      "Review certificate pinning: flag the dead HPKP `Public-Key-Pins` header, leaf-certificate pinning (vs. SPKI), pinning with no backup pin (brick risk), and report-only / non-enforcing pinning. Notes absent pinning for mobile platforms.",
    inputSchema: certPinningSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(certPinningSchema),
      (d) => auditCertPinning(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_audit_acme ─────────────────────────────────────────────────────

const acmeSchema = z.object({
  filename: filenameField,
  config: z.object({
    provider: z.string().min(1).max(128).optional(),
    challenge_type: z.enum(["http-01", "dns-01", "tls-alpn-01"]).optional(),
    auto_renewal: z.boolean().optional(),
    renewal_threshold_days: z.number().int().min(0).max(365).optional(),
    wildcard: z.boolean().optional(),
    caa_configured: z.boolean().optional(),
    key_type: z.enum(["rsa", "ecdsa"]).optional(),
    key_size_bits: z.number().int().min(0).max(65536).optional(),
    staging_endpoint: z.boolean().optional(),
    account_key_storage: z.enum(["hsm", "kms", "vault", "file", "repo"]).optional(),
  }),
});

function buildAcmeTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_acme",
    title: "Audit ACME / Let's Encrypt configuration",
    description:
      "Review an ACME setup for missing renewal automation, a renewal threshold too close to expiry, http-01 used for a wildcard (which requires dns-01), missing CAA records, weak certificate keys, use of the staging endpoint in production, and insecure account-key storage.",
    inputSchema: acmeSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(acmeSchema),
      (d) => auditAcme(d),
      (findings) => withSummary(findings),
    ),
  };
}

// ─── altais_assess_crypto_agility ──────────────────────────────────────────

const agilitySchema = z.object({
  source: sourceField,
  filename: filenameField,
  config: z
    .object({
      algorithm_from_config: z.boolean().optional(),
      versioned_ciphertext: z.boolean().optional(),
      abstraction_layer: z.boolean().optional(),
      inventory_exists: z.boolean().optional(),
      rotation_without_redeploy: z.boolean().optional(),
    })
    .optional(),
});

function buildAgilityTool(deps: CryptoModuleDeps): ToolDefinition {
  return {
    name: "altais_assess_crypto_agility",
    title: "Assess cryptographic agility",
    description:
      "Assess whether the system can swap a cryptographic primitive without code changes: flags algorithm names hardcoded across the codebase, ciphertext with no version identifier (blocks data migration), no abstraction layer, no cryptographic inventory (CBOM), and rotation that requires a redeploy.",
    inputSchema: agilitySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(
      deps,
      zodParser(agilitySchema),
      (d) => assessCryptoAgility(d),
      (findings) => withSummary(findings),
    ),
  };
}

export function createCryptoModule(deps: CryptoModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildCryptoTool(deps),
    buildTlsTool(deps),
    buildRandomnessTool(deps),
    buildKeyMgmtTool(deps),
    buildPqTool(deps),
    buildCtLogsTool(deps),
    buildCertPinningTool(deps),
    buildAcmeTool(deps),
    buildAgilityTool(deps),
  ];
  return {
    name: "crypto",
    description:
      "Crypto audits: algorithm / cipher usage, TLS configuration, insecure randomness, key management, post-quantum readiness, CT log monitoring, certificate pinning, ACME, cryptographic agility.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
