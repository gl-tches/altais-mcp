// Supply-chain module: 10 tools spanning vuln audit, SBOM generation,
// license / typosquat / dependency-confusion checks, SLSA + signature
// inspection, VEX emission, and build-pipeline / registry audits.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditPackages, OsvDatabase } from "./audit.js";
import { checkBuildIntegrity } from "./build-integrity.js";
import { checkDependencyConfusion } from "./dep-confusion.js";
import { checkLicenses, DEFAULT_ALLOW, DEFAULT_DENY, DEFAULT_WARN } from "./licenses.js";
import {
  detectLockfileKind,
  type LockfileKind,
  LOCKFILE_KINDS,
  parseLockfile,
} from "./lockfiles/index.js";
import { auditRegistryConfig } from "./registry.js";
import { generateSbom } from "./sbom.js";
import { inspectSignature } from "./signatures.js";
import { verifySlsa } from "./slsa.js";
import { detectTyposquat } from "./typosquat.js";
import { generateVex } from "./vex.js";

const MODULE_VERSION = "0.2.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface SupplyChainModuleDeps {
  readonly findingStore: FindingStore;
  readonly dataDir?: string;
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

const lockfileSchema = {
  content: z
    .string()
    .min(1)
    .max(8 * 1024 * 1024)
    .describe("Raw lockfile content."),
  kind: z
    .enum(LOCKFILE_KINDS as unknown as readonly [LockfileKind, ...LockfileKind[]])
    .optional()
    .describe("Lockfile kind. Inferred from `filename` if omitted."),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Filename for kind detection and finding location."),
};

function resolveKind(args: {
  kind?: LockfileKind;
  filename?: string;
}): { kind: LockfileKind } | { error: string } {
  if (args.kind) return { kind: args.kind };
  if (args.filename) {
    const detected = detectLockfileKind(args.filename);
    if (detected) return { kind: detected };
  }
  return { error: "Provide `kind` (npm/cargo/poetry/go) or a recognized `filename`." };
}

function buildAuditTool(deps: SupplyChainModuleDeps, db: OsvDatabase): ToolDefinition {
  const inputSchema = lockfileSchema;
  return {
    name: "altais_audit_deps",
    title: "Audit dependencies against the bundled vuln database",
    description:
      "Parse a lockfile (npm / cargo / poetry / go) and match every (name, version) pair against the bundled OSV snapshot. Returns findings per vulnerable package; the database is small and curated — replace `data/osv-snapshot.json` with a fresh export for production use.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const kindArg: { kind?: LockfileKind; filename?: string } = {};
      if (parsed.data.kind !== undefined) kindArg.kind = parsed.data.kind;
      if (parsed.data.filename !== undefined) kindArg.filename = parsed.data.filename;
      const r = resolveKind(kindArg);
      if ("error" in r) return errorResult(r.error);
      let parsedLock;
      try {
        parsedLock = parseLockfile(parsed.data.content, r.kind);
      } catch (err) {
        return errorResult(`Failed to parse ${r.kind} lockfile: ${(err as Error).message}`);
      }
      const audit = auditPackages(parsedLock, db, parsed.data.filename);
      deps.findingStore.addMany(audit.findings);
      return textResult(jsonText(audit));
    },
  };
}

function buildSbomTool(): ToolDefinition {
  const inputSchema = {
    ...lockfileSchema,
    format: z.enum(["cyclonedx", "spdx"]).default("cyclonedx"),
    project_name: z.string().min(1).max(256).optional(),
    project_version: z.string().min(1).max(64).optional(),
  };
  return {
    name: "altais_generate_sbom",
    title: "Generate an SBOM from a lockfile",
    description:
      "Emit a CycloneDX 1.5 or SPDX 2.3 software bill of materials from a lockfile (npm / cargo / poetry / go). The document includes PURLs and any hashes the lockfile carries.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const kindArg: { kind?: LockfileKind; filename?: string } = {};
      if (parsed.data.kind !== undefined) kindArg.kind = parsed.data.kind;
      if (parsed.data.filename !== undefined) kindArg.filename = parsed.data.filename;
      const r = resolveKind(kindArg);
      if ("error" in r) return errorResult(r.error);
      const parsedLock = parseLockfile(parsed.data.content, r.kind);
      const sbom = generateSbom(parsedLock, {
        format: parsed.data.format,
        ...(parsed.data.project_name !== undefined
          ? { project_name: parsed.data.project_name }
          : {}),
        ...(parsed.data.project_version !== undefined
          ? { project_version: parsed.data.project_version }
          : {}),
        tool_name: "altais-mcp",
        tool_version: MODULE_VERSION,
      });
      return textResult(jsonText(sbom));
    },
  };
}

function buildLicenseTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    ...lockfileSchema,
    allow: z.array(z.string().min(1).max(128)).max(256).optional(),
    warn: z.array(z.string().min(1).max(128)).max(256).optional(),
    deny: z.array(z.string().min(1).max(128)).max(256).optional(),
  };
  return {
    name: "altais_check_licenses",
    title: "Check dependency licenses against allow / warn / deny lists",
    description:
      "Classify every dependency's declared license against three lists (allow / warn / deny). Returns findings for `denied`, `warn` (weak copyleft), and `unknown` (no license declared) categories. Custom lists override the bundled SPDX-based defaults.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const kindArg: { kind?: LockfileKind; filename?: string } = {};
      if (parsed.data.kind !== undefined) kindArg.kind = parsed.data.kind;
      if (parsed.data.filename !== undefined) kindArg.filename = parsed.data.filename;
      const r = resolveKind(kindArg);
      if ("error" in r) return errorResult(r.error);
      const parsedLock = parseLockfile(parsed.data.content, r.kind);
      const report = checkLicenses(
        parsedLock.packages,
        {
          allow: parsed.data.allow ?? DEFAULT_ALLOW,
          warn: parsed.data.warn ?? DEFAULT_WARN,
          deny: parsed.data.deny ?? DEFAULT_DENY,
        },
        parsed.data.filename,
      );
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildTyposquatTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = lockfileSchema;
  return {
    name: "altais_detect_typosquat",
    title: "Detect typosquatted dependencies",
    description:
      "For each dependency, compare its name against a curated list of popular packages in the same ecosystem. Flag packages within edit-distance 1 or 2 — a common typosquat profile.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const kindArg: { kind?: LockfileKind; filename?: string } = {};
      if (parsed.data.kind !== undefined) kindArg.kind = parsed.data.kind;
      if (parsed.data.filename !== undefined) kindArg.filename = parsed.data.filename;
      const r = resolveKind(kindArg);
      if ("error" in r) return errorResult(r.error);
      const parsedLock = parseLockfile(parsed.data.content, r.kind);
      const report = detectTyposquat(parsedLock.packages, parsed.data.filename);
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildSlsaTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    attestation: z
      .string()
      .min(1)
      .max(1024 * 1024)
      .describe("SLSA provenance: DSSE envelope JSON, or an in-toto Statement JSON."),
  };
  return {
    name: "altais_verify_slsa",
    title: "Structurally verify a SLSA provenance attestation",
    description:
      "Parse a DSSE-wrapped SLSA v1 provenance (or a bare in-toto Statement) and check it for required fields: predicateType, builder.id, buildDefinition.buildType, subjects, signatures. Does not perform cryptographic verification — that requires a trust store outside this tool.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const report = verifySlsa(parsed.data.attestation);
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildSignaturesTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    signature: z
      .string()
      .min(1)
      .max(512 * 1024)
      .describe("Cosign bundle JSON, raw cosign payload, or an ASCII-armored GPG signature."),
  };
  return {
    name: "altais_verify_signatures",
    title: "Inspect cosign / GPG signature metadata",
    description:
      "Classify a signature payload (cosign bundle, cosign .sig, or ASCII-armored GPG), report its metadata (mediaType, hash algorithm, transparency-log entries), and flag missing or weak fields. No live cryptographic verification.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const report = inspectSignature(parsed.data.signature);
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildDepConfusionTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    ...lockfileSchema,
    internal_names: z.array(z.string().min(1).max(256)).max(256).optional(),
    internal_scopes: z.array(z.string().min(1).max(64)).max(64).optional(),
    internal_prefixes: z.array(z.string().min(1).max(128)).max(64).optional(),
    internal_registries: z.array(z.string().min(1).max(256)).max(32).optional(),
  };
  return {
    name: "altais_check_dependency_confusion",
    title: "Check for dependency-confusion risks",
    description:
      "Given lockfile content and a description of which package names / scopes / prefixes are internal, flag any package that matches the internal pattern but resolved from a public registry. Combine with internal-registry hostnames to suppress false positives.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const kindArg: { kind?: LockfileKind; filename?: string } = {};
      if (parsed.data.kind !== undefined) kindArg.kind = parsed.data.kind;
      if (parsed.data.filename !== undefined) kindArg.filename = parsed.data.filename;
      const r = resolveKind(kindArg);
      if ("error" in r) return errorResult(r.error);
      const parsedLock = parseLockfile(parsed.data.content, r.kind);
      const report = checkDependencyConfusion(
        parsedLock.packages,
        {
          ...(parsed.data.internal_names !== undefined
            ? { internal_names: parsed.data.internal_names }
            : {}),
          ...(parsed.data.internal_scopes !== undefined
            ? { internal_scopes: parsed.data.internal_scopes }
            : {}),
          ...(parsed.data.internal_prefixes !== undefined
            ? { internal_prefixes: parsed.data.internal_prefixes }
            : {}),
          ...(parsed.data.internal_registries !== undefined
            ? { internal_registries: parsed.data.internal_registries }
            : {}),
        },
        parsed.data.filename,
      );
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildVexTool(): ToolDefinition {
  const statementSchema = z.object({
    vulnerability: z.string().min(1).max(128),
    products: z
      .array(
        z.object({
          identifier: z.string().min(1).max(512),
          subcomponent_identifiers: z.array(z.string().min(1).max(512)).max(64).optional(),
        }),
      )
      .min(1)
      .max(64),
    status: z.enum(["not_affected", "affected", "fixed", "under_investigation"]),
    justification: z
      .enum([
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
      ])
      .optional(),
    impact_statement: z.string().max(2048).optional(),
    action_statement: z.string().max(2048).optional(),
  });
  const inputSchema = {
    format: z.enum(["openvex", "cyclonedx-vex"]).default("openvex"),
    author: z.string().min(1).max(256).optional(),
    author_role: z.string().min(1).max(64).optional(),
    statements: z.array(statementSchema).min(1).max(256),
  };
  return {
    name: "altais_generate_vex",
    title: "Generate a VEX document",
    description:
      "Emit a VEX (Vulnerability Exploitability eXchange) document — OpenVEX 0.2.0 or CycloneDX 1.5 VEX — from a list of (vulnerability, products, status) statements. Useful for declaring `not_affected` decisions on advisories that surface in the audit but do not apply to your product.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const doc = generateVex({
        format: parsed.data.format,
        ...(parsed.data.author !== undefined ? { author: parsed.data.author } : {}),
        ...(parsed.data.author_role !== undefined ? { author_role: parsed.data.author_role } : {}),
        statements: parsed.data.statements.map((s) => ({
          vulnerability: s.vulnerability,
          products: s.products.map((p) => ({
            identifier: p.identifier,
            ...(p.subcomponent_identifiers !== undefined
              ? { subcomponent_identifiers: p.subcomponent_identifiers }
              : {}),
          })),
          status: s.status,
          ...(s.justification !== undefined ? { justification: s.justification } : {}),
          ...(s.impact_statement !== undefined ? { impact_statement: s.impact_statement } : {}),
          ...(s.action_statement !== undefined ? { action_statement: s.action_statement } : {}),
        })),
      });
      return textResult(jsonText(doc));
    },
  };
}

function buildBuildIntegrityTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    content: z
      .string()
      .min(1)
      .max(2 * 1024 * 1024)
      .describe(
        "CI/CD configuration text (GitHub Actions YAML, GitLab CI YAML, Jenkinsfile, etc.).",
      ),
    filename: z.string().min(1).max(512).optional(),
  };
  return {
    name: "altais_check_build_integrity",
    title: "Audit a CI/CD configuration for tamper vectors",
    description:
      "Pattern-based audit of build pipeline configuration: third-party actions pinned by mutable tag or branch, secrets echoed in shell steps, write-all `permissions`, `pull_request_target` checkouts of PR refs, missing signature verification on releases, and `curl | bash` install steps.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const report = checkBuildIntegrity(parsed.data.content, parsed.data.filename);
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

function buildRegistryTool(deps: SupplyChainModuleDeps): ToolDefinition {
  const inputSchema = {
    content: z
      .string()
      .min(1)
      .max(512 * 1024)
      .describe("Registry configuration text (.npmrc, pip.conf, .cargo/config.toml)."),
    kind: z.enum(["npmrc", "pip", "cargo", "auto"]).default("auto"),
    filename: z.string().min(1).max(512).optional(),
  };
  return {
    name: "altais_audit_registry",
    title: "Audit a package registry configuration",
    description:
      "Check a registry configuration file for HTTP registries, plaintext auth tokens, disabled TLS verification, and pip `trusted-host` entries that include public hosts.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const report = auditRegistryConfig(
        parsed.data.content,
        parsed.data.kind,
        parsed.data.filename,
      );
      deps.findingStore.addMany(report.findings);
      return textResult(jsonText(report));
    },
  };
}

export function createSupplyChainModule(deps: SupplyChainModuleDeps): ModuleDefinition {
  const dbRef: { value: OsvDatabase | null } = { value: null };
  const ensureDb = (): OsvDatabase => {
    if (!dbRef.value) throw new Error("supply_chain module accessed before init()");
    return dbRef.value;
  };

  const auditTool: ToolDefinition = {
    // Build a placeholder with an empty DB so registration sees a valid
    // ToolDefinition; the handler swaps in the real DB after init().
    ...buildAuditTool(deps, new OsvDatabase([], undefined)),
    handler: (args) => buildAuditTool(deps, ensureDb()).handler(args),
  };

  const tools: readonly ToolDefinition[] = [
    auditTool,
    buildSbomTool(),
    buildLicenseTool(deps),
    buildTyposquatTool(deps),
    buildSlsaTool(deps),
    buildSignaturesTool(deps),
    buildDepConfusionTool(deps),
    buildVexTool(),
    buildBuildIntegrityTool(deps),
    buildRegistryTool(deps),
  ];

  return {
    name: "supply_chain",
    description:
      "Lockfile parsing, vulnerability audit, SBOM generation, license / typosquat / dependency-confusion checks, SLSA + cosign + GPG inspection, VEX, CI/CD pipeline + registry config audits.",
    version: MODULE_VERSION,
    tools,
    async init() {
      dbRef.value = await OsvDatabase.load(deps.dataDir);
    },
  };
}
