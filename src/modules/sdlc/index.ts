// sdlc module: 8 secure-software-development-lifecycle tools —
// 3 generators (pre-commit config, code-review checklist) and
// 5 auditors / assessors (CI/CD gates, release integrity, commit
// signing, branch protection, SLSA Build Track level, CODEOWNERS).
//
// Generators return an artifact as JSON text and do not push Finding
// objects. Auditors push Finding objects into the shared FindingStore.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { auditBranchProtection } from "./branch-protection.js";
import { auditCiCd } from "./ci-cd.js";
import { checkCodeowners } from "./codeowners.js";
import { generatePrecommit } from "./precommit.js";
import { checkReleaseIntegrity } from "./release-integrity.js";
import { generateReviewChecklist } from "./review-checklist.js";
import { checkSignedCommits } from "./signed-commits.js";
import { assessSlsaLevel } from "./slsa-level.js";

const MODULE_VERSION = "0.5.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface SdlcModuleDeps {
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

function withSummary(findings: readonly Finding[]): unknown {
  return { summary: summarize(findings), findings };
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

function makeRunner<TInput>(
  deps: SdlcModuleDeps,
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => readonly Finding[],
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    const findings = run(parsed.data);
    deps.findingStore.addMany(findings);
    return textResult(jsonText(withSummary(findings)));
  };
}

function makeGenerator<TInput>(
  parser: (args: unknown) => { success: true; data: TInput } | { success: false; message: string },
  run: (data: TInput) => unknown,
): (args: unknown) => CallToolResult {
  return (args: unknown) => {
    const parsed = parser(args);
    if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
    return textResult(jsonText(run(parsed.data)));
  };
}

// ─── shared field schemas ──────────────────────────────────────────────────

const MAX_CONTENT = 512 * 1024;

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename used for the finding location.");

const languagesField = z
  .array(z.string().min(1).max(64))
  .max(40)
  .describe("Programming languages in the codebase, e.g. `python`, `typescript`.");

// ─── altais_generate_precommit ─────────────────────────────────────────────

const precommitCheckEnum = z.enum([
  "secrets",
  "lint",
  "format",
  "sast",
  "dependency-audit",
  "large-files",
  "private-key",
]);

const precommitSchema = z.object({
  config: z.object({
    languages: languagesField,
    checks: z
      .array(precommitCheckEnum)
      .min(1)
      .max(7)
      .describe("Checks to wire into the hook configuration."),
  }),
});

function buildPrecommitTool(): ToolDefinition {
  const schema = precommitSchema;
  return {
    name: "altais_generate_precommit",
    title: "Generate a pre-commit hook configuration",
    description:
      "Generate a ready-to-use `.pre-commit-config.yaml` that wires the requested security and quality checks: secret scanning (gitleaks + detect-secrets), language linters / formatters, SAST (Semgrep, plus Bandit for Python), dependency auditing, large-file blocking, and private-key detection. Returns the YAML body and setup notes. This is a generator — it returns an artifact, not findings.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(schema), (d) =>
      generatePrecommit({
        languages: d.config.languages,
        checks: d.config.checks,
      }),
    ),
  };
}

// ─── altais_audit_ci_cd ────────────────────────────────────────────────────

const ciCdSchema = z
  .object({
    content: z
      .string()
      .min(1)
      .max(MAX_CONTENT)
      .optional()
      .describe("CI/CD pipeline YAML (GitHub Actions, GitLab CI, etc.) to scan."),
    config: z
      .object({
        has_sast: z.boolean().optional(),
        has_dependency_scan: z.boolean().optional(),
        has_secret_scan: z.boolean().optional(),
        has_container_scan: z.boolean().optional(),
        has_dast: z.boolean().optional(),
        blocks_on_failure: z.boolean().optional(),
        signed_artifacts: z.boolean().optional(),
      })
      .optional()
      .describe("Declared presence of pipeline security gates."),
    filename: filenameField,
  })
  .refine((v) => v.content !== undefined || v.config !== undefined, {
    message: "provide at least one of `content` or `config`",
  });

function buildCiCdTool(deps: SdlcModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_ci_cd",
    title: "Audit a CI/CD pipeline for security gates",
    description:
      "Review a CI/CD pipeline for the security gates that should block an insecure change: SAST, dependency / SCA scanning, secret scanning, container image scanning, DAST, and a fail-on-findings policy. When pipeline YAML is supplied it is additionally scanned for unpinned third-party actions, over-broad `permissions: write-all`, and secrets echoed to logs. Findings cite CWE-1395, CWE-693, CWE-829, and CWE-1269.",
    inputSchema: ciCdSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(ciCdSchema), (d) =>
      auditCiCd({
        ...(d.content !== undefined ? { content: d.content } : {}),
        ...(d.config !== undefined ? { config: d.config } : {}),
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_generate_review_checklist ──────────────────────────────────────

const reviewChecklistSchema = z.object({
  config: z.object({
    change_type: z
      .enum(["feature", "bugfix", "dependency", "infrastructure", "auth", "crypto"])
      .describe("The kind of change under review."),
    languages: languagesField,
    sensitivity: z
      .enum(["low", "medium", "high"])
      .describe("How security-sensitive the change is."),
  }),
});

function buildReviewChecklistTool(): ToolDefinition {
  const schema = reviewChecklistSchema;
  return {
    name: "altais_generate_review_checklist",
    title: "Generate a security code-review checklist",
    description:
      "Generate a security code-review checklist tailored to the change type (feature, bugfix, dependency, infrastructure, auth, crypto), the languages involved, and the change's sensitivity. Covers input validation, authorization, secrets, crypto, error handling, dependencies, and tests, with extra items weighted to the change type. High-sensitivity changes elevate every recommended item to mandatory. This is a generator — it returns an artifact, not findings.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeGenerator(zodParser(schema), (d) => generateReviewChecklist(d.config)),
  };
}

// ─── altais_check_release_integrity ────────────────────────────────────────

const releaseIntegritySchema = z.object({
  config: z.object({
    artifacts_signed: z.boolean().optional(),
    checksums_published: z.boolean().optional(),
    reproducible_build: z.boolean().optional(),
    sbom_published: z.boolean().optional(),
    provenance_attestation: z.boolean().optional(),
    release_from_protected_branch: z.boolean().optional(),
    changelog_maintained: z.boolean().optional(),
    tags_signed: z.boolean().optional(),
  }),
  filename: filenameField,
});

function buildReleaseIntegrityTool(deps: SdlcModuleDeps): ToolDefinition {
  const schema = releaseIntegritySchema;
  return {
    name: "altais_check_release_integrity",
    title: "Check release-process integrity controls",
    description:
      "Verify a release process carries the controls that let a consumer trust a published artifact: signed artifacts, published checksums, reproducible builds, a published SBOM, signed provenance attestation, release from a protected branch, a maintained changelog, and signed tags. Flags each missing control, citing CWE-345, CWE-353, and CWE-1357.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(schema), (d) =>
      checkReleaseIntegrity({
        config: d.config,
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_check_signed_commits ───────────────────────────────────────────

const signedCommitsSchema = z
  .object({
    git_log: z
      .string()
      .min(1)
      .max(MAX_CONTENT)
      .optional()
      .describe(
        "`git log` output, one commit per line, each with a signature marker (`%G?` letter, `gpg:` line, or `Good signature`).",
      ),
    config: z
      .object({
        signing_enforced: z.boolean().optional(),
        total_commits: z.number().int().min(0).max(10_000_000).optional(),
        signed_commits: z.number().int().min(0).max(10_000_000).optional(),
        verified_commits: z.number().int().min(0).max(10_000_000).optional(),
      })
      .optional()
      .describe("Precomputed commit-signing summary."),
    filename: filenameField,
  })
  .refine((v) => v.git_log !== undefined || v.config !== undefined, {
    message: "provide at least one of `git_log` or `config`",
  });

function buildSignedCommitsTool(deps: SdlcModuleDeps): ToolDefinition {
  return {
    name: "altais_check_signed_commits",
    title: "Verify GPG/SSH commit signing",
    description:
      "Verify that commits are GPG or SSH signed and that signing is enforced. Accepts `git log` output with signature markers and/or a precomputed summary. Flags signing not being enforced, unsigned commits, and signatures that cannot be verified (bad, expired, revoked, or unknown key). Findings cite CWE-347.",
    inputSchema: signedCommitsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(signedCommitsSchema), (d) =>
      checkSignedCommits({
        ...(d.git_log !== undefined ? { git_log: d.git_log } : {}),
        ...(d.config !== undefined ? { config: d.config } : {}),
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_audit_branch_protection ────────────────────────────────────────

const branchProtectionSchema = z.object({
  config: z.object({
    required_reviews: z.number().int().min(0).max(100).optional(),
    dismiss_stale_reviews: z.boolean().optional(),
    required_status_checks: z
      .union([z.boolean(), z.array(z.string().min(1).max(256)).max(200)])
      .optional(),
    require_up_to_date: z.boolean().optional(),
    enforce_for_admins: z.boolean().optional(),
    restrict_force_push: z.boolean().optional(),
    restrict_deletions: z.boolean().optional(),
    require_signed_commits: z.boolean().optional(),
    require_linear_history: z.boolean().optional(),
    require_conversation_resolution: z.boolean().optional(),
  }),
  filename: filenameField,
});

function buildBranchProtectionTool(deps: SdlcModuleDeps): ToolDefinition {
  const schema = branchProtectionSchema;
  return {
    name: "altais_audit_branch_protection",
    title: "Audit default-branch protection settings",
    description:
      "Audit a repository's default-branch protection settings and flag each weak or missing control: no required review, undismissed stale approvals, no required status checks, admins able to bypass protection, allowed force pushes, allowed branch deletion, no signed-commit requirement, and unresolved-conversation merges. Findings cite CWE-284 and CWE-1269.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(schema), (d) =>
      auditBranchProtection({
        config: d.config,
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_assess_slsa_level ──────────────────────────────────────────────

const slsaSchema = z.object({
  config: z.object({
    scripted_build: z.boolean().optional(),
    build_service: z.boolean().optional(),
    provenance_generated: z.boolean().optional(),
    provenance_authenticated: z.boolean().optional(),
    provenance_service_generated: z.boolean().optional(),
    isolated_build: z.boolean().optional(),
    hermetic: z.boolean().optional(),
    parameterless: z.boolean().optional(),
  }),
  filename: filenameField,
});

function buildSlsaTool(deps: SdlcModuleDeps): ToolDefinition {
  const schema = slsaSchema;
  return {
    name: "altais_assess_slsa_level",
    title: "Assess the SLSA v1.2 Build Track level",
    description:
      "Assess the achieved SLSA v1.2 Build Track level (0-3) from a set of build-process facts: scripted build, hosted build service, provenance generation / authentication / service-generation, and an isolated, hermetic, parameterless build. Emits a finding stating the current level and lists the exact requirements needed to reach the next level. Cites CWE-1357.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(schema), (d) =>
      assessSlsaLevel({
        config: d.config,
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── altais_check_codeowners ───────────────────────────────────────────────

const codeownersSchema = z.object({
  content: z.string().min(1).max(MAX_CONTENT).describe("The CODEOWNERS file body to audit."),
  sensitive_paths: z
    .array(z.string().min(1).max(256))
    .max(200)
    .optional()
    .describe(
      "Security-sensitive paths that must have an owner rule. Defaults to auth, crypto, security, CI, infra, deploy, iam, secrets, and Dockerfile.",
    ),
  filename: filenameField,
});

function buildCodeownersTool(deps: SdlcModuleDeps): ToolDefinition {
  const schema = codeownersSchema;
  return {
    name: "altais_check_codeowners",
    title: "Check CODEOWNERS coverage of sensitive paths",
    description:
      "Verify a CODEOWNERS file gives security-sensitive paths a required reviewer. Flags sensitive paths with no owner rule, a missing catch-all `*` rule, rules with no actual owner, malformed owner entries, and (info) a single owner gating every rule. Findings cite CWE-1220 and CWE-284.",
    inputSchema: schema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(schema), (d) =>
      checkCodeowners({
        content: d.content,
        ...(d.sensitive_paths !== undefined ? { sensitive_paths: d.sensitive_paths } : {}),
        ...(d.filename !== undefined ? { filename: d.filename } : {}),
      }),
    ),
  };
}

// ─── module assembly ───────────────────────────────────────────────────────

export function createSdlcModule(deps: SdlcModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildPrecommitTool(),
    buildCiCdTool(deps),
    buildReviewChecklistTool(),
    buildReleaseIntegrityTool(deps),
    buildSignedCommitsTool(deps),
    buildBranchProtectionTool(deps),
    buildSlsaTool(deps),
    buildCodeownersTool(deps),
  ];
  return {
    name: "sdlc",
    description:
      "Secure SDLC tooling: generate pre-commit hook configs and security code-review checklists; audit CI/CD security gates, release integrity, GPG/SSH commit signing, branch protection, and CODEOWNERS coverage; and assess the SLSA v1.2 Build Track level.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
