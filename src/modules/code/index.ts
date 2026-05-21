// Code module: 5 reviewers for source-code security —
// CERT secure-coding review, Rust `unsafe` auditing, sensitive-information
// leakage in error handling, input-validation coverage, and memory-safety
// defects in C / C++ / Rust.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import { scanToken } from "../../core/scan-patterns.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { checkErrorHandling } from "./error-handling.js";
import { checkInputValidation } from "./input-validation.js";
import { checkMemorySafety } from "./memory-safety.js";
import { reviewSecureCoding } from "./secure-coding.js";
import { auditUnsafe } from "./unsafe.js";

const MODULE_VERSION = "0.3.0";

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const TOKEN_EVAL = scanToken("js-dynamic-code");
const TOKEN_SYSTEM = scanToken("libc-system");
const TOKEN_POPEN = scanToken("libc-popen");

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface CodeModuleDeps {
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
  deps: CodeModuleDeps,
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

const filenameField = z
  .string()
  .min(1)
  .max(512)
  .optional()
  .describe("Optional filename used for the finding location.");

const sourceField = z
  .string()
  .min(1)
  .max(512 * 1024)
  .describe("Full source code text to review.");

const fullLanguageEnum = z
  .enum(["c", "cpp", "java", "python", "javascript", "typescript", "go"])
  .describe("Programming language of the source — selects language-specific patterns.");

const memoryLanguageEnum = z
  .enum(["c", "cpp", "rust"])
  .describe("Programming language of the source — C / C++ or Rust.");

// ─── altais_review_secure_coding ───────────────────────────────────────────

const secureCodingSchema = z.object({
  source: sourceField,
  language: fullLanguageEnum,
  filename: filenameField,
});

function buildSecureCodingTool(deps: CodeModuleDeps): ToolDefinition {
  return {
    name: "altais_review_secure_coding",
    title: "Review source against secure-coding standards",
    description: `Review source code against CERT secure-coding guidance: non-literal \`printf\`-family format strings, integer-overflow risks in size and allocation expressions, ignored security-relevant return values, time-of-check/time-of-use file races, dangerous process / evaluation APIs (\`${TOKEN_SYSTEM}\`, \`${TOKEN_POPEN}\`, \`${TOKEN_EVAL}\`), \`switch\` statements with no \`default\`, and signed/unsigned comparison mismatches.`,
    inputSchema: secureCodingSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(secureCodingSchema), (d) => reviewSecureCoding(d)),
  };
}

// ─── altais_audit_unsafe ───────────────────────────────────────────────────

const unsafeSchema = z.object({
  source: sourceField,
  filename: filenameField,
});

function buildUnsafeTool(deps: CodeModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_unsafe",
    title: "Audit Rust `unsafe` code for soundness",
    description:
      "Audit Rust `unsafe` blocks and functions for soundness: `unsafe` constructs with no `// SAFETY:` justification, `mem::transmute`, `static mut`, raw-pointer dereferences, `get_unchecked`, `slice::from_raw_parts`, `Vec::set_len`, `mem::uninitialized` / `MaybeUninit::assume_init`, and `ptr::read` / `ptr::write`.",
    inputSchema: unsafeSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(unsafeSchema), (d) => auditUnsafe(d)),
  };
}

// ─── altais_check_error_handling ───────────────────────────────────────────

const errorHandlingSchema = z.object({
  source: sourceField,
  language: fullLanguageEnum,
  filename: filenameField,
});

function buildErrorHandlingTool(deps: CodeModuleDeps): ToolDefinition {
  return {
    name: "altais_check_error_handling",
    title: "Check error handling for information leakage",
    description:
      "Detect error handling that leaks sensitive information or hides failures: stack traces and raw exception messages returned to clients, `printStackTrace()` near responses, Python tracebacks in responses, empty / swallowed `catch` blocks, bare `except: pass`, overly broad exception handlers, and debug mode left enabled.",
    inputSchema: errorHandlingSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(errorHandlingSchema), (d) => checkErrorHandling(d)),
  };
}

// ─── altais_check_input_validation ─────────────────────────────────────────

const inputValidationSchema = z.object({
  source: sourceField,
  language: fullLanguageEnum,
  filename: filenameField,
});

function buildInputValidationTool(deps: CodeModuleDeps): ToolDefinition {
  return {
    name: "altais_check_input_validation",
    title: "Check input validation and sanitization",
    description:
      "Verify that request and external input is validated before use: untrusted input (`req.body` / `request.form` / `os.Args`) consumed with no recognized validator (Zod, Joi, yup, express-validator, pydantic), `parseInt` without an explicit radix, and unbounded regular expressions applied to user input (ReDoS risk).",
    inputSchema: inputValidationSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(inputValidationSchema), (d) => checkInputValidation(d)),
  };
}

// ─── altais_check_memory_safety ────────────────────────────────────────────

const memorySafetySchema = z.object({
  source: sourceField,
  language: memoryLanguageEnum,
  filename: filenameField,
});

function buildMemorySafetyTool(deps: CodeModuleDeps): ToolDefinition {
  return {
    name: "altais_check_memory_safety",
    title: "Check memory safety in C / C++ / Rust",
    description:
      'Detect memory-safety defects: in C / C++ — unbounded string functions (`strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")`), allocation results used without a NULL check, `memcpy` / `memmove` with an unchecked size, `alloca`, double free, and use-after-free; in Rust — `get_unchecked`, `slice::from_raw_parts`, `Vec::set_len`, and uninitialized-memory use.',
    inputSchema: memorySafetySchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(memorySafetySchema), (d) => checkMemorySafety(d)),
  };
}

export function createCodeModule(deps: CodeModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildSecureCodingTool(deps),
    buildUnsafeTool(deps),
    buildErrorHandlingTool(deps),
    buildInputValidationTool(deps),
    buildMemorySafetyTool(deps),
  ];
  return {
    name: "code",
    description:
      "Code reviews: CERT secure-coding standards, Rust `unsafe` soundness, sensitive-information leakage in error handling, input-validation coverage, and memory-safety defects in C / C++ / Rust.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
