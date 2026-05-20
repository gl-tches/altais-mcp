// Testing module: 7 generator tools for security testing artifacts —
// fuzz-testing configuration, SAST tool configuration, penetration-test
// scoping, security-focused test cases, security chaos-engineering
// configuration, red-team engagement scoping, and IAST setup.
//
// Every tool in this module is a generator: it parses a request and
// returns a generated configuration / scope / artifact as JSON text. None
// of these tools push Finding objects into the shared FindingStore — they
// produce artifacts, they do not analyze code.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { FuzzConfigError, generateFuzzConfig } from "./fuzz.js";
import { generateSastConfig, SastConfigError } from "./sast.js";
import { generatePentestScope, PentestScopeError } from "./pentest.js";
import { generateSecurityTests, SecurityTestsError } from "./security-tests.js";
import { ChaosConfigError, generateChaosConfig } from "./chaos.js";
import { generateRedTeamScope, RedTeamScopeError } from "./red-team.js";
import { generateIastConfig, IastConfigError } from "./iast.js";

const MODULE_VERSION = "0.5.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface TestingModuleDeps {
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

// ─── shared schema fields ──────────────────────────────────────────────────

const MAX_LIST = 40;
const MAX_ITEM_LEN = 512;

const itemString = z.string().min(1).max(MAX_ITEM_LEN);

const languageEnum = z.enum(["c", "cpp", "rust", "go", "python", "javascript", "java"]);

// ─── altais_generate_fuzz_config ───────────────────────────────────────────

const fuzzSchema = z.object({
  language: languageEnum.describe("The language of the code being fuzzed."),
  fuzzer: z
    .enum(["libfuzzer", "afl++", "cargo-fuzz", "go-fuzz", "atheris", "jazzer", "jsfuzz"])
    .optional()
    .describe("The fuzzing engine. Defaults to the idiomatic engine for the language."),
  target_function: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "must be a plain identifier")
    .optional()
    .describe("Optional name of the function under test, used in the generated harness."),
});

function buildFuzzTool(): ToolDefinition {
  const parse = zodParser(fuzzSchema);
  return {
    name: "altais_generate_fuzz_config",
    title: "Generate a fuzz-testing configuration",
    description:
      "Generate a fuzz-testing setup for a chosen language and engine: a fuzz harness skeleton, a runner script, a sanitizer recommendation (ASan / UBSan / MSan or the language equivalent), and corpus / seed and dictionary guidance. Supports libFuzzer, AFL++, cargo-fuzz, Go native fuzzing, Atheris, Jazzer, and jsfuzz. Generates static text only — it does not compile or run the harness.",
    inputSchema: fuzzSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        return textResult(
          jsonText(
            generateFuzzConfig({
              language: parsed.data.language,
              ...(parsed.data.fuzzer !== undefined ? { fuzzer: parsed.data.fuzzer } : {}),
              ...(parsed.data.target_function !== undefined
                ? { target_function: parsed.data.target_function }
                : {}),
            }),
          ),
        );
      } catch (err) {
        if (err instanceof FuzzConfigError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult("Could not generate the fuzz configuration due to an unexpected error.");
      }
    },
  };
}

// ─── altais_generate_sast_config ───────────────────────────────────────────

const sastSchema = z.object({
  tool: z
    .enum(["semgrep", "codeql", "bandit", "gosec", "eslint-security", "brakeman"])
    .describe("The static-analysis tool to generate a configuration for."),
  languages: z
    .array(z.string().min(1).max(48))
    .min(1)
    .max(MAX_LIST)
    .describe("The target languages, e.g. `python`, `javascript`."),
});

function buildSastTool(): ToolDefinition {
  const parse = zodParser(sastSchema);
  return {
    name: "altais_generate_sast_config",
    title: "Generate a SAST tool configuration",
    description:
      "Generate a ready-to-use static-analysis (SAST) configuration: the config file body for the chosen tool (a Semgrep ruleset, a CodeQL config + workflow, a `.bandit`, a `.gosec.json`, an ESLint security config, or a Brakeman config), the recommended rule packs, and a CI invocation snippet. Supports Semgrep, CodeQL, Bandit, gosec, eslint-plugin-security, and Brakeman.",
    inputSchema: sastSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        return textResult(
          jsonText(
            generateSastConfig({ tool: parsed.data.tool, languages: parsed.data.languages }),
          ),
        );
      } catch (err) {
        if (err instanceof SastConfigError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult("Could not generate the SAST configuration due to an unexpected error.");
      }
    },
  };
}

// ─── altais_generate_pentest_scope ─────────────────────────────────────────

const pentestSchema = z.object({
  config: z.object({
    application_type: z
      .enum(["web", "api", "mobile", "network", "cloud", "thick-client"])
      .describe("The kind of target system being tested."),
    assets: z
      .array(itemString)
      .min(1)
      .max(MAX_LIST)
      .describe("In-scope assets: hostnames, URLs, IP ranges, or repositories."),
    environment: z
      .enum(["production", "staging", "isolated"])
      .describe("The environment the test runs against."),
    constraints: z
      .array(itemString)
      .max(MAX_LIST)
      .default([])
      .describe("Client constraints folded into the rules of engagement."),
    objectives: z
      .array(itemString)
      .min(1)
      .max(MAX_LIST)
      .describe("Engagement objectives, e.g. `prove access to customer PII`."),
  }),
});

function buildPentestTool(): ToolDefinition {
  const parse = zodParser(pentestSchema);
  return {
    name: "altais_generate_pentest_scope",
    title: "Generate a penetration-test scope",
    description:
      "Generate a penetration-test scoping document: in-scope and out-of-scope definitions, rules of engagement tailored to the environment, a methodology aligned to the OWASP Web Security Testing Guide and PTES, and a testing checklist specific to the application type (web, API, mobile, network, cloud, or thick-client).",
    inputSchema: pentestSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        const c = parsed.data.config;
        return textResult(
          jsonText(
            generatePentestScope({
              application_type: c.application_type,
              assets: c.assets,
              environment: c.environment,
              constraints: c.constraints,
              objectives: c.objectives,
            }),
          ),
        );
      } catch (err) {
        if (err instanceof PentestScopeError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult(
          "Could not generate the penetration-test scope due to an unexpected error.",
        );
      }
    },
  };
}

// ─── altais_generate_security_tests ────────────────────────────────────────

const securityTestsSchema = z.object({
  vulnerability_class: z
    .enum([
      "injection",
      "xss",
      "auth",
      "access-control",
      "ssrf",
      "csrf",
      "crypto",
      "business-logic",
    ])
    .describe("The vulnerability class the generated tests assert is mitigated."),
  language: languageEnum.describe("The language of the test code to generate."),
  framework: z
    .string()
    .min(1)
    .max(48)
    .regex(/^[A-Za-z0-9._-]+$/, "must be a short identifier")
    .optional()
    .describe("Optional test framework, e.g. `jest`, `pytest`, `go-test`."),
});

function buildSecurityTestsTool(): ToolDefinition {
  const parse = zodParser(securityTestsSchema);
  return {
    name: "altais_generate_security_tests",
    title: "Generate security test cases",
    description:
      "Generate security-focused test cases for a vulnerability class (injection, XSS, auth, access control, SSRF, CSRF, crypto, or business logic). Returns runnable-shaped test code with both positive cases (benign input is accepted) and negative cases (malicious input is rejected), so the suite asserts the vulnerability is mitigated. Supports Python, JavaScript, Go, Rust, Java, and C/C++.",
    inputSchema: securityTestsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        return textResult(
          jsonText(
            generateSecurityTests({
              vulnerability_class: parsed.data.vulnerability_class,
              language: parsed.data.language,
              ...(parsed.data.framework !== undefined ? { framework: parsed.data.framework } : {}),
            }),
          ),
        );
      } catch (err) {
        if (err instanceof SecurityTestsError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult("Could not generate the security tests due to an unexpected error.");
      }
    },
  };
}

// ─── altais_generate_chaos_config ──────────────────────────────────────────

const chaosSchema = z.object({
  config: z.object({
    platform: z
      .enum(["kubernetes", "aws", "linux-host", "application"])
      .describe("The platform the chaos experiments run against."),
    experiments: z
      .array(
        z.enum([
          "network-latency",
          "dependency-failure",
          "credential-expiry",
          "pod-kill",
          "iam-revocation",
        ]),
      )
      .min(1)
      .max(20)
      .describe("The fault-injection experiments to generate definitions for."),
  }),
});

function buildChaosTool(): ToolDefinition {
  const parse = zodParser(chaosSchema);
  return {
    name: "altais_generate_chaos_config",
    title: "Generate a security chaos-engineering configuration",
    description:
      "Generate a security chaos-engineering / fault-injection configuration: experiment definitions shaped after Chaos Mesh, LitmusChaos, or AWS Fault Injection Service, each with a steady-state hypothesis, an explicit blast-radius limit, and rollback guidance. Supports network latency, dependency failure, credential expiry, pod kill, and IAM revocation experiments.",
    inputSchema: chaosSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        const c = parsed.data.config;
        return textResult(
          jsonText(generateChaosConfig({ platform: c.platform, experiments: c.experiments })),
        );
      } catch (err) {
        if (err instanceof ChaosConfigError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult(
          "Could not generate the chaos configuration due to an unexpected error.",
        );
      }
    },
  };
}

// ─── altais_scope_red_team ─────────────────────────────────────────────────

const redTeamSchema = z.object({
  config: z.object({
    objectives: z
      .array(itemString)
      .min(1)
      .max(MAX_LIST)
      .describe("Engagement objectives the adversary simulation pursues."),
    threat_actor_profile: z
      .enum(["opportunistic", "organized-crime", "nation-state", "insider"])
      .describe("The threat actor whose tradecraft the engagement emulates."),
    duration_weeks: z.number().int().min(1).max(52).describe("Engagement duration in weeks."),
    constraints: z
      .array(itemString)
      .max(MAX_LIST)
      .default([])
      .describe("Client constraints folded into the rules of engagement."),
    assumed_breach: z
      .boolean()
      .describe("Whether the engagement starts from an assumed-breach foothold."),
  }),
});

function buildRedTeamTool(): ToolDefinition {
  const parse = zodParser(redTeamSchema);
  return {
    name: "altais_scope_red_team",
    title: "Generate a red-team engagement scope",
    description:
      "Generate a red-team / adversary-simulation engagement scope: objectives and capture flags, MITRE ATT&CK-mapped TTPs to emulate selected by threat-actor profile (opportunistic, organized crime, nation-state, or insider), rules of engagement, deconfliction procedures, and success criteria. Adapts to assumed-breach versus full-scope starting positions.",
    inputSchema: redTeamSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        const c = parsed.data.config;
        return textResult(
          jsonText(
            generateRedTeamScope({
              objectives: c.objectives,
              threat_actor_profile: c.threat_actor_profile,
              duration_weeks: c.duration_weeks,
              constraints: c.constraints,
              assumed_breach: c.assumed_breach,
            }),
          ),
        );
      } catch (err) {
        if (err instanceof RedTeamScopeError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult("Could not generate the red-team scope due to an unexpected error.");
      }
    },
  };
}

// ─── altais_generate_iast_config ───────────────────────────────────────────

const iastSchema = z.object({
  tool: z
    .enum(["contrast", "seeker", "dynatrace", "open-source"])
    .describe("The IAST product to generate a setup for."),
  language: languageEnum.describe("The language of the application being instrumented."),
  framework: z
    .string()
    .min(1)
    .max(48)
    .regex(/^[A-Za-z0-9._-]+$/, "must be a short identifier")
    .optional()
    .describe("Optional application framework, e.g. `spring-boot`, `django`, `express`."),
});

function buildIastTool(): ToolDefinition {
  const parse = zodParser(iastSchema);
  return {
    name: "altais_generate_iast_config",
    title: "Generate an IAST configuration",
    description:
      "Generate an Interactive Application Security Testing (IAST) setup: agent setup steps, an instrumentation configuration, a CI/CD integration workflow, and coverage guidance. Supports Contrast, Seeker, Dynatrace, and open-source IAST. Flags that IAST is not applicable to natively compiled languages (C, C++, Rust) and recommends DAST plus fuzzing instead.",
    inputSchema: iastSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        return textResult(
          jsonText(
            generateIastConfig({
              tool: parsed.data.tool,
              language: parsed.data.language,
              ...(parsed.data.framework !== undefined ? { framework: parsed.data.framework } : {}),
            }),
          ),
        );
      } catch (err) {
        if (err instanceof IastConfigError) return errorResult(`Invalid input: ${err.message}`);
        return errorResult("Could not generate the IAST configuration due to an unexpected error.");
      }
    },
  };
}

// ─── module assembly ───────────────────────────────────────────────────────

export function createTestingModule(deps: TestingModuleDeps): ModuleDefinition {
  void deps;
  const tools: readonly ToolDefinition[] = [
    buildFuzzTool(),
    buildSastTool(),
    buildPentestTool(),
    buildSecurityTestsTool(),
    buildChaosTool(),
    buildRedTeamTool(),
    buildIastTool(),
  ];
  return {
    name: "testing",
    description:
      "Security testing artifact generators: fuzz-testing configuration, SAST tool configuration, penetration-test scoping, security test-case generation, security chaos-engineering configuration, red-team engagement scoping, and IAST setup.",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load.
    },
  };
}
