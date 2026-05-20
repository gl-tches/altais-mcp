// OWASP module: coverage reports against Web / API / Mobile / Serverless
// Top 10 lists, plus ASVS controls filtered by level/section.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { loadOwaspKnowledge, type OwaspCategory, type OwaspKnowledge } from "./knowledge.js";
import { type CoverageReport, mapFindingsToCategories, reportAsvs } from "./matcher.js";

const MODULE_VERSION = "0.2.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface OwaspModuleDeps {
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

const findingForInputSchema = z.object({
  module: z.string().min(1).max(64),
  rule: z.string().min(1).max(128),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  cwe: z.array(z.string().max(32)).optional(),
  title: z.string().max(512).optional(),
});

const sharedInputs = {
  findings: z
    .array(findingForInputSchema)
    .max(2000)
    .optional()
    .describe(
      "Optional pre-existing findings to evaluate. If omitted (and `use_session_findings` is true), the session FindingStore is used.",
    ),
  use_session_findings: z
    .boolean()
    .default(true)
    .describe("Read findings from the shared session FindingStore."),
};

function gatherFindings(
  deps: OwaspModuleDeps,
  findings: z.infer<typeof findingForInputSchema>[] | undefined,
  useSession: boolean,
): readonly Finding[] {
  const session = useSession ? deps.findingStore.all() : [];
  if (!findings || findings.length === 0) return session;
  const supplied: Finding[] = findings.map((f) => ({
    id: `${f.module}:${f.rule}:supplied`,
    module: f.module,
    rule: f.rule,
    severity: f.severity,
    cwe: f.cwe ?? [],
    title: f.title ?? f.rule,
    description: f.title ?? f.rule,
    remediation: "",
    references: [],
    tags: ["owasp-input"],
    status: "open",
  }));
  return [...session, ...supplied];
}

function buildList(
  deps: OwaspModuleDeps,
  knowledge: OwaspKnowledge,
  toolName: string,
  toolTitle: string,
  listLabel: string,
  category: (k: OwaspKnowledge) => readonly OwaspCategory[],
  description: string,
): ToolDefinition {
  const inputSchema = sharedInputs;
  return {
    name: toolName,
    title: toolTitle,
    description,
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const findings = gatherFindings(deps, parsed.data.findings, parsed.data.use_session_findings);
      const report: CoverageReport = mapFindingsToCategories(
        findings,
        category(knowledge),
        listLabel,
      );
      return textResult(jsonText(report));
    },
  };
}

function buildAsvsTool(deps: OwaspModuleDeps, knowledge: OwaspKnowledge): ToolDefinition {
  const inputSchema = {
    level: z
      .union([z.literal(1), z.literal(2), z.literal(3)])
      .default(1)
      .describe(
        "ASVS verification level. Level N returns all controls at levels 1..N (Level 1 = baseline, Level 2 = standard, Level 3 = critical apps).",
      ),
    section: z.string().min(1).max(8).optional().describe("Optional section filter (V1 .. V14)."),
    ...sharedInputs,
  };
  return {
    name: "altais_check_asvs",
    title: "Check OWASP ASVS controls at a given level",
    description:
      "Return the OWASP ASVS controls applicable at the specified level (1, 2, or 3), optionally filtered to a single section (V1..V14). Each control is annotated with related findings from the session (or supplied list); this is a coarse hint to focus review, not a formal compliance claim.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const findings = gatherFindings(deps, parsed.data.findings, parsed.data.use_session_findings);
      const report = reportAsvs(
        knowledge.asvs.controls,
        {
          level: parsed.data.level,
          ...(parsed.data.section !== undefined ? { section: parsed.data.section } : {}),
        },
        findings,
        knowledge.asvs.version,
      );
      return textResult(jsonText(report));
    },
  };
}

export function createOwaspModule(deps: OwaspModuleDeps): ModuleDefinition {
  const knowledgeRef: { value: OwaspKnowledge | null } = { value: null };
  const ensure = (): OwaspKnowledge => {
    if (!knowledgeRef.value) throw new Error("owasp module accessed before init()");
    return knowledgeRef.value;
  };

  const lazy = (build: (k: OwaspKnowledge) => ToolDefinition): ToolDefinition => {
    // Placeholder built with an empty knowledge object so registration can
    // pull metadata (name, description, schema); the handler swaps in the
    // real knowledge after init().
    const empty: OwaspKnowledge = {
      web_top_10_2025: [],
      api_top_10_2023: [],
      mobile_top_10_2024: [],
      serverless_top_10: [],
      asvs: { version: "0.0", controls: [] },
    };
    const placeholder = build(empty);
    return {
      ...placeholder,
      handler: (args) => build(ensure()).handler(args),
    };
  };

  const tools: readonly ToolDefinition[] = [
    lazy((k) =>
      buildList(
        deps,
        k,
        "altais_check_owasp_web",
        "Check OWASP Top 10:2025 (Web)",
        "Web Top 10:2025",
        (kk) => kk.web_top_10_2025,
        "Map findings to the OWASP Top 10:2025 categories (A01–A10). The 2025 edition promotes Supply Chain to A03 and adds A10 Mishandling of Exceptional Conditions; SSRF moved into A01 Broken Access Control.",
      ),
    ),
    lazy((k) =>
      buildList(
        deps,
        k,
        "altais_check_owasp_api",
        "Check OWASP API Security Top 10 (2023)",
        "API Top 10:2023",
        (kk) => kk.api_top_10_2023,
        "Map findings to the OWASP API Security Top 10 (2023). Covers BOLA, BOPLA, BFLA, unrestricted resource consumption, unsafe consumption of third-party APIs, and improper inventory management.",
      ),
    ),
    lazy((k) =>
      buildList(
        deps,
        k,
        "altais_check_owasp_mobile",
        "Check OWASP Mobile Top 10 (2024)",
        "Mobile Top 10:2024",
        (kk) => kk.mobile_top_10_2024,
        "Map findings to the OWASP Mobile Top 10 (2024). Covers credentials, supply chain, authn/authz, network communication, privacy controls, binary protections, and insecure data storage.",
      ),
    ),
    lazy((k) =>
      buildList(
        deps,
        k,
        "altais_check_owasp_serverless",
        "Check OWASP Serverless Top 10",
        "Serverless Top 10",
        (kk) => kk.serverless_top_10,
        "Map findings to the OWASP Serverless Top 10. Covers event-data injection, over-privileged execution roles, secrets in env vars, financial DoS, and idempotency / replay risks.",
      ),
    ),
    lazy((k) => buildAsvsTool(deps, k)),
  ];

  return {
    name: "owasp",
    description:
      "Coverage reports against OWASP Top 10:2025 (Web), API:2023, Mobile:2024, Serverless, and ASVS controls.",
    version: MODULE_VERSION,
    tools,
    async init() {
      knowledgeRef.value = await loadOwaspKnowledge(deps.dataDir);
    },
  };
}
