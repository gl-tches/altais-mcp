// Core module: always-loaded utility tools.
// Provides config inspection, CWE explanation, CVSS scoring, session
// reporting, and composite risk summary.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { Config } from "../../config.js";
import { calculateCvssV40 } from "../../core/cvss-v4.js";
import { CvssError, scoreCvss, riskSummary } from "../../core/scoring.js";
import type { FindingStore } from "../../core/report.js";
import { hashJson, renderJsonReport, renderMarkdownReport } from "../../core/report.js";
import type { ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { CweDatabase } from "./cwe.js";

const PACKAGE_VERSION = "0.1.0";

export interface CoreModuleDeps {
  readonly config: Config;
  readonly findingStore: FindingStore;
  readonly activeModules: () => readonly string[];
  readonly dataDir?: string;
}

interface CoreState {
  readonly cwe: CweDatabase;
  readonly configHash: string;
}

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(text: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: "text", text }],
  };
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function buildGetConfigTool(deps: CoreModuleDeps): ToolDefinition {
  return {
    name: "altais_get_config",
    title: "Get altais-mcp configuration",
    description:
      "Return the active server config and the list of currently loaded modules. Use this to verify which security checks are available before scanning.",
    annotations: COMMON_ANNOTATIONS,
    handler: () => {
      const payload = {
        server: {
          name: deps.config.server.name,
          transport: deps.config.server.transport,
          port: deps.config.server.port,
          log_level: deps.config.server.log_level,
        },
        modules: deps.config.modules,
        active_modules: deps.activeModules(),
        package_version: PACKAGE_VERSION,
      };
      return textResult(jsonText(payload));
    },
  };
}

function buildExplainCweTool(state: CoreState): ToolDefinition {
  const inputSchema = {
    cwe: z.string().min(1).max(32).describe("CWE identifier, e.g. 'CWE-79' or '79'."),
  };
  return {
    name: "altais_explain_cwe",
    title: "Explain a CWE",
    description:
      "Look up a Common Weakness Enumeration (CWE) entry from the bundled database. Returns name, description, examples, and remediation guidance.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const entry = state.cwe.lookup(parsed.data.cwe);
      if (!entry) {
        return errorResult(
          `Unknown CWE: ${parsed.data.cwe}. Try a top-100 ID like CWE-79 or CWE-89.`,
        );
      }
      return textResult(jsonText(entry));
    },
  };
}

function buildScoreTool(): ToolDefinition {
  const inputSchema = {
    vector: z
      .string()
      .min(8)
      .max(256)
      .describe("CVSS vector string, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'."),
  };
  return {
    name: "altais_score",
    title: "Score a CVSS vector",
    description:
      "Calculate a CVSS base score from a vector string. Both CVSS v3.1 and CVSS v4.0 are fully scored: v3.1 per the FIRST §7.1 base formula, v4.0 via the official MacroVector lookup table with maximal-severity interpolation across all four metric groups.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      try {
        const vector = parsed.data.vector.trim();
        const result = vector.startsWith("CVSS:4.0/")
          ? calculateCvssV40(vector)
          : scoreCvss(vector);
        return textResult(jsonText(result));
      } catch (err) {
        if (err instanceof CvssError) return errorResult(err.message);
        return errorResult(`Unexpected scoring error: ${(err as Error).message}`);
      }
    },
  };
}

function buildReportTool(deps: CoreModuleDeps, state: CoreState): ToolDefinition {
  const inputSchema = {
    format: z
      .enum(["markdown", "json"])
      .default("markdown")
      .describe("Output format for the report."),
    include_info: z.boolean().default(false).describe("Include informational-severity findings."),
    group_by: z
      .enum(["module", "severity"])
      .default("module")
      .describe(
        "Markdown layout: `module` (default) groups findings under a per-module section; `severity` returns a flat severity-sorted list. JSON output always includes a `by_module` breakdown.",
      ),
  };
  return {
    name: "altais_report",
    title: "Generate session report",
    description:
      "Aggregate every finding produced by tools in this session and render a consolidated security report. Markdown output includes a module-level summary table plus per-module subsections; JSON output adds a `by_module` array with the findings grouped by module.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
        );
      }
      const { format, include_info, group_by } = parsed.data;
      const result = deps.findingStore.result(deps.activeModules(), state.configHash);
      const text =
        format === "json"
          ? renderJsonReport(result, include_info)
          : renderMarkdownReport(result, include_info, group_by);
      return textResult(text);
    },
  };
}

function buildRiskSummaryTool(deps: CoreModuleDeps): ToolDefinition {
  return {
    name: "altais_risk_summary",
    title: "Composite risk summary",
    description:
      "Return a composite risk score (0-100) and severity breakdown for all findings in the current session.",
    annotations: COMMON_ANNOTATIONS,
    handler: () => {
      const findings = deps.findingStore.all();
      const summary = deps.findingStore.summarize();
      return textResult(
        jsonText({
          risk_score: riskSummary(findings),
          total: summary.total,
          by_severity: summary.by_severity,
          by_module: summary.by_module,
        }),
      );
    },
  };
}

export function createCoreModule(deps: CoreModuleDeps): ModuleDefinition {
  // State that lives across init() and tool handler closures.
  const state: { value: CoreState | null } = { value: null };

  const ensureState = (): CoreState => {
    if (!state.value) {
      throw new Error("core module accessed before init()");
    }
    return state.value;
  };

  // Build tools eagerly but resolve state lazily so handlers can use the
  // database loaded during init().
  const explainCwe: ToolDefinition = {
    ...buildExplainCweTool({ cwe: new CweDatabase([]), configHash: "" }),
    handler: (args) => buildExplainCweTool(ensureState()).handler(args),
  };
  const report: ToolDefinition = {
    ...buildReportTool(deps, { cwe: new CweDatabase([]), configHash: "" }),
    handler: (args) => buildReportTool(deps, ensureState()).handler(args),
  };

  const tools: readonly ToolDefinition[] = [
    buildGetConfigTool(deps),
    explainCwe,
    buildScoreTool(),
    report,
    buildRiskSummaryTool(deps),
  ];

  return {
    name: "core",
    description: "Always-loaded utility tools: config, CWE lookup, CVSS scoring, reporting.",
    version: PACKAGE_VERSION,
    tools,
    async init() {
      const cwe = await CweDatabase.load(deps.dataDir);
      state.value = {
        cwe,
        configHash: hashJson(deps.config),
      };
    },
  };
}
