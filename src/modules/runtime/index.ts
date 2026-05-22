// vuln_db module: 4 vulnerability-knowledge lookup tools —
// CVE lookup, full CWE taxonomy lookup, a complete CVSS v3.1 + v4.0
// calculator, and CWE/description-to-MITRE-ATT&CK mapping.
//
// All four tools read bundled, offline data files and make no network
// calls at runtime. These are lookup/calculation tools: they return
// structured JSON results and do not push Finding objects into the
// shared FindingStore.

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { AttackCatalog, mapToAttack } from "./attack.js";
import { CveDatabase, CVE_ID_RE, lookupCve } from "./cve.js";
import { calculateCvss, CvssCalcError } from "./cvss.js";
import { CweDatabase, lookupCwe } from "./cwe.js";

const MODULE_VERSION = "0.4.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface VulnDbModuleDeps {
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

// ─── altais_lookup_cve ─────────────────────────────────────────────────────

const cveSchema = z.object({
  cve_id: z
    .string()
    .min(1)
    .max(32)
    .regex(CVE_ID_RE, "must be a CVE identifier of the form CVE-YYYY-NNNN")
    .describe("A CVE identifier, e.g. `CVE-2021-44228`."),
});

function buildLookupCveTool(db: CveDatabase): ToolDefinition {
  const parse = zodParser(cveSchema);
  return {
    name: "altais_lookup_cve",
    title: "Look up a CVE",
    description:
      "Look up a CVE by identifier in a bundled, curated offline snapshot of well-known, high-impact CVEs (Log4Shell, Heartbleed, Spring4Shell, xz backdoor, and others). Returns the description, CVSS v3.1 vector and score, severity, related CWEs, affected versions, publication date, remediation guidance, and references. This is an offline snapshot, not a live feed.",
    inputSchema: cveSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      const result = lookupCve(db, parsed.data.cve_id);
      if (!result.found) return errorResult(result.message);
      return textResult(jsonText(result.cve));
    },
  };
}

// ─── altais_lookup_cwe ─────────────────────────────────────────────────────

const cweSchema = z.object({
  cwe_id: z
    .string()
    .min(1)
    .max(32)
    .regex(
      /^(?:cwe[-_ ]?)?\d{1,5}(?:[-_][a-z0-9]+)?$/i,
      "must be a CWE identifier, e.g. CWE-79 or 79",
    )
    .describe("A CWE identifier in any common form: `79`, `CWE-79`, `cwe-79`."),
});

function buildLookupCweTool(db: CweDatabase): ToolDefinition {
  const parse = zodParser(cweSchema);
  return {
    name: "altais_lookup_cwe",
    title: "Look up a CWE in the full taxonomy",
    description:
      "Full CWE taxonomy lookup against the bundled CWE database. Accepts an id in any form (`79`, `CWE-79`). Returns the weakness name, description, concrete examples, remediation, and references, plus related CWEs (parent / child / peer relations) derived from a curated relation map and cross-references in the entry text. Richer than the core module's `altais_explain_cwe`.",
    inputSchema: cweSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      const result = lookupCwe(db, parsed.data.cwe_id);
      if (!result.found) return errorResult(result.message);
      return textResult(jsonText({ entry: result.entry, related: result.related }));
    },
  };
}

// ─── altais_calculate_cvss ─────────────────────────────────────────────────

const cvssSchema = z.object({
  vector: z
    .string()
    .min(1)
    .max(512)
    .regex(/^CVSS:[34]\.[0-9]\//, "must start with a `CVSS:3.1/` or `CVSS:4.0/` prefix")
    .describe(
      "A CVSS vector string. v3.1 (`CVSS:3.1/...`) or v4.0 (`CVSS:4.0/...`). Temporal / Environmental / Threat / Supplemental metrics are scored when present.",
    ),
});

function buildCalculateCvssTool(): ToolDefinition {
  const parse = zodParser(cvssSchema);
  return {
    name: "altais_calculate_cvss",
    title: "Calculate a CVSS score",
    description:
      "Parse and score a CVSS vector. CVSS v3.1: Base score plus Temporal and Environmental metric groups when supplied. CVSS v4.0: all four metric groups (Base, Threat, Environmental, Supplemental) are parsed and validated, the MacroVector is derived, and the score is computed with the official FIRST CVSS v4.0 lookup-table algorithm. Returns the version, score, qualitative severity, subscores, and the parsed metric groups.",
    inputSchema: cvssSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      try {
        const result = calculateCvss(parsed.data.vector);
        return textResult(jsonText(result));
      } catch (err) {
        if (err instanceof CvssCalcError) {
          return errorResult(
            `Could not score the CVSS vector: ${err.message}. Verify each metric key and value ` +
              `against the FIRST CVSS specification at https://www.first.org/cvss/.`,
          );
        }
        return errorResult("Could not score the CVSS vector due to an unexpected parsing error.");
      }
    },
  };
}

// ─── altais_map_attack ─────────────────────────────────────────────────────

const attackSchema = z
  .object({
    cwe: z
      .string()
      .min(1)
      .max(32)
      .regex(/^(?:cwe[-_ ]?)?\d{1,5}(?:[-_][a-z0-9]+)?$/i, "must be a CWE identifier, e.g. CWE-89")
      .optional()
      .describe("Optional CWE identifier to map, e.g. `CWE-89`."),
    description: z
      .string()
      .min(1)
      .max(4096)
      .optional()
      .describe(
        "Optional free-text vulnerability description to match against technique keywords.",
      ),
    limit: z
      .number()
      .int()
      .min(1)
      .max(30)
      .default(10)
      .describe("Maximum number of ranked techniques to return."),
  })
  .refine((v) => v.cwe !== undefined || v.description !== undefined, {
    message: "provide at least one of `cwe` or `description`",
  });

function buildMapAttackTool(catalog: AttackCatalog): ToolDefinition {
  const parse = zodParser(attackSchema);
  return {
    name: "altais_map_attack",
    title: "Map a vulnerability to MITRE ATT&CK techniques",
    description:
      "Map a CWE identifier and/or a free-text vulnerability description to MITRE ATT&CK techniques, using a bundled, curated subset of software-relevant techniques. A CWE match against a technique's related weaknesses is the strongest signal; description keywords add weight. Returns ranked techniques with id, name, tactic, a normalized confidence score, and the reasons each matched.",
    inputSchema: attackSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = parse(args);
      if (!parsed.success) return errorResult(`Invalid input: ${parsed.message}`);
      const result = mapToAttack(catalog, {
        ...(parsed.data.cwe !== undefined ? { cwe: parsed.data.cwe } : {}),
        ...(parsed.data.description !== undefined ? { description: parsed.data.description } : {}),
        limit: parsed.data.limit,
      });
      return textResult(jsonText(result));
    },
  };
}

// ─── module assembly ───────────────────────────────────────────────────────

export function createVulnDbModule(deps: VulnDbModuleDeps): ModuleDefinition {
  const state: {
    cve: CveDatabase | null;
    cwe: CweDatabase | null;
    attack: AttackCatalog | null;
  } = { cve: null, cwe: null, attack: null };

  const ensureCve = (): CveDatabase => {
    if (state.cve === null) throw new Error("vuln_db module accessed before init()");
    return state.cve;
  };
  const ensureCwe = (): CweDatabase => {
    if (state.cwe === null) throw new Error("vuln_db module accessed before init()");
    return state.cwe;
  };
  const ensureAttack = (): AttackCatalog => {
    if (state.attack === null) throw new Error("vuln_db module accessed before init()");
    return state.attack;
  };

  // Build placeholder tools so registration metadata (name, schema,
  // description) is available immediately; handlers resolve the loaded
  // databases lazily after init().
  const cvePlaceholder = buildLookupCveTool(new CveDatabase([]));
  const cwePlaceholder = buildLookupCweTool(new CweDatabase([]));
  const attackPlaceholder = buildMapAttackTool(new AttackCatalog([]));

  const tools: readonly ToolDefinition[] = [
    {
      ...cvePlaceholder,
      handler: (args) => buildLookupCveTool(ensureCve()).handler(args),
    },
    {
      ...cwePlaceholder,
      handler: (args) => buildLookupCweTool(ensureCwe()).handler(args),
    },
    buildCalculateCvssTool(),
    {
      ...attackPlaceholder,
      handler: (args) => buildMapAttackTool(ensureAttack()).handler(args),
    },
  ];

  return {
    name: "vuln_db",
    description:
      "Vulnerability knowledge base: CVE lookup, full CWE taxonomy lookup with related weaknesses, a complete CVSS v3.1 + v4.0 calculator, and CWE/description-to-MITRE-ATT&CK technique mapping — all from bundled offline data.",
    version: MODULE_VERSION,
    tools,
    async init() {
      state.cve = await CveDatabase.load(deps.dataDir);
      state.cwe = await CweDatabase.load(deps.dataDir);
      state.attack = await AttackCatalog.load(deps.dataDir);
    },
  };
}
