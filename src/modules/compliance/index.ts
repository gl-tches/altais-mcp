// Compliance module: 3 tools that map security findings to the controls
// of 16 compliance frameworks (OWASP ASVS/SAMM/DSOMM, NIST 800-53/SSDF/
// AI RMF, ISO 27001, SOC 2, GDPR, PCI-DSS, NIS2, DORA, CRA, CISA Secure
// by Design, EO 14028, and FDA 524B).
//
//   - altais_map_findings     — map findings to a framework's controls
//   - altais_gap_analysis     — coverage / gap report for a framework
//   - altais_generate_evidence — generate an audit evidence pack

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, Severity, ToolDefinition } from "../../core/types.js";
import { buildComplianceFinding } from "./finding.js";
import {
  FRAMEWORK_IDS,
  FRAMEWORK_REFERENCES,
  FrameworkRegistry,
  type ComplianceControl,
  type ComplianceFramework,
  type FrameworkId,
} from "./frameworks.js";
import {
  isHighRiskFamily,
  mapFindingsToFramework,
  toMappable,
  type ControlMapping,
  type MappableFinding,
} from "./mapper.js";

const MODULE_VERSION = "0.4.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ComplianceModuleDeps {
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

// ─── Shared input schema fragments ─────────────────────────────────────────

const frameworkField = z
  .enum(FRAMEWORK_IDS)
  .describe("The compliance framework to evaluate against (one of the 16 bundled framework ids).");

const suppliedFindingSchema = z.object({
  rule: z.string().min(1).max(128).describe("The rule / check that produced the finding."),
  cwe: z
    .array(z.string().min(1).max(32))
    .max(32)
    .optional()
    .describe("CWE identifiers associated with the finding (e.g. `CWE-89`)."),
  title: z.string().min(1).max(512).optional().describe("Human-readable finding title."),
  severity: z
    .enum(["critical", "high", "medium", "low", "info"])
    .optional()
    .describe("Finding severity; defaults to `medium` when omitted."),
});

const findingsField = z
  .array(suppliedFindingSchema)
  .max(2000)
  .optional()
  .describe(
    "Optional explicit findings to evaluate. When omitted, the shared session FindingStore is used.",
  );

type SuppliedFinding = z.infer<typeof suppliedFindingSchema>;

/**
 * Resolve the set of findings to evaluate: an explicit `findings` array
 * when supplied, otherwise the session FindingStore.
 */
function gatherFindings(
  deps: ComplianceModuleDeps,
  supplied: readonly SuppliedFinding[] | undefined,
): readonly MappableFinding[] {
  if (supplied !== undefined && supplied.length > 0) {
    return supplied.map((f, idx) => ({
      id: `supplied:${f.rule}:${String(idx)}`,
      rule: f.rule,
      title: f.title ?? f.rule,
      severity: f.severity ?? "medium",
      cwe: f.cwe ?? [],
    }));
  }
  return deps.findingStore.all().map(toMappable);
}

// ─── Finding emission ──────────────────────────────────────────────────────

function refsFor(frameworkId: FrameworkId): readonly string[] {
  return [FRAMEWORK_REFERENCES[frameworkId], "https://cwe.mitre.org/"];
}

/** Collect the distinct CWE IDs across a control and its matched findings. */
function controlCwes(mapping: ControlMapping): readonly string[] {
  const set = new Set<string>(mapping.control.cwes);
  for (const f of mapping.matched_findings) for (const c of f.cwe) set.add(c);
  return Array.from(set);
}

/**
 * Emit one Finding per addressed control recording the mapping — these
 * surface in the consolidated report as an audit trail of which controls
 * the current findings touch.
 */
function emitMappingFindings(
  result: ReturnType<typeof mapFindingsToFramework>,
  frameworkId: FrameworkId,
): readonly Finding[] {
  const out: Finding[] = [];
  for (const mapping of result.mappings) {
    if (mapping.status !== "addressed") continue;
    const count = mapping.matched_findings.length;
    out.push(
      buildComplianceFinding(
        {
          rule: `mapping:${frameworkId}:${mapping.control.id}`,
          severity: "info",
          title: `${result.framework_name} ${mapping.control.id} — ${mapping.control.title} (${String(count)} related finding${count === 1 ? "" : "s"})`,
          description: `${String(count)} finding${count === 1 ? "" : "s"} map to control ${mapping.control.id} (${mapping.control.title}). ${mapping.control.description}`,
          remediation: `Review the ${String(count)} related finding${count === 1 ? "" : "s"} as evidence relevant to ${result.framework_name} control ${mapping.control.id}; resolve them to demonstrate the control is met.`,
          cwe: controlCwes(mapping),
          references: refsFor(frameworkId),
          evidence: mapping.matched_findings
            .map((f) => f.rule)
            .join(", ")
            .slice(0, 200),
          tags: ["mapping", frameworkId, mapping.control.family],
        },
        undefined,
      ),
    );
  }
  return out;
}

/**
 * Emit one Finding per gap control — control areas with no related
 * finding, i.e. areas the current assessment has not covered.
 */
function emitGapFindings(
  result: ReturnType<typeof mapFindingsToFramework>,
  frameworkId: FrameworkId,
): readonly Finding[] {
  const out: Finding[] = [];
  for (const mapping of result.mappings) {
    if (mapping.status !== "gap") continue;
    const severity: Severity = isHighRiskFamily(mapping.control.family) ? "high" : "medium";
    out.push(
      buildComplianceFinding(
        {
          rule: `gap:${frameworkId}:${mapping.control.id}`,
          severity,
          title: `${result.framework_name} ${mapping.control.id} — ${mapping.control.title}: not assessed`,
          description: `No finding maps to ${result.framework_name} control ${mapping.control.id} (${mapping.control.title}). ${mapping.control.description} This control area has not been assessed by the current scan.`,
          remediation: `Assess control ${mapping.control.id} (${mapping.control.family}) for ${result.framework_name}: run scans that exercise this control area or document a compensating control, then re-run the gap analysis.`,
          cwe: mapping.control.cwes,
          references: refsFor(frameworkId),
          tags: ["gap", frameworkId, mapping.control.family],
        },
        undefined,
      ),
    );
  }
  return out;
}

// ─── altais_map_findings ───────────────────────────────────────────────────

const mapFindingsSchema = z.object({
  framework: frameworkField,
  findings: findingsField,
});

function runMapFindings(
  deps: ComplianceModuleDeps,
  registry: FrameworkRegistry,
  data: z.infer<typeof mapFindingsSchema>,
): CallToolResult {
  const framework: ComplianceFramework | undefined = registry.get(data.framework);
  if (framework === undefined) {
    return errorResult(
      `Unknown framework: ${data.framework}. Use one of: ${FRAMEWORK_IDS.join(", ")}.`,
    );
  }
  const findings = gatherFindings(deps, data.findings);
  const result = mapFindingsToFramework(findings, framework);
  deps.findingStore.addMany(emitMappingFindings(result, data.framework));
  return textResult(jsonText(result));
}

function buildMapFindingsTool(
  deps: ComplianceModuleDeps,
  ensure: () => FrameworkRegistry,
): ToolDefinition {
  return {
    name: "altais_map_findings",
    title: "Map findings to compliance-framework controls",
    description:
      "Map security findings to the controls of a compliance framework. Each finding is matched to controls whose CWE list intersects the finding's CWEs, or whose keywords appear in the finding's rule or title. Returns a per-control list of matched findings plus coverage statistics. When `findings` is omitted, the shared session FindingStore is used.",
    inputSchema: mapFindingsSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = mapFindingsSchema.safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      return runMapFindings(deps, ensure(), parsed.data);
    },
  };
}

// ─── altais_gap_analysis ───────────────────────────────────────────────────

const gapAnalysisSchema = z.object({
  framework: frameworkField,
  findings: findingsField,
});

interface GapControl {
  readonly id: string;
  readonly title: string;
  readonly family: string;
  readonly description: string;
  readonly severity: Severity;
}

function runGapAnalysis(
  deps: ComplianceModuleDeps,
  registry: FrameworkRegistry,
  data: z.infer<typeof gapAnalysisSchema>,
): CallToolResult {
  const framework: ComplianceFramework | undefined = registry.get(data.framework);
  if (framework === undefined) {
    return errorResult(
      `Unknown framework: ${data.framework}. Use one of: ${FRAMEWORK_IDS.join(", ")}.`,
    );
  }
  const findings = gatherFindings(deps, data.findings);
  const result = mapFindingsToFramework(findings, framework);

  const gaps: GapControl[] = [];
  const addressed: { id: string; title: string }[] = [];
  for (const mapping of result.mappings) {
    if (mapping.status === "gap") {
      gaps.push({
        id: mapping.control.id,
        title: mapping.control.title,
        family: mapping.control.family,
        description: mapping.control.description,
        severity: isHighRiskFamily(mapping.control.family) ? "high" : "medium",
      });
    } else {
      addressed.push({ id: mapping.control.id, title: mapping.control.title });
    }
  }

  deps.findingStore.addMany(emitGapFindings(result, data.framework));

  return textResult(
    jsonText({
      framework_id: result.framework_id,
      framework_name: result.framework_name,
      framework_version: result.framework_version,
      coverage: {
        total_controls: result.summary.total_controls,
        addressed: result.summary.addressed,
        gap: result.summary.gap,
        coverage_pct: result.summary.coverage_pct,
      },
      addressed_controls: addressed,
      gap_controls: gaps,
    }),
  );
}

function buildGapAnalysisTool(
  deps: ComplianceModuleDeps,
  ensure: () => FrameworkRegistry,
): ToolDefinition {
  return {
    name: "altais_gap_analysis",
    title: "Generate a compliance gap report",
    description:
      "Generate a gap analysis for a compliance framework. Every control is classified as `addressed` (at least one finding maps to it) or `gap` (no finding maps to it — that control area has not been assessed). Returns coverage statistics and the list of gap controls, and emits a finding per gap so unassessed control areas surface in the consolidated report.",
    inputSchema: gapAnalysisSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = gapAnalysisSchema.safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      return runGapAnalysis(deps, ensure(), parsed.data);
    },
  };
}

// ─── altais_generate_evidence ──────────────────────────────────────────────

const generateEvidenceSchema = z.object({
  framework: frameworkField,
  control_ids: z
    .array(z.string().min(1).max(64))
    .max(200)
    .optional()
    .describe("Optional list of control ids to include; when omitted, all controls are included."),
  findings: findingsField,
});

interface EvidenceRecord {
  readonly control_id: string;
  readonly control_title: string;
  readonly control_family: string;
  readonly status: "addressed" | "gap";
  readonly evidence_statement: string;
  readonly evidence_findings: readonly {
    readonly id: string;
    readonly rule: string;
    readonly title: string;
    readonly severity: Severity;
  }[];
}

function evidenceStatement(mapping: ControlMapping, frameworkName: string): string {
  const c: ComplianceControl = mapping.control;
  if (mapping.status === "gap") {
    return `No assessment evidence is available for ${frameworkName} control ${c.id} (${c.title}). This control area was not exercised by the current scan; a manual review or a compensating control must be documented.`;
  }
  const count = mapping.matched_findings.length;
  return `${frameworkName} control ${c.id} (${c.title}) was assessed; ${String(count)} related finding${count === 1 ? "" : "s"} (${mapping.matched_findings
    .map((f) => f.rule)
    .join(
      ", ",
    )}) were identified as evidence. Resolution of these findings demonstrates conformance.`;
}

function runGenerateEvidence(
  deps: ComplianceModuleDeps,
  registry: FrameworkRegistry,
  data: z.infer<typeof generateEvidenceSchema>,
): CallToolResult {
  const framework: ComplianceFramework | undefined = registry.get(data.framework);
  if (framework === undefined) {
    return errorResult(
      `Unknown framework: ${data.framework}. Use one of: ${FRAMEWORK_IDS.join(", ")}.`,
    );
  }
  const findings = gatherFindings(deps, data.findings);
  const result = mapFindingsToFramework(findings, framework);

  const filter: Set<string> | undefined =
    data.control_ids !== undefined ? new Set(data.control_ids) : undefined;
  const selected = result.mappings.filter((m) => filter === undefined || filter.has(m.control.id));

  if (filter !== undefined && selected.length === 0) {
    return errorResult(
      `No matching controls in ${framework.name}. Valid control ids: ${framework.controls
        .map((c) => c.id)
        .join(", ")}.`,
    );
  }

  const records: EvidenceRecord[] = selected.map((mapping) => ({
    control_id: mapping.control.id,
    control_title: mapping.control.title,
    control_family: mapping.control.family,
    status: mapping.status,
    evidence_statement: evidenceStatement(mapping, framework.name),
    evidence_findings: mapping.matched_findings.map((f) => ({
      id: f.id,
      rule: f.rule,
      title: f.title,
      severity: f.severity,
    })),
  }));

  const addressed = records.filter((r) => r.status === "addressed").length;
  return textResult(
    jsonText({
      framework_id: framework.id,
      framework_name: framework.name,
      framework_version: framework.version,
      generated_at_note:
        "Evidence pack derived from the current finding set; statements are advisory and require auditor review.",
      reference: FRAMEWORK_REFERENCES[data.framework],
      summary: {
        controls_in_pack: records.length,
        addressed,
        gap: records.length - addressed,
      },
      evidence: records,
    }),
  );
}

function buildGenerateEvidenceTool(
  deps: ComplianceModuleDeps,
  ensure: () => FrameworkRegistry,
): ToolDefinition {
  return {
    name: "altais_generate_evidence",
    title: "Generate compliance evidence artifacts",
    description:
      "Generate a structured evidence pack for an audit against a compliance framework. For each selected control (all controls by default, or those named in `control_ids`), produces an evidence record with the control id/title, its `addressed`/`gap` status, the findings serving as evidence, and a generated evidence statement. Returns the evidence pack as JSON.",
    inputSchema: generateEvidenceSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: (args) => {
      const parsed = generateEvidenceSchema.safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      return runGenerateEvidence(deps, ensure(), parsed.data);
    },
  };
}

// ─── Module factory ────────────────────────────────────────────────────────

export function createComplianceModule(deps: ComplianceModuleDeps): ModuleDefinition {
  const registryRef: { value: FrameworkRegistry | null } = { value: null };
  const ensure = (): FrameworkRegistry => {
    if (registryRef.value === null) {
      throw new Error("compliance module accessed before init()");
    }
    return registryRef.value;
  };

  const tools: readonly ToolDefinition[] = [
    buildMapFindingsTool(deps, ensure),
    buildGapAnalysisTool(deps, ensure),
    buildGenerateEvidenceTool(deps, ensure),
  ];

  return {
    name: "compliance",
    description:
      "Compliance mapping: map security findings to the controls of 16 frameworks (OWASP ASVS/SAMM/DSOMM, NIST 800-53/SSDF/AI RMF, ISO 27001, SOC 2, GDPR, PCI-DSS, NIS2, DORA, CRA, CISA Secure by Design, EO 14028, FDA 524B), run gap analyses, and generate audit evidence packs.",
    version: MODULE_VERSION,
    tools,
    async init() {
      registryRef.value = await FrameworkRegistry.load(deps.dataDir);
    },
  };
}
