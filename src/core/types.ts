import type { z } from "zod";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "open" | "confirmed" | "false_positive" | "mitigated";

export type CvssVersion = "3.1" | "4.0";

export interface FindingLocation {
  readonly file: string;
  readonly line_start: number;
  readonly line_end?: number;
  readonly column?: number;
}

export interface Finding {
  readonly id: string;
  readonly module: string;
  readonly rule: string;
  readonly severity: Severity;
  readonly cvss?: number;
  readonly cvss_version?: CvssVersion;
  readonly cwe?: readonly string[];
  readonly title: string;
  readonly description: string;
  readonly location?: FindingLocation;
  readonly evidence?: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly tags: readonly string[];
  readonly status: FindingStatus;
}

export interface ScanSummary {
  readonly total: number;
  readonly by_severity: Readonly<Record<Severity, number>>;
  readonly by_module: Readonly<Record<string, number>>;
  readonly risk_score: number;
}

export interface ScanMetadata {
  readonly scanned_at: string;
  readonly duration_ms: number;
  readonly files_scanned: number;
  readonly modules_active: readonly string[];
  readonly config_hash: string;
}

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly summary: ScanSummary;
  readonly metadata: ScanMetadata;
}

export type ToolHandler = (
  args: Record<string, unknown>,
) => Promise<CallToolResult> | CallToolResult;

export interface ToolDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description: string;
  readonly inputSchema?: z.ZodRawShape;
  readonly outputSchema?: z.ZodRawShape;
  readonly annotations: ToolAnnotations;
  readonly handler: ToolHandler;
}

export type ModuleConfig = Record<string, unknown>;

export interface ModuleDefinition {
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly dependencies?: readonly string[];
  readonly tools: readonly ToolDefinition[];
  readonly init: (config: ModuleConfig) => Promise<void> | void;
}
