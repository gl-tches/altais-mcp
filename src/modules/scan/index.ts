// Scan module: source code static analysis tools.

import { readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

import { z } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { Config } from "../../config.js";
import type { FindingStore } from "../../core/report.js";
import type { Finding, ModuleDefinition, ToolDefinition } from "../../core/types.js";
import { parseUnifiedDiff } from "./diff.js";
import { runPatterns } from "./engine.js";
import { detectLanguage, isSupported, type Language } from "./languages.js";
import { ALL_PATTERNS } from "./patterns/index.js";

const MODULE_VERSION = "0.3.0";

const COMMON_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

export interface ScanModuleDeps {
  readonly config: Config;
  readonly findingStore: FindingStore;
}

interface ScanState {
  readonly maxSourceBytes: number;
  readonly maxFileBytes: number;
  readonly scanRoot: string;
}

function deriveState(config: Config): ScanState {
  const configured = config.scan.scan_root;
  const scanRoot =
    configured && path.isAbsolute(configured)
      ? path.resolve(configured)
      : path.resolve(process.cwd());
  return {
    maxSourceBytes: config.scan.max_source_bytes,
    maxFileBytes: config.scan.max_file_size_kb * 1024,
    scanRoot,
  };
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
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }
  return { total: findings.length, by_severity: bySeverity };
}

const rulesField = z
  .array(z.string().min(1).max(128))
  .max(64)
  .optional()
  .describe("Restrict to pattern IDs or category names. Empty = all enabled.");

function buildScanCodeTool(deps: ScanModuleDeps, state: ScanState): ToolDefinition {
  const inputSchema = {
    source: z.string().min(1).max(state.maxSourceBytes).describe("Source code to scan."),
    language: z
      .string()
      .min(1)
      .max(32)
      .optional()
      .describe(
        "Language hint, e.g. 'typescript', 'python'. Auto-detected from filename if omitted.",
      ),
    filename: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe("Optional filename used for reporting and language detection."),
    rules: rulesField,
  };
  return {
    name: "altais_scan_code",
    title: "Scan source code",
    description:
      "Run security pattern detection against inline source code (TypeScript, JavaScript, Python, Go, Rust). Detects injection, XSS, SSRF, path traversal, exceptional conditions, prototype pollution, SSTI, ReDoS, race conditions, insecure deserialization, business-logic flaws, request smuggling, cache poisoning, CRLF injection, and host-header injection. Findings are also appended to the session report.",
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
      const { source, language: lang, filename, rules } = parsed.data;
      const language = detectLanguage({
        ...(lang !== undefined ? { language: lang } : {}),
        ...(filename !== undefined ? { filename } : {}),
        source,
      });
      if (!isSupported(language)) {
        return errorResult(
          "Unsupported or undetected language. Pass an explicit `language` (typescript, javascript, python, go, rust) or a `filename` with a known extension.",
        );
      }
      const findings = runPatterns(
        ALL_PATTERNS,
        {
          source,
          language,
          ...(filename !== undefined ? { file: filename } : {}),
        },
        rules ? { rules } : {},
      );
      deps.findingStore.addMany(findings);
      deps.findingStore.recordFileScanned();
      return textResult(jsonText({ language, summary: summarize(findings), findings }));
    },
  };
}

function buildScanFileTool(deps: ScanModuleDeps, state: ScanState): ToolDefinition {
  const inputSchema = {
    path: z
      .string()
      .min(1)
      .max(2048)
      .describe("File path to scan. Resolved against the configured scan_root."),
    rules: rulesField,
  };
  return {
    name: "altais_scan_file",
    title: "Scan a file",
    description:
      "Read a file from disk and run the scan patterns against it. The path is canonicalized and required to live under the configured scan root; symlinks pointing outside the root are rejected.",
    inputSchema,
    annotations: COMMON_ANNOTATIONS,
    handler: async (args) => {
      const parsed = z.object(inputSchema).safeParse(args);
      if (!parsed.success) {
        return errorResult(
          `Invalid input: ${parsed.error.issues
            .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
            .join("; ")}`,
        );
      }
      const userPath = parsed.data.path;
      const resolved = path.resolve(state.scanRoot, userPath);
      let realResolved: string;
      try {
        realResolved = await realpath(resolved);
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code === "ENOENT") return errorResult(`File not found: ${userPath}`);
        return errorResult(`Cannot resolve ${userPath}: ${(err as Error).message}`);
      }
      if (!isInside(realResolved, state.scanRoot)) {
        return errorResult(
          `Path escapes scan_root: ${userPath}. Configure scan.scan_root or pass a path inside the project.`,
        );
      }
      let stats;
      try {
        stats = await stat(realResolved);
      } catch (err) {
        return errorResult(`Cannot stat ${userPath}: ${(err as Error).message}`);
      }
      if (!stats.isFile()) {
        return errorResult(`Not a regular file: ${userPath}`);
      }
      if (stats.size > state.maxFileBytes) {
        return errorResult(
          `File too large: ${stats.size} bytes (limit ${state.maxFileBytes}). Increase scan.max_file_size_kb to allow it.`,
        );
      }

      const relPath = path.relative(state.scanRoot, realResolved) || path.basename(realResolved);
      const language = detectLanguage({ filename: realResolved });
      if (!isSupported(language)) {
        return errorResult(
          `Unsupported language for ${relPath}. Supported: typescript, javascript, python, go, rust.`,
        );
      }
      const source = await readFile(realResolved, "utf8");
      const findings = runPatterns(
        ALL_PATTERNS,
        { source, language, file: relPath },
        parsed.data.rules ? { rules: parsed.data.rules } : {},
      );
      deps.findingStore.addMany(findings);
      deps.findingStore.recordFileScanned();
      return textResult(
        jsonText({ file: relPath, language, summary: summarize(findings), findings }),
      );
    },
  };
}

function buildScanDiffTool(deps: ScanModuleDeps, state: ScanState): ToolDefinition {
  const inputSchema = {
    diff: z
      .string()
      .min(1)
      .max(state.maxSourceBytes)
      .describe("Unified diff (e.g. `git diff` output) to scan."),
    rules: rulesField,
  };
  return {
    name: "altais_scan_diff",
    title: "Scan a unified diff",
    description:
      "Parse a unified diff and run scan patterns against the touched hunks of every changed file. Only findings that overlap an added line are reported.",
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
      const files = parseUnifiedDiff(parsed.data.diff);
      const allFindings: Finding[] = [];
      const perFile: { path: string; language: Language; findings: number }[] = [];

      for (const file of files) {
        if (file.path === "/dev/null") continue;
        const language = detectLanguage({ filename: file.path });
        if (!isSupported(language)) {
          perFile.push({ path: file.path, language, findings: 0 });
          continue;
        }
        let fileFindingCount = 0;
        for (const hunk of file.hunks) {
          if (hunk.newLines.length === 0) continue;
          const addedSet = new Set(hunk.addedLineNumbers);
          const hunkFindings = runPatterns(
            ALL_PATTERNS,
            {
              source: hunk.newLines.join("\n"),
              language,
              file: file.path,
            },
            parsed.data.rules ? { rules: parsed.data.rules } : {},
          );
          for (const finding of hunkFindings) {
            const absoluteStart = hunk.newStart + (finding.location?.line_start ?? 1) - 1;
            const absoluteEnd =
              finding.location?.line_end !== undefined
                ? hunk.newStart + finding.location.line_end - 1
                : undefined;
            // Only surface findings that actually touch an added line.
            const startInAdded = addedSet.has(absoluteStart);
            const endInAdded = absoluteEnd !== undefined && addedSet.has(absoluteEnd);
            if (!startInAdded && !endInAdded) continue;
            const remapped: Finding = {
              ...finding,
              location: {
                file: file.path,
                line_start: absoluteStart,
                ...(absoluteEnd !== undefined ? { line_end: absoluteEnd } : {}),
                ...(finding.location?.column !== undefined
                  ? { column: finding.location.column }
                  : {}),
              },
            };
            allFindings.push(remapped);
            fileFindingCount += 1;
          }
        }
        perFile.push({ path: file.path, language, findings: fileFindingCount });
      }

      deps.findingStore.addMany(allFindings);
      return textResult(
        jsonText({
          files: perFile,
          summary: summarize(allFindings),
          findings: allFindings,
        }),
      );
    },
  };
}

function isInside(candidate: string, root: string): boolean {
  if (candidate === root) return true;
  const withSep = root.endsWith(path.sep) ? root : `${root}${path.sep}`;
  return candidate.startsWith(withSep);
}

export function createScanModule(deps: ScanModuleDeps): ModuleDefinition {
  const state = deriveState(deps.config);
  const tools: readonly ToolDefinition[] = [
    buildScanCodeTool(deps, state),
    buildScanFileTool(deps, state),
    buildScanDiffTool(deps, state),
  ];

  return {
    name: "scan",
    description:
      "Static analysis security scanning for source code (TypeScript, JavaScript, Python, Go, Rust).",
    version: MODULE_VERSION,
    tools,
    init() {
      // No async resources to load — config is consumed at construction.
    },
  };
}
