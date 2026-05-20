// Secret pattern loader + scanner.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, FindingLocation, Severity } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ALLOWED_FLAGS = /^[gimsu]*$/;

export interface SecretPatternRaw {
  readonly id: string;
  readonly name: string;
  readonly regex: string;
  readonly flags?: string;
  readonly severity: Severity;
  readonly cwe: readonly string[];
  readonly description: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly evidenceGroup?: number;
}

export interface SecretPattern {
  readonly id: string;
  readonly name: string;
  readonly regex: RegExp;
  readonly severity: Severity;
  readonly cwe: readonly string[];
  readonly description: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly evidenceGroup: number | undefined;
}

export interface SecretMatchOptions {
  readonly rules?: readonly string[];
  readonly maxFindings?: number;
}

export interface ScanInput {
  readonly source: string;
  readonly file?: string;
}

const DEFAULT_MAX_FINDINGS = 500;
const MAX_EVIDENCE_CHARS = 240;

function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

function compile(raw: SecretPatternRaw): SecretPattern {
  const flags = raw.flags ?? "g";
  if (!ALLOWED_FLAGS.test(flags)) {
    throw new Error(`secret pattern ${raw.id}: invalid flags "${flags}"`);
  }
  const withGlobal = flags.includes("g") ? flags : `${flags}g`;
  return {
    id: raw.id,
    name: raw.name,
    regex: new RegExp(raw.regex, withGlobal),
    severity: raw.severity,
    cwe: raw.cwe,
    description: raw.description,
    remediation: raw.remediation,
    references: raw.references,
    evidenceGroup: raw.evidenceGroup,
  };
}

export class SecretPatternRegistry {
  constructor(private readonly patterns: readonly SecretPattern[]) {}

  static async load(dataDir: string = defaultDataDir()): Promise<SecretPatternRegistry> {
    const file = path.join(dataDir, "secret-patterns.json");
    const raw = await readFile(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error(`secret-patterns.json must be an array (${file})`);
    }
    const compiled = (parsed as SecretPatternRaw[]).map(compile);
    return new SecretPatternRegistry(compiled);
  }

  all(): readonly SecretPattern[] {
    return this.patterns;
  }

  size(): number {
    return this.patterns.length;
  }

  scan(input: ScanInput, options: SecretMatchOptions = {}): readonly Finding[] {
    const { source } = input;
    const file = input.file ?? "<inline>";
    const max = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
    const filter = options.rules && options.rules.length > 0 ? new Set(options.rules) : null;
    const lineOffsets = computeLineOffsets(source);
    const out: Finding[] = [];

    for (const pattern of this.patterns) {
      if (filter && !filter.has(pattern.id)) continue;
      pattern.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.regex.exec(source)) !== null) {
        if (out.length >= max) return out;
        const full = m[0];
        const evidenceText =
          pattern.evidenceGroup !== undefined ? (m[pattern.evidenceGroup] ?? full) : full;
        const groupOffset =
          pattern.evidenceGroup !== undefined
            ? m.index + full.indexOf(m[pattern.evidenceGroup] ?? "")
            : m.index;
        const { line, column } = offsetToLineCol(groupOffset, lineOffsets);
        const evidence = redact(evidenceText.trim().replace(/\s+/g, " "), MAX_EVIDENCE_CHARS);
        const location: FindingLocation = {
          file,
          line_start: line,
          column,
        };
        out.push({
          id: findingId("secrets", pattern.id, location, evidence),
          module: "secrets",
          rule: pattern.id,
          severity: pattern.severity,
          cwe: pattern.cwe,
          title: pattern.name,
          description: pattern.description,
          location,
          evidence,
          remediation: pattern.remediation,
          references: pattern.references,
          tags: ["secret"],
          status: "open",
        });
        if (full.length === 0) pattern.regex.lastIndex += 1;
      }
    }
    return out;
  }
}

function computeLineOffsets(src: string): readonly number[] {
  const offsets: number[] = [0];
  for (let i = 0; i < src.length; i++) {
    if (src.charCodeAt(i) === 0x0a) offsets.push(i + 1);
  }
  return offsets;
}

function offsetToLineCol(
  offset: number,
  offsets: readonly number[],
): { line: number; column: number } {
  let lo = 0;
  let hi = offsets.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    const v = offsets[mid] ?? 0;
    if (v <= offset) lo = mid;
    else hi = mid - 1;
  }
  const base = offsets[lo] ?? 0;
  return { line: lo + 1, column: offset - base + 1 };
}

/**
 * Truncate evidence to a safe length and mask the middle so logs do not
 * preserve the secret verbatim. Keeps a 4-char head and 4-char tail to
 * help locate the literal in source.
 */
export function redact(text: string, max: number): string {
  const trimmed = text.length > max ? `${text.slice(0, max)}…` : text;
  if (trimmed.length <= 12) return trimmed;
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)} (len=${trimmed.length})`;
}
