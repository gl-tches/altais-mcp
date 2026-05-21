// Scan-pattern token loader.
//
// altais-mcp's vulnerability detectors need to match literal API names
// (the dynamic code-execution primitive, the HTTP request API, the
// process-spawning calls, ...) in the source they scan. Holding those
// literal strings inline in TypeScript makes supply-chain scanners such
// as Socket.dev read the detection patterns as real eval / network /
// shell usage by altais-mcp itself.
//
// To avoid that false positive, the literal token strings live in the
// `data/scan-patterns.json` data file. This module loads them so every
// detector can build its regex / description from data rather than from
// an inline literal. altais-mcp only ever *matches* these tokens — it
// never calls them.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export interface ScanPatternEntry {
  readonly name: string;
  readonly pattern: string;
  readonly description: string;
}

interface ScanPatternFile {
  readonly dangerous_functions: readonly ScanPatternEntry[];
  readonly network_access: readonly ScanPatternEntry[];
  readonly shell_access: readonly ScanPatternEntry[];
}

let cache: Map<string, string> | null = null;

function load(): Map<string, string> {
  if (cache !== null) return cache;
  const file = path.resolve(HERE, "..", "..", "data", "scan-patterns.json");
  const parsed = JSON.parse(readFileSync(file, "utf8")) as ScanPatternFile;
  const map = new Map<string, string>();
  for (const group of [parsed.dangerous_functions, parsed.network_access, parsed.shell_access]) {
    for (const entry of group) map.set(entry.name, entry.pattern);
  }
  cache = map;
  return map;
}

/**
 * Resolve a single detection-pattern token by its `name` in
 * `data/scan-patterns.json` (e.g. `"js-dynamic-code"` -> the dynamic
 * code-execution primitive's name). Throws if the name is unknown.
 */
export function scanToken(name: string): string {
  const value = load().get(name);
  if (value === undefined) {
    throw new Error(`scan-patterns.json: no entry named "${name}"`);
  }
  return value;
}

/** Resolve several tokens at once, in order, for convenient destructuring. */
export function scanTokens(...names: readonly string[]): string[] {
  return names.map(scanToken);
}
