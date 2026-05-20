// OWASP knowledge-base loader.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface OwaspCategory {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly cwes: readonly string[];
  readonly detection_hints: readonly string[];
  readonly remediation: string;
}

export type AsvsLevel = 1 | 2 | 3;

export interface AsvsControl {
  readonly id: string;
  readonly section: string;
  readonly section_name: string;
  readonly level: AsvsLevel;
  readonly description: string;
}

export interface OwaspKnowledge {
  readonly web_top_10_2025: readonly OwaspCategory[];
  readonly api_top_10_2023: readonly OwaspCategory[];
  readonly mobile_top_10_2024: readonly OwaspCategory[];
  readonly serverless_top_10: readonly OwaspCategory[];
  readonly asvs: {
    readonly version: string;
    readonly controls: readonly AsvsControl[];
  };
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

export async function loadOwaspKnowledge(
  dataDir: string = defaultDataDir(),
): Promise<OwaspKnowledge> {
  const file = path.join(dataDir, "owasp-controls.json");
  const raw = await readFile(file, "utf8");
  const parsed = JSON.parse(raw) as OwaspKnowledge;
  if (!Array.isArray(parsed.web_top_10_2025)) {
    throw new Error(`Malformed OWASP knowledge file: ${file}`);
  }
  return parsed;
}
