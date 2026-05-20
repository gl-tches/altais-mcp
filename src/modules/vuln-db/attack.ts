// MITRE ATT&CK technique mapping (altais_map_attack).
//
// Maps a CWE id and/or a free-text vulnerability description to MITRE
// ATT&CK techniques. The technique catalogue is a curated, bundled
// subset of software-relevant techniques in `data/attack-techniques.json`
// — no network calls (CLAUDE.md rule 3).

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { normalizeCweId } from "../core/cwe.js";

export interface AttackTechnique {
  readonly id: string;
  readonly name: string;
  readonly tactic: string;
  readonly description: string;
  readonly related_cwes: readonly string[];
  readonly keywords: readonly string[];
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

function isAttackTechnique(value: unknown): value is AttackTechnique {
  if (typeof value !== "object" || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r.id === "string" &&
    typeof r.name === "string" &&
    typeof r.tactic === "string" &&
    typeof r.description === "string" &&
    isStringArray(r.related_cwes) &&
    isStringArray(r.keywords)
  );
}

export class AttackCatalog {
  private readonly techniques: readonly AttackTechnique[];

  constructor(techniques: readonly AttackTechnique[]) {
    this.techniques = techniques;
  }

  static async load(dataDir: string = defaultDataDir()): Promise<AttackCatalog> {
    const file = path.join(dataDir, "attack-techniques.json");
    const raw = await readFile(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error(`ATT&CK technique database is not an array: ${file}`);
    }
    const techniques: AttackTechnique[] = [];
    for (const item of parsed) {
      if (!isAttackTechnique(item)) {
        throw new Error(`Malformed ATT&CK technique in ${file}`);
      }
      techniques.push(item);
    }
    return new AttackCatalog(techniques);
  }

  all(): readonly AttackTechnique[] {
    return this.techniques;
  }

  size(): number {
    return this.techniques.length;
  }
}

export interface AttackMatch {
  readonly id: string;
  readonly name: string;
  readonly tactic: string;
  readonly description: string;
  /** 0..1 relative confidence, descending. */
  readonly score: number;
  /** Human-readable reasons the technique matched. */
  readonly reasons: readonly string[];
}

export interface AttackMapInput {
  readonly cwe?: string;
  readonly description?: string;
  readonly limit?: number;
}

export interface AttackMapResult {
  readonly query: {
    readonly cwe: string | null;
    readonly description_terms: readonly string[];
  };
  readonly total_matched: number;
  readonly matches: readonly AttackMatch[];
}

const WORD_RE = /[a-z0-9][a-z0-9+-]*/gi;

/** Tokenize free text into lower-cased terms, dropping very short noise. */
function tokenize(text: string): readonly string[] {
  const tokens: string[] = [];
  let m: RegExpExecArray | null;
  const re = new RegExp(WORD_RE.source, WORD_RE.flags);
  while ((m = re.exec(text)) !== null) {
    const t = m[0].toLowerCase();
    if (t.length >= 3) tokens.push(t);
  }
  return tokens;
}

/**
 * Map a CWE and/or description to ranked ATT&CK techniques.
 *
 * Scoring: a CWE match against a technique's `related_cwes` is the
 * strongest signal (weight 3). Each technique keyword that appears as a
 * phrase in the description adds weight 2; a single overlapping token
 * adds weight 1 (capped). Scores are normalized to 0..1 against the
 * top-ranked match so the ranking is stable and interpretable.
 */
export function mapToAttack(catalog: AttackCatalog, input: AttackMapInput): AttackMapResult {
  const cweNorm = input.cwe !== undefined ? normalizeCweId(input.cwe) : null;
  const description = input.description ?? "";
  const descLower = description.toLowerCase();
  const descTokens = new Set(tokenize(description));
  const limit = input.limit ?? 10;

  interface Raw {
    readonly technique: AttackTechnique;
    score: number;
    readonly reasons: string[];
  }
  const raw: Raw[] = [];

  for (const technique of catalog.all()) {
    let score = 0;
    const reasons: string[] = [];

    if (cweNorm !== null) {
      const related = technique.related_cwes.map((c) => c.toUpperCase());
      if (related.includes(cweNorm.toUpperCase())) {
        score += 3;
        reasons.push(`${cweNorm} is listed among the technique's related weaknesses`);
      }
    }

    if (description !== "") {
      let keywordHits = 0;
      const tokenHits = new Set<string>();
      for (const keyword of technique.keywords) {
        const kw = keyword.toLowerCase();
        if (kw.includes(" ")) {
          if (descLower.includes(kw)) {
            keywordHits++;
            reasons.push(`description mentions \`${keyword}\``);
          }
        } else if (descTokens.has(kw)) {
          tokenHits.add(kw);
        }
      }
      score += keywordHits * 2;
      // Cap single-token overlap so a long description cannot dominate.
      const tokenScore = Math.min(tokenHits.size, 3);
      if (tokenScore > 0) {
        score += tokenScore;
        reasons.push(
          `description shares ${String(tokenHits.size)} keyword term(s): ${[...tokenHits].join(", ")}`,
        );
      }
    }

    if (score > 0) {
      raw.push({ technique, score, reasons });
    }
  }

  raw.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.technique.id.localeCompare(b.technique.id);
  });

  const top = raw[0]?.score ?? 1;
  const matches: AttackMatch[] = raw.slice(0, Math.max(1, limit)).map((r) => ({
    id: r.technique.id,
    name: r.technique.name,
    tactic: r.technique.tactic,
    description: r.technique.description,
    score: Math.round((r.score / top) * 100) / 100,
    reasons: r.reasons,
  }));

  return {
    query: {
      cwe: cweNorm,
      description_terms: [...descTokens].slice(0, 40),
    },
    total_matched: raw.length,
    matches,
  };
}
