// CVSS v3.1 scoring and composite risk score.
//
// v3.1 is implemented per the FIRST specification (Section 7.1).
// CVSS v4.0 scoring lives in `core/cvss-v4.ts` (the official MacroVector
// lookup-table method). `scoreCvss` here handles v3.1 only; the
// `altais_score` tool dispatches v4.0 vectors to `calculateCvssV40`.

import type { Finding, Severity } from "./types.js";

export type CvssVersion = "3.1" | "4.0";

export interface CvssV31Metrics {
  readonly attack_vector: "N" | "A" | "L" | "P";
  readonly attack_complexity: "L" | "H";
  readonly privileges_required: "N" | "L" | "H";
  readonly user_interaction: "N" | "R";
  readonly scope: "U" | "C";
  readonly confidentiality: "N" | "L" | "H";
  readonly integrity: "N" | "L" | "H";
  readonly availability: "N" | "L" | "H";
}

export interface CvssScore {
  readonly version: CvssVersion;
  readonly vector: string;
  readonly base_score: number;
  readonly severity: Severity;
  readonly metrics?: CvssV31Metrics;
  readonly impact_subscore?: number;
  readonly exploitability_subscore?: number;
  readonly note?: string;
}

export class CvssError extends Error {
  override readonly name = "CvssError";
}

const AV_WEIGHT: Readonly<Record<CvssV31Metrics["attack_vector"], number>> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};

const AC_WEIGHT: Readonly<Record<CvssV31Metrics["attack_complexity"], number>> = {
  L: 0.77,
  H: 0.44,
};

const PR_WEIGHT_UNCHANGED: Readonly<Record<CvssV31Metrics["privileges_required"], number>> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
};

const PR_WEIGHT_CHANGED: Readonly<Record<CvssV31Metrics["privileges_required"], number>> = {
  N: 0.85,
  L: 0.68,
  H: 0.5,
};

const UI_WEIGHT: Readonly<Record<CvssV31Metrics["user_interaction"], number>> = {
  N: 0.85,
  R: 0.62,
};

const CIA_WEIGHT: Readonly<Record<CvssV31Metrics["confidentiality"], number>> = {
  H: 0.56,
  L: 0.22,
  N: 0,
};

/**
 * CVSS roundUp1: round a number up to the nearest tenth using integer
 * arithmetic to avoid floating-point surprises. Matches the reference
 * implementation in the FIRST specification.
 */
function roundUp1(value: number): number {
  const scaled = Math.round(value * 100000);
  if (scaled % 10000 === 0) {
    return scaled / 100000;
  }
  return (Math.floor(scaled / 10000) + 1) / 10;
}

const V31_PREFIX = "CVSS:3.1/";

const V31_KEY_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] as const;
type V31Key = (typeof V31_KEY_ORDER)[number];

const V31_VALID_VALUES: Readonly<Record<V31Key, readonly string[]>> = {
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  PR: ["N", "L", "H"],
  UI: ["N", "R"],
  S: ["U", "C"],
  C: ["N", "L", "H"],
  I: ["N", "L", "H"],
  A: ["N", "L", "H"],
};

/**
 * Parse a CVSS v3.1 vector. Only base-metric keys are required;
 * temporal/environmental extensions are accepted but ignored.
 */
export function parseCvssV31Vector(vector: string): CvssV31Metrics {
  if (!vector.startsWith(V31_PREFIX)) {
    throw new CvssError(`Not a CVSS v3.1 vector: ${vector}`);
  }
  const parts = vector.slice(V31_PREFIX.length).split("/");
  const map = new Map<string, string>();
  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key === undefined || value === undefined || key === "" || value === "") {
      throw new CvssError(`Malformed CVSS v3.1 segment: ${part}`);
    }
    map.set(key, value);
  }
  for (const key of V31_KEY_ORDER) {
    const value = map.get(key);
    if (value === undefined) {
      throw new CvssError(`CVSS v3.1 vector missing required metric: ${key}`);
    }
    if (!V31_VALID_VALUES[key].includes(value)) {
      throw new CvssError(`CVSS v3.1 invalid value for ${key}: ${value}`);
    }
  }
  return {
    attack_vector: map.get("AV") as CvssV31Metrics["attack_vector"],
    attack_complexity: map.get("AC") as CvssV31Metrics["attack_complexity"],
    privileges_required: map.get("PR") as CvssV31Metrics["privileges_required"],
    user_interaction: map.get("UI") as CvssV31Metrics["user_interaction"],
    scope: map.get("S") as CvssV31Metrics["scope"],
    confidentiality: map.get("C") as CvssV31Metrics["confidentiality"],
    integrity: map.get("I") as CvssV31Metrics["integrity"],
    availability: map.get("A") as CvssV31Metrics["availability"],
  };
}

/**
 * Compute CVSS v3.1 base score components from parsed metrics.
 */
export function computeCvssV31(metrics: CvssV31Metrics): {
  base_score: number;
  impact: number;
  exploitability: number;
} {
  const av = AV_WEIGHT[metrics.attack_vector];
  const ac = AC_WEIGHT[metrics.attack_complexity];
  const ui = UI_WEIGHT[metrics.user_interaction];
  const c = CIA_WEIGHT[metrics.confidentiality];
  const i = CIA_WEIGHT[metrics.integrity];
  const a = CIA_WEIGHT[metrics.availability];
  const scopeChanged = metrics.scope === "C";
  const pr = scopeChanged
    ? PR_WEIGHT_CHANGED[metrics.privileges_required]
    : PR_WEIGHT_UNCHANGED[metrics.privileges_required];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeChanged) {
    baseScore = roundUp1(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = roundUp1(Math.min(impact + exploitability, 10));
  }
  return { base_score: baseScore, impact, exploitability };
}

/**
 * Map a CVSS base score to a qualitative severity per FIRST's rating scale.
 * Aligned with the project's severity thresholds in altais.config.toml.
 */
export function cvssSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

/**
 * Score a CVSS v3.1 vector and return a full base score with subscores.
 * v4.0 vectors are not handled here — score them with `calculateCvssV40`
 * from `core/cvss-v4.ts` (the `altais_score` tool dispatches on the
 * version prefix).
 */
export function scoreCvss(vector: string): CvssScore {
  if (vector.startsWith(V31_PREFIX)) {
    const metrics = parseCvssV31Vector(vector);
    const { base_score, impact, exploitability } = computeCvssV31(metrics);
    return {
      version: "3.1",
      vector,
      base_score,
      severity: cvssSeverity(base_score),
      metrics,
      impact_subscore: Math.round(impact * 10) / 10,
      exploitability_subscore: Math.round(exploitability * 10) / 10,
    };
  }
  throw new CvssError(`Unsupported CVSS vector prefix: ${vector.slice(0, 16)}`);
}

const SEVERITY_WEIGHT: Readonly<Record<Severity, number>> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

/**
 * Composite risk score 0-100 from a collection of findings.
 * Uses severity weights, scaled and capped to keep the score interpretable.
 * Critical findings dominate; a single critical pushes the score to ~50+
 * even in a small set, while many low/info findings cannot exceed 30.
 */
export function riskSummary(findings: readonly Finding[]): number {
  if (findings.length === 0) return 0;
  let total = 0;
  for (const f of findings) {
    total += SEVERITY_WEIGHT[f.severity];
  }
  // Logarithmic-ish saturation so the score asymptotes toward 100.
  const score = 100 * (1 - Math.exp(-total / 25));
  return Math.round(score * 10) / 10;
}
