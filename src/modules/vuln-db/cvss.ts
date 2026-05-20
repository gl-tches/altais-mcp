// Full CVSS calculator (altais_calculate_cvss) — v3.1 and v4.0.
//
// v3.1: the Base score is computed by reusing `computeCvssV31` /
// `parseCvssV31Vector` from core/scoring.ts (FIRST CVSS v3.1 spec §7.1).
// On top of that this file adds the optional Temporal and Environmental
// metric groups (FIRST CVSS v3.1 spec §7.2 and §7.3).
//
// v4.0: implemented per the FIRST CVSS v4.0 specification §8 — every
// metric of all four groups (Base, Threat, Environmental, Supplemental)
// is parsed and validated, the MacroVector is derived, and the score is
// produced from the official MacroVector lookup table together with the
// interpolation procedure over the maximal-severity distances. The
// lookup table is static data and is embedded below as a constant.

import { calculateCvssV40, type CvssV40Result } from "../../core/cvss-v4.js";
import {
  computeCvssV31,
  CvssError,
  type CvssV31Metrics,
  parseCvssV31Vector,
} from "../../core/scoring.js";
import type { Severity } from "../../core/types.js";

// The CVSS v4.0 calculator lives in `core/cvss-v4.ts` so the core
// `altais_score` tool and the vuln-db module share one implementation.
// Re-exported here to keep vuln-db's public API (`calculateCvssV40`,
// `CvssV40Result`) stable for existing callers.
export { calculateCvssV40, type CvssV40Result };

export class CvssCalcError extends Error {
  override readonly name = "CvssCalcError";
}

const V31_PREFIX = "CVSS:3.1/";
const V40_PREFIX = "CVSS:4.0/";

/** Map a CVSS score to a qualitative rating (shared by v3.1 and v4.0). */
export function ratingOf(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

// ─── shared vector parsing ─────────────────────────────────────────────────

/** Parse `KEY:VAL/KEY:VAL/...` segments (after the version prefix). */
function parseSegments(body: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of body.split("/")) {
    if (part === "") continue;
    const colon = part.indexOf(":");
    const key = colon >= 0 ? part.slice(0, colon) : "";
    const value = colon >= 0 ? part.slice(colon + 1) : "";
    if (key === "" || value === "") {
      throw new CvssCalcError(`Malformed CVSS segment: \`${part}\``);
    }
    if (map.has(key)) {
      throw new CvssCalcError(`Duplicate CVSS metric: ${key}`);
    }
    map.set(key, value);
  }
  return map;
}

// ─── CVSS v3.1 — Temporal & Environmental ──────────────────────────────────

const V31_TEMPORAL_KEYS = ["E", "RL", "RC"] as const;
const V31_ENV_KEYS = [
  "CR",
  "IR",
  "AR",
  "MAV",
  "MAC",
  "MPR",
  "MUI",
  "MS",
  "MC",
  "MI",
  "MA",
] as const;

const V31_TEMPORAL_VALUES: Readonly<Record<string, readonly string[]>> = {
  E: ["X", "U", "P", "F", "H"],
  RL: ["X", "O", "T", "W", "U"],
  RC: ["X", "U", "R", "C"],
};

const V31_ENV_VALUES: Readonly<Record<string, readonly string[]>> = {
  CR: ["X", "L", "M", "H"],
  IR: ["X", "L", "M", "H"],
  AR: ["X", "L", "M", "H"],
  MAV: ["X", "N", "A", "L", "P"],
  MAC: ["X", "L", "H"],
  MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "R"],
  MS: ["X", "U", "C"],
  MC: ["X", "N", "L", "H"],
  MI: ["X", "N", "L", "H"],
  MA: ["X", "N", "L", "H"],
};

const E_WEIGHT: Readonly<Record<string, number>> = {
  X: 1.0,
  U: 0.91,
  P: 0.94,
  F: 0.97,
  H: 1.0,
};
const RL_WEIGHT: Readonly<Record<string, number>> = {
  X: 1.0,
  O: 0.95,
  T: 0.96,
  W: 0.97,
  U: 1.0,
};
const RC_WEIGHT: Readonly<Record<string, number>> = {
  X: 1.0,
  U: 0.92,
  R: 0.96,
  C: 1.0,
};
const CIAR_WEIGHT: Readonly<Record<string, number>> = {
  X: 1.0,
  L: 0.5,
  M: 1.0,
  H: 1.5,
};

function roundUp1(value: number): number {
  const scaled = Math.round(value * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

export interface CvssV31Result {
  readonly version: "3.1";
  readonly vector: string;
  readonly base_score: number;
  readonly base_severity: Severity;
  readonly temporal_score?: number;
  readonly environmental_score?: number;
  readonly score: number;
  readonly severity: Severity;
  readonly impact_subscore: number;
  readonly exploitability_subscore: number;
  readonly metric_groups: {
    readonly base: Readonly<Record<string, string>>;
    readonly temporal?: Readonly<Record<string, string>>;
    readonly environmental?: Readonly<Record<string, string>>;
  };
}

/** Resolve a modified env metric: `X` (not defined) falls back to base. */
function modified(env: Map<string, string>, key: string, fallback: string): string {
  const v = env.get(key);
  return v === undefined || v === "X" ? fallback : v;
}

const AV_W: Readonly<Record<string, number>> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC_W: Readonly<Record<string, number>> = { L: 0.77, H: 0.44 };
const PR_W_U: Readonly<Record<string, number>> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_W_C: Readonly<Record<string, number>> = { N: 0.85, L: 0.68, H: 0.5 };
const UI_W: Readonly<Record<string, number>> = { N: 0.85, R: 0.62 };
const CIA_W: Readonly<Record<string, number>> = { H: 0.56, L: 0.22, N: 0 };

/**
 * Compute the CVSS v3.1 Environmental score (FIRST spec §7.3). This
 * reuses the Base formula structure with modified metrics and the
 * security-requirement multipliers.
 */
function computeV31Environmental(
  base: CvssV31Metrics,
  env: Map<string, string>,
  temporalMultiplier: number,
): number {
  const mav = modified(env, "MAV", base.attack_vector);
  const mac = modified(env, "MAC", base.attack_complexity);
  const mpr = modified(env, "MPR", base.privileges_required);
  const mui = modified(env, "MUI", base.user_interaction);
  const ms = modified(env, "MS", base.scope);
  const mc = modified(env, "MC", base.confidentiality);
  const mi = modified(env, "MI", base.integrity);
  const ma = modified(env, "MA", base.availability);

  const cr = CIAR_WEIGHT[env.get("CR") ?? "X"] ?? 1.0;
  const ir = CIAR_WEIGHT[env.get("IR") ?? "X"] ?? 1.0;
  const ar = CIAR_WEIGHT[env.get("AR") ?? "X"] ?? 1.0;

  const scopeChanged = ms === "C";
  const miss = Math.min(
    1 - (1 - (CIA_W[mc] ?? 0) * cr) * (1 - (CIA_W[mi] ?? 0) * ir) * (1 - (CIA_W[ma] ?? 0) * ar),
    0.915,
  );
  const modifiedImpact = scopeChanged
    ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13)
    : 6.42 * miss;
  const pr = scopeChanged ? (PR_W_C[mpr] ?? 0) : (PR_W_U[mpr] ?? 0);
  const modifiedExploitability = 8.22 * (AV_W[mav] ?? 0) * (AC_W[mac] ?? 0) * pr * (UI_W[mui] ?? 0);

  if (modifiedImpact <= 0) return 0;
  const raw = scopeChanged
    ? roundUp1(
        roundUp1(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10)) *
          temporalMultiplier,
      )
    : roundUp1(
        roundUp1(Math.min(modifiedImpact + modifiedExploitability, 10)) * temporalMultiplier,
      );
  return raw;
}

/** Score a CVSS v3.1 vector including Temporal and Environmental groups. */
export function calculateCvssV31(vector: string): CvssV31Result {
  let metrics: CvssV31Metrics;
  try {
    metrics = parseCvssV31Vector(vector);
  } catch (err) {
    if (err instanceof CvssError) throw new CvssCalcError(err.message);
    throw err;
  }
  const { base_score, impact, exploitability } = computeCvssV31(metrics);

  const map = parseSegments(vector.slice(V31_PREFIX.length));
  const baseGroup: Record<string, string> = {};
  for (const k of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    const v = map.get(k);
    if (v !== undefined) baseGroup[k] = v;
  }

  // Temporal group.
  const temporal = new Map<string, string>();
  for (const k of V31_TEMPORAL_KEYS) {
    const v = map.get(k);
    if (v === undefined) continue;
    if (!(V31_TEMPORAL_VALUES[k] ?? []).includes(v)) {
      throw new CvssCalcError(`CVSS v3.1 invalid value for ${k}: ${v}`);
    }
    temporal.set(k, v);
  }
  let temporalScore: number | undefined;
  let temporalMultiplier = 1.0;
  if (temporal.size > 0) {
    const e = E_WEIGHT[temporal.get("E") ?? "X"] ?? 1.0;
    const rl = RL_WEIGHT[temporal.get("RL") ?? "X"] ?? 1.0;
    const rc = RC_WEIGHT[temporal.get("RC") ?? "X"] ?? 1.0;
    temporalMultiplier = e * rl * rc;
    temporalScore = roundUp1(base_score * temporalMultiplier);
  }

  // Environmental group.
  const env = new Map<string, string>();
  for (const k of V31_ENV_KEYS) {
    const v = map.get(k);
    if (v === undefined) continue;
    if (!(V31_ENV_VALUES[k] ?? []).includes(v)) {
      throw new CvssCalcError(`CVSS v3.1 invalid value for ${k}: ${v}`);
    }
    env.set(k, v);
  }
  let environmentalScore: number | undefined;
  if (env.size > 0) {
    environmentalScore = computeV31Environmental(metrics, env, temporalMultiplier);
  }

  const known = new Set<string>([
    ...["AV", "AC", "PR", "UI", "S", "C", "I", "A"],
    ...V31_TEMPORAL_KEYS,
    ...V31_ENV_KEYS,
  ]);
  for (const key of map.keys()) {
    if (!known.has(key)) {
      throw new CvssCalcError(`Unknown CVSS v3.1 metric: ${key}`);
    }
  }

  const finalScore = environmentalScore ?? temporalScore ?? base_score;
  const groups: CvssV31Result["metric_groups"] = {
    base: baseGroup,
    ...(temporal.size > 0 ? { temporal: Object.fromEntries(temporal) } : {}),
    ...(env.size > 0 ? { environmental: Object.fromEntries(env) } : {}),
  };
  return {
    version: "3.1",
    vector,
    base_score,
    base_severity: ratingOf(base_score),
    ...(temporalScore !== undefined ? { temporal_score: temporalScore } : {}),
    ...(environmentalScore !== undefined ? { environmental_score: environmentalScore } : {}),
    score: finalScore,
    severity: ratingOf(finalScore),
    impact_subscore: round1(impact),
    exploitability_subscore: round1(exploitability),
    metric_groups: groups,
  };
}

export type CvssCalcResult = CvssV31Result | CvssV40Result;

/**
 * Score a CVSS v4.0 vector. Delegates to the shared `core/cvss-v4.ts`
 * calculator and normalizes its `CvssError` to `CvssCalcError` so the
 * error type is consistent across the vuln-db module's public API.
 */
function scoreV40(vector: string): CvssV40Result {
  try {
    return calculateCvssV40(vector);
  } catch (err) {
    if (err instanceof CvssError) throw new CvssCalcError(err.message);
    throw err;
  }
}

/**
 * Dispatch a CVSS vector to the v3.1 or v4.0 calculator based on its
 * version prefix. Throws CvssCalcError on a malformed or unsupported
 * vector — callers surface this as an actionable tool error.
 */
export function calculateCvss(vector: string): CvssCalcResult {
  const trimmed = vector.trim();
  if (trimmed.startsWith(V31_PREFIX)) return calculateCvssV31(trimmed);
  if (trimmed.startsWith(V40_PREFIX)) return scoreV40(trimmed);
  throw new CvssCalcError(
    `Unsupported CVSS vector: expected a \`${V31_PREFIX}...\` or \`${V40_PREFIX}...\` ` +
      `prefix, got \`${trimmed.slice(0, 20)}\`.`,
  );
}
