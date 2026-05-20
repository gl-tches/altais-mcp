// DREAD scoring.
//
// Inputs are five subjective integers (1-10). Output is the raw sum
// (5-50), the average (1-10), and a qualitative rating based on the
// average. DREAD is a relative-ranking tool — useful for prioritizing
// among threats from the same model, less useful as an absolute risk
// measure.

import type { Severity } from "../../core/types.js";

export interface DreadInput {
  readonly threat: string;
  readonly damage: number;
  readonly reproducibility: number;
  readonly exploitability: number;
  readonly affected_users: number;
  readonly discoverability: number;
  readonly justification?: string;
}

export interface DreadResult {
  readonly threat: string;
  readonly scores: {
    readonly damage: number;
    readonly reproducibility: number;
    readonly exploitability: number;
    readonly affected_users: number;
    readonly discoverability: number;
  };
  readonly total: number;
  readonly average: number;
  readonly rating: Severity;
  readonly justification: string | undefined;
}

export function ratingFromAverage(average: number): Severity {
  if (average >= 8) return "critical";
  if (average >= 6) return "high";
  if (average >= 4) return "medium";
  if (average >= 2) return "low";
  return "info";
}

export function scoreDread(input: DreadInput): DreadResult {
  const scores = {
    damage: clamp(input.damage),
    reproducibility: clamp(input.reproducibility),
    exploitability: clamp(input.exploitability),
    affected_users: clamp(input.affected_users),
    discoverability: clamp(input.discoverability),
  };
  const total =
    scores.damage +
    scores.reproducibility +
    scores.exploitability +
    scores.affected_users +
    scores.discoverability;
  const average = Math.round((total / 5) * 100) / 100;
  return {
    threat: input.threat,
    scores,
    total,
    average,
    rating: ratingFromAverage(average),
    justification: input.justification,
  };
}

function clamp(value: number): number {
  if (!Number.isFinite(value)) return 1;
  if (value < 1) return 1;
  if (value > 10) return 10;
  return Math.round(value);
}
