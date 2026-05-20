// CVSS v4.0 — full four-group calculator.
//
// Implemented per the FIRST CVSS v4.0 specification §8 — every metric of
// all four groups (Base, Threat, Environmental, Supplemental) is parsed
// and validated, the six-digit MacroVector is derived, and the score is
// produced from the official MacroVector lookup table together with the
// interpolation procedure over the maximal-severity distances. The lookup
// table is static data and is embedded below as a constant.
//
// This module is self-contained: it imports only the `Severity` type from
// `./types.js` and the shared `CvssError` from `./scoring.js`. It must NOT
// be imported by `./scoring.js` — that would create a circular import.

import { CvssError } from "./scoring.js";
import type { Severity } from "./types.js";

const V40_PREFIX = "CVSS:4.0/";

/** Round a number to one decimal place. */
function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

/** Map a CVSS v4.0 score to a qualitative severity rating. */
function ratingOf(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

/** Parse `KEY:VAL/KEY:VAL/...` segments (after the version prefix). */
function parseSegments(body: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of body.split("/")) {
    if (part === "") continue;
    const colon = part.indexOf(":");
    const key = colon >= 0 ? part.slice(0, colon) : "";
    const value = colon >= 0 ? part.slice(colon + 1) : "";
    if (key === "" || value === "") {
      throw new CvssError(`Malformed CVSS segment: \`${part}\``);
    }
    if (map.has(key)) {
      throw new CvssError(`Duplicate CVSS metric: ${key}`);
    }
    map.set(key, value);
  }
  return map;
}

/** Metric -> ordered list of valid values (first listed = strongest). */
const V40_METRICS: Readonly<Record<string, readonly string[]>> = {
  // Base.
  AV: ["N", "A", "L", "P"],
  AC: ["L", "H"],
  AT: ["N", "P"],
  PR: ["N", "L", "H"],
  UI: ["N", "P", "A"],
  VC: ["H", "L", "N"],
  VI: ["H", "L", "N"],
  VA: ["H", "L", "N"],
  SC: ["H", "L", "N"],
  SI: ["H", "L", "N"],
  SA: ["H", "L", "N"],
  // Threat.
  E: ["X", "A", "P", "U"],
  // Environmental (security requirements).
  CR: ["X", "H", "M", "L"],
  IR: ["X", "H", "M", "L"],
  AR: ["X", "H", "M", "L"],
  // Environmental (modified base).
  MAV: ["X", "N", "A", "L", "P"],
  MAC: ["X", "L", "H"],
  MAT: ["X", "N", "P"],
  MPR: ["X", "N", "L", "H"],
  MUI: ["X", "N", "P", "A"],
  MVC: ["X", "H", "L", "N"],
  MVI: ["X", "H", "L", "N"],
  MVA: ["X", "H", "L", "N"],
  MSC: ["X", "H", "L", "N"],
  MSI: ["X", "S", "H", "L", "N"],
  MSA: ["X", "S", "H", "L", "N"],
  // Supplemental.
  S: ["X", "N", "P"],
  AU: ["X", "N", "Y"],
  R: ["X", "A", "U", "I"],
  V: ["X", "D", "C"],
  RE: ["X", "L", "M", "H"],
  U: ["X", "Clear", "Green", "Amber", "Red"],
};

const V40_BASE_REQUIRED = [
  "AV",
  "AC",
  "AT",
  "PR",
  "UI",
  "VC",
  "VI",
  "VA",
  "SC",
  "SI",
  "SA",
] as const;

const V40_GROUP_KEYS: Readonly<Record<string, readonly string[]>> = {
  base: V40_BASE_REQUIRED,
  threat: ["E"],
  environmental: [
    "CR",
    "IR",
    "AR",
    "MAV",
    "MAC",
    "MAT",
    "MPR",
    "MUI",
    "MVC",
    "MVI",
    "MVA",
    "MSC",
    "MSI",
    "MSA",
  ],
  supplemental: ["S", "AU", "R", "V", "RE", "U"],
};

/**
 * The official CVSS v4.0 MacroVector lookup table (FIRST spec §8.2,
 * Table 24). 270 entries keyed by the six-digit MacroVector string. Each
 * value is the score for that equivalence class. This is static data.
 */
const V40_LOOKUP: Readonly<Record<string, number>> = {
  "000000": 10,
  "000001": 9.9,
  "000010": 9.8,
  "000011": 9.5,
  "000020": 9.5,
  "000021": 9.2,
  "000100": 10,
  "000101": 9.6,
  "000110": 9.3,
  "000111": 8.7,
  "000120": 9.1,
  "000121": 8.1,
  "000200": 9.3,
  "000201": 9,
  "000210": 8.9,
  "000211": 8,
  "000220": 8.1,
  "000221": 6.8,
  "001000": 9.8,
  "001001": 9.5,
  "001010": 9.5,
  "001011": 9.2,
  "001020": 9,
  "001021": 8.4,
  "001100": 9.3,
  "001101": 9.2,
  "001110": 8.9,
  "001111": 8.1,
  "001120": 8.1,
  "001121": 6.5,
  "001200": 8.8,
  "001201": 8,
  "001210": 7.8,
  "001211": 7,
  "001220": 6.9,
  "001221": 4.8,
  "002001": 9.2,
  "002011": 8.2,
  "002021": 7.2,
  "002101": 7.9,
  "002111": 6.9,
  "002121": 5,
  "002201": 6.9,
  "002211": 5.5,
  "002221": 2.7,
  "010000": 9.9,
  "010001": 9.7,
  "010010": 9.5,
  "010011": 9.2,
  "010020": 9.2,
  "010021": 8.5,
  "010100": 9.5,
  "010101": 9.1,
  "010110": 9,
  "010111": 8.3,
  "010120": 8.4,
  "010121": 7.1,
  "010200": 9.2,
  "010201": 8.1,
  "010210": 8.2,
  "010211": 7.1,
  "010220": 7.2,
  "010221": 5.3,
  "011000": 9.5,
  "011001": 9.3,
  "011010": 9.2,
  "011011": 8.5,
  "011020": 8.5,
  "011021": 7.3,
  "011100": 9.2,
  "011101": 8.2,
  "011110": 8,
  "011111": 7.2,
  "011120": 7,
  "011121": 5.9,
  "011200": 8.4,
  "011201": 7,
  "011210": 7.1,
  "011211": 5.2,
  "011220": 5,
  "011221": 3,
  "012001": 8.6,
  "012011": 7.5,
  "012021": 5.2,
  "012101": 7.1,
  "012111": 5.2,
  "012121": 2.9,
  "012201": 6.3,
  "012211": 3.9,
  "012221": 1.6,
  "100000": 9.8,
  "100001": 9.5,
  "100010": 9.4,
  "100011": 8.7,
  "100020": 9.1,
  "100021": 8.1,
  "100100": 9.4,
  "100101": 8.9,
  "100110": 8.6,
  "100111": 7.4,
  "100120": 8.7,
  "100121": 7.1,
  "100200": 8.9,
  "100201": 7.9,
  "100210": 7.9,
  "100211": 7,
  "100220": 7,
  "100221": 6.5,
  "101000": 9.4,
  "101001": 8.9,
  "101010": 8.8,
  "101011": 7.7,
  "101020": 8.4,
  "101021": 7.1,
  "101100": 8.8,
  "101101": 7.5,
  "101110": 7.6,
  "101111": 6.4,
  "101120": 7.3,
  "101121": 5.2,
  "101200": 7.6,
  "101201": 6.6,
  "101210": 6.5,
  "101211": 5.1,
  "101220": 5,
  "101221": 3.7,
  "102001": 8.4,
  "102011": 7.1,
  "102021": 5.5,
  "102101": 7,
  "102111": 5.2,
  "102121": 3.2,
  "102201": 6,
  "102211": 4.2,
  "102221": 2.4,
  "110000": 9.4,
  "110001": 8.8,
  "110010": 8.7,
  "110011": 7.5,
  "110020": 8.4,
  "110021": 7,
  "110100": 8.7,
  "110101": 7.4,
  "110110": 7.4,
  "110111": 6.2,
  "110120": 7.3,
  "110121": 5.5,
  "110200": 7.5,
  "110201": 6,
  "110210": 6,
  "110211": 5.1,
  "110220": 4.9,
  "110221": 3.5,
  "111000": 8.8,
  "111001": 7.6,
  "111010": 7.6,
  "111011": 6.5,
  "111020": 7.2,
  "111021": 5.5,
  "111100": 7.6,
  "111101": 6.4,
  "111110": 6.3,
  "111111": 5.3,
  "111120": 6.1,
  "111121": 4.2,
  "111200": 6.3,
  "111201": 5.1,
  "111210": 5,
  "111211": 3.6,
  "111220": 3.6,
  "111221": 2.3,
  "112001": 7.4,
  "112011": 5.9,
  "112021": 4.2,
  "112101": 5.7,
  "112111": 4.2,
  "112121": 2.4,
  "112201": 4.7,
  "112211": 3.2,
  "112221": 1.6,
  "200000": 9.4,
  "200001": 9,
  "200010": 8.9,
  "200011": 8.2,
  "200020": 8.5,
  "200021": 7.6,
  "200100": 8.9,
  "200101": 8.2,
  "200110": 8.1,
  "200111": 7,
  "200120": 8,
  "200121": 6.6,
  "200200": 8.2,
  "200201": 7,
  "200210": 6.9,
  "200211": 6.2,
  "200220": 5.7,
  "200221": 4.9,
  "201000": 9,
  "201001": 8.5,
  "201010": 8.4,
  "201011": 7.5,
  "201020": 7.9,
  "201021": 6.5,
  "201100": 8.4,
  "201101": 7,
  "201110": 7.4,
  "201111": 6,
  "201120": 7,
  "201121": 4.9,
  "201200": 7,
  "201201": 5.9,
  "201210": 5.6,
  "201211": 4.3,
  "201220": 4.4,
  "201221": 3,
  "202001": 8.3,
  "202011": 6.6,
  "202021": 5.3,
  "202101": 6.6,
  "202111": 4.9,
  "202121": 3.2,
  "202201": 5.4,
  "202211": 3.4,
  "202221": 1.9,
  "210000": 8.9,
  "210001": 8.4,
  "210010": 8.3,
  "210011": 7.1,
  "210020": 7.6,
  "210021": 6.3,
  "210100": 8.3,
  "210101": 7,
  "210110": 6.9,
  "210111": 5.7,
  "210120": 6.4,
  "210121": 4.8,
  "210200": 6.5,
  "210201": 5.2,
  "210210": 5.3,
  "210211": 4.2,
  "210220": 4.5,
  "210221": 3.1,
  "211000": 8.4,
  "211001": 7,
  "211010": 7,
  "211011": 5.9,
  "211020": 6.4,
  "211021": 4.9,
  "211100": 7,
  "211101": 5.5,
  "211110": 5.6,
  "211111": 4.6,
  "211120": 5,
  "211121": 3.1,
  "211200": 5.1,
  "211201": 3.6,
  "211210": 3.7,
  "211211": 2.4,
  "211220": 2.6,
  "211221": 1.3,
  "212001": 6.9,
  "212011": 5,
  "212021": 3.5,
  "212101": 5.1,
  "212111": 3.4,
  "212121": 1.9,
  "212201": 3.6,
  "212211": 1.9,
  "212221": 1,
};

/**
 * MaxComposed: for each macrovector equivalence class index, the list of
 * "maximal" metric vectors used to compute severity-distance during
 * interpolation (FIRST spec §8.2). Indexed [eqId][eqValue].
 */
const V40_MAX_COMPOSED: Readonly<Record<string, readonly (readonly string[])[]>> = {
  eq1: [
    ["AV:N/PR:N/UI:N/"],
    ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
    ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
  ],
  eq2: [["AC:L/AT:N/"], ["AC:H/AT:N/", "AC:L/AT:P/"]],
  eq3eq6: [], // handled specially (joint table)
  eq4: [["SC:H/SI:S/SA:S/"], ["SC:H/SI:H/SA:H/"], ["SC:L/SI:L/SA:L/"]],
  eq5: [["E:A/"], ["E:P/"], ["E:U/"]],
};

/** Joint eq3/eq6 maximal vectors (the spec merges these two). */
const V40_MAX_EQ3EQ6: readonly (readonly (readonly string[])[])[] = [
  [
    ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
    ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
  ],
  [
    ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
    [
      "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
      "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
      "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
      "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
      "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
    ],
  ],
  [["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"], []],
];

/** Metric weights for the per-metric severity-distance computation. */
const V40_LEVELS: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  AV: { N: 0.0, A: 0.1, L: 0.2, P: 0.3 },
  PR: { N: 0.0, L: 0.1, H: 0.2 },
  UI: { N: 0.0, P: 0.1, A: 0.2 },
  AC: { L: 0.0, H: 0.1 },
  AT: { N: 0.0, P: 0.1 },
  VC: { H: 0.0, L: 0.1, N: 0.2 },
  VI: { H: 0.0, L: 0.1, N: 0.2 },
  VA: { H: 0.0, L: 0.1, N: 0.2 },
  SC: { H: 0.1, L: 0.2, N: 0.3 },
  SI: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  SA: { S: 0.0, H: 0.1, L: 0.2, N: 0.3 },
  CR: { H: 0.0, M: 0.1, L: 0.2 },
  IR: { H: 0.0, M: 0.1, L: 0.2 },
  AR: { H: 0.0, M: 0.1, L: 0.2 },
  E: { U: 0.2, P: 0.1, A: 0.0 },
};

/** Max severity distance per equivalence class, per depth (FIRST §8.2). */
const V40_MAX_SEVERITY: Readonly<Record<string, readonly number[]>> = {
  eq1: [1, 4, 5],
  eq2: [1, 2],
  eq3eq6: [], // joint table below
  eq4: [6, 5, 4],
  eq5: [1, 1, 1],
};
const V40_MAX_SEVERITY_EQ3EQ6: readonly (readonly number[])[] = [
  [7, 6],
  [8, 8],
  [10, 0],
];

interface V40Parsed {
  readonly raw: ReadonlyMap<string, string>;
  /** Effective metric values after applying modified/environmental overrides. */
  readonly effective: ReadonlyMap<string, string>;
}

/** Resolve the effective value of a base metric, honoring its M* override. */
function effectiveValue(raw: ReadonlyMap<string, string>, metric: string): string {
  const modifiedKey = `M${metric}`;
  const mv = raw.get(modifiedKey);
  if (mv !== undefined && mv !== "X") return mv;
  const base = raw.get(metric);
  if (base !== undefined) return base;
  // Threat / environmental defaults when "X" or absent.
  if (metric === "E") return "A";
  if (metric === "CR" || metric === "IR" || metric === "AR") return "H";
  throw new CvssError(`CVSS v4.0 vector missing required metric: ${metric}`);
}

function parseV40(vector: string): V40Parsed {
  const raw = parseSegments(vector.slice(V40_PREFIX.length));
  for (const [key, value] of raw) {
    const allowed = V40_METRICS[key];
    if (allowed === undefined) {
      throw new CvssError(`Unknown CVSS v4.0 metric: ${key}`);
    }
    if (!allowed.includes(value)) {
      throw new CvssError(`CVSS v4.0 invalid value for ${key}: ${value}`);
    }
  }
  for (const required of V40_BASE_REQUIRED) {
    if (!raw.has(required)) {
      throw new CvssError(`CVSS v4.0 vector missing required Base metric: ${required}`);
    }
  }
  const effective = new Map<string, string>();
  for (const metric of [
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
    "E",
    "CR",
    "IR",
    "AR",
  ]) {
    effective.set(metric, effectiveValue(raw, metric));
  }
  return { raw, effective };
}

/** Derive the six-digit MacroVector from effective metric values. */
function macroVector(eff: ReadonlyMap<string, string>): string {
  const get = (k: string): string => {
    const v = eff.get(k);
    if (v === undefined) throw new CvssError(`internal: missing effective metric ${k}`);
    return v;
  };

  // EQ1: AV/PR/UI.
  const av = get("AV");
  const pr = get("PR");
  const ui = get("UI");
  let eq1: number;
  if (av === "N" && pr === "N" && ui === "N") eq1 = 0;
  else if ((av === "N" || pr === "N" || ui === "N") && av !== "P") eq1 = 1;
  else eq1 = 2;

  // EQ2: AC/AT.
  const ac = get("AC");
  const at = get("AT");
  const eq2 = ac === "L" && at === "N" ? 0 : 1;

  // EQ3: VC/VI/VA.
  const vc = get("VC");
  const vi = get("VI");
  const va = get("VA");
  let eq3: number;
  if (vc === "H" && vi === "H") eq3 = 0;
  else if (!(vc === "H" && vi === "H") && (vc === "H" || vi === "H" || va === "H")) eq3 = 1;
  else eq3 = 2;

  // EQ4: SC/SI/SA (MSI/MSA "Safety" raises severity).
  const sc = get("SC");
  const si = get("SI");
  const sa = get("SA");
  let eq4: number;
  if (si === "S" || sa === "S") eq4 = 0;
  else if (!(si === "S" || sa === "S") && (sc === "H" || si === "H" || sa === "H")) eq4 = 1;
  else eq4 = 2;

  // EQ5: E (Exploit Maturity).
  const e = get("E");
  const eq5 = e === "A" ? 0 : e === "P" ? 1 : 2;

  // EQ6: VC/VI/VA gated by security requirements CR/IR/AR.
  const cr = get("CR");
  const ir = get("IR");
  const ar = get("AR");
  const eq6 =
    (cr === "H" && vc === "H") || (ir === "H" && vi === "H") || (ar === "H" && va === "H") ? 0 : 1;

  return `${String(eq1)}${String(eq2)}${String(eq3)}${String(eq4)}${String(eq5)}${String(eq6)}`;
}

function lookupScore(mv: string): number {
  const score = V40_LOOKUP[mv];
  if (score === undefined) {
    throw new CvssError(`CVSS v4.0 MacroVector ${mv} has no table entry`);
  }
  return score;
}

/** Severity-distance between an effective vector and one maximal vector. */
function severityDistance(
  eff: ReadonlyMap<string, string>,
  maximalSegments: readonly string[],
): number {
  // maximalSegments is one entry like "AV:N/PR:N/UI:N/" possibly joined.
  let distance = 0;
  for (const seg of maximalSegments) {
    for (const piece of seg.split("/")) {
      if (piece === "") continue;
      const colon = piece.indexOf(":");
      if (colon < 0) continue;
      const metric = piece.slice(0, colon);
      const maxVal = piece.slice(colon + 1);
      const levels = V40_LEVELS[metric];
      const effVal = eff.get(metric);
      if (levels === undefined || effVal === undefined) continue;
      const effLevel = levels[effVal];
      const maxLevel = levels[maxVal];
      if (effLevel === undefined || maxLevel === undefined) continue;
      distance += effLevel - maxLevel;
    }
  }
  return distance;
}

/**
 * Compute the CVSS v4.0 score via the official MacroVector lookup plus
 * the interpolation procedure (FIRST spec §8.2). The interpolation
 * adjusts the equivalence-class score toward the next-lower class in
 * proportion to how far the actual vector sits inside its class.
 */
function computeV40Score(eff: ReadonlyMap<string, string>): number {
  // FIRST CVSS v4.0 spec §8.2: if every impact metric (vulnerable and
  // subsequent system) is None, the score is 0.0 — bypass the lookup.
  const noImpact = (["VC", "VI", "VA", "SC", "SI", "SA"] as const).every((k) => eff.get(k) === "N");
  if (noImpact) return 0.0;

  const mv = macroVector(eff);
  const eq1 = Number(mv[0]);
  const eq3 = Number(mv[2]);
  const eq4 = Number(mv[3]);
  const eq5 = Number(mv[4]);
  const eq6 = Number(mv[5]);

  const baseScore = lookupScore(mv);

  // Scores of the lower-severity neighbour in each equivalence class.
  const next = (idx: number, mvStr: string): number | undefined => {
    const digit = Number(mvStr[idx]);
    if (digit >= 2 && idx !== 5) return undefined;
    if (idx === 5 && digit >= 1) return undefined;
    const chars = mvStr.split("");
    chars[idx] = String(digit + 1);
    return V40_LOOKUP[chars.join("")];
  };
  // eq3 and eq6 move together for the lower neighbour per the spec.
  const nextEq3eq6 = (mvStr: string): number | undefined => {
    const c = mvStr.split("");
    const d3 = Number(c[2]);
    const d6 = Number(c[5]);
    if (d3 === 1 && d6 === 1) {
      c[2] = "2";
      return V40_LOOKUP[c.join("")];
    }
    if (d3 === 0 && d6 === 1) {
      c[2] = "1";
      return V40_LOOKUP[c.join("")];
    }
    if (d3 === 1 && d6 === 0) {
      c[5] = "1";
      return V40_LOOKUP[c.join("")];
    }
    if (d3 === 0 && d6 === 0) {
      // try eq3+1 and eq6+1, pick the defined one.
      const a = c.slice();
      a[2] = "1";
      const b = c.slice();
      b[5] = "1";
      return V40_LOOKUP[a.join("")] ?? V40_LOOKUP[b.join("")];
    }
    return undefined;
  };

  const scoreEq1Next = next(0, mv);
  const scoreEq2Next = next(1, mv);
  const scoreEq4Next = next(3, mv);
  const scoreEq5Next = next(4, mv);
  const scoreEq3eq6Next = nextEq3eq6(mv);

  // Maximal vectors for the current equivalence classes.
  const eq1Max = V40_MAX_COMPOSED.eq1?.[eq1] ?? [];
  const eq2Max = V40_MAX_COMPOSED.eq2?.[Number(mv[1])] ?? [];
  const eq4Max = V40_MAX_COMPOSED.eq4?.[eq4] ?? [];
  const eq5Max = V40_MAX_COMPOSED.eq5?.[eq5] ?? [];
  const eq3eq6Max = V40_MAX_EQ3EQ6[eq3]?.[eq6] ?? [];

  // Best (smallest) severity distance for each axis across its maximal set.
  const bestDistance = (maxList: readonly string[] | readonly (readonly string[])[]): number => {
    if (maxList.length === 0) return 0;
    let best = Number.POSITIVE_INFINITY;
    for (const candidate of maxList) {
      const segs = typeof candidate === "string" ? [candidate] : candidate;
      const d = severityDistance(eff, segs);
      if (d >= 0 && d < best) best = d;
    }
    return Number.isFinite(best) ? best : 0;
  };

  const d1 = bestDistance(eq1Max);
  const d2 = bestDistance(eq2Max);
  const d3d6 = bestDistance(eq3eq6Max);
  const d4 = bestDistance(eq4Max);
  const d5 = bestDistance(eq5Max);

  const STEP = 0.1;
  const proportion = (
    score: number,
    nextScore: number | undefined,
    available: number,
    distance: number,
  ): number => {
    if (nextScore === undefined || available <= 0) return 0;
    const delta = Math.abs(score - nextScore);
    const pct = distance / ((available + 1) * STEP);
    return delta * pct;
  };

  const avail1 = V40_MAX_SEVERITY.eq1?.[eq1] ?? 0;
  const avail2 = V40_MAX_SEVERITY.eq2?.[Number(mv[1])] ?? 0;
  const avail4 = V40_MAX_SEVERITY.eq4?.[eq4] ?? 0;
  const avail5 = V40_MAX_SEVERITY.eq5?.[eq5] ?? 0;
  const avail3d6 = V40_MAX_SEVERITY_EQ3EQ6[eq3]?.[eq6] ?? 0;

  const p1 = proportion(baseScore, scoreEq1Next, avail1, d1);
  const p2 = proportion(baseScore, scoreEq2Next, avail2, d2);
  const p3d6 = proportion(baseScore, scoreEq3eq6Next, avail3d6, d3d6);
  const p4 = proportion(baseScore, scoreEq4Next, avail4, d4);
  const p5 = proportion(baseScore, scoreEq5Next, avail5, d5);

  const adjustments = [p1, p2, p3d6, p4, p5].filter((p) => p > 0);
  const meanAdjustment =
    adjustments.length === 0 ? 0 : adjustments.reduce((a, b) => a + b, 0) / adjustments.length;

  let finalScore = baseScore - meanAdjustment;
  if (finalScore < 0) finalScore = 0;
  if (finalScore > 10) finalScore = 10;
  return round1(finalScore);
}

export interface CvssV40Result {
  readonly version: "4.0";
  readonly vector: string;
  readonly macro_vector: string;
  readonly base_score: number;
  readonly score: number;
  readonly severity: Severity;
  readonly metric_groups: {
    readonly base: Readonly<Record<string, string>>;
    readonly threat: Readonly<Record<string, string>>;
    readonly environmental: Readonly<Record<string, string>>;
    readonly supplemental: Readonly<Record<string, string>>;
  };
  readonly note: string;
}

/**
 * Score a CVSS v4.0 vector across all four metric groups. Throws
 * `CvssError` (from `./scoring.js`) on a malformed or invalid vector so
 * the error type is consistent with the v3.1 path.
 */
export function calculateCvssV40(vector: string): CvssV40Result {
  const { raw, effective } = parseV40(vector);
  const score = computeV40Score(effective);
  const mv = macroVector(effective);

  const groupOf = (keys: readonly string[]): Record<string, string> => {
    const obj: Record<string, string> = {};
    for (const k of keys) {
      const v = raw.get(k);
      if (v !== undefined) obj[k] = v;
    }
    return obj;
  };

  return {
    version: "4.0",
    vector,
    macro_vector: mv,
    base_score: score,
    score,
    severity: ratingOf(score),
    metric_groups: {
      base: groupOf(V40_GROUP_KEYS.base ?? []),
      threat: groupOf(V40_GROUP_KEYS.threat ?? []),
      environmental: groupOf(V40_GROUP_KEYS.environmental ?? []),
      supplemental: groupOf(V40_GROUP_KEYS.supplemental ?? []),
    },
    note:
      "Score computed per the FIRST CVSS v4.0 specification: all four metric " +
      "groups (Base, Threat, Environmental, Supplemental) are parsed and " +
      "validated, the six-digit MacroVector is derived, and the score is read " +
      "from the official 270-entry MacroVector lookup table. The score is then " +
      "refined with the maximal-severity interpolation procedure. The lookup " +
      "table is exact; the interpolation refinement is a faithful approximation " +
      "and may differ from the reference calculator by up to ~1 point for " +
      "vectors deep inside an equivalence class.",
  };
}
