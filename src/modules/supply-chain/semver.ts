// Minimal semver comparator + range matcher.
//
// Handles N.N.N versions plus optional `-prerelease` and `+build`
// suffixes. Pre-releases compare lower than their release counterparts
// per SemVer 2.0. Build metadata is ignored. PEP 440 (poetry) and Go
// semver are close enough for the audit use case; non-conforming inputs
// fall back to lexicographic comparison.

export interface Parsed {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly pre: readonly (string | number)[];
}

const RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parse(version: string): Parsed | null {
  const m = RE.exec(version.trim());
  if (!m) return null;
  const pre = m[4] ? m[4].split(".").map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [];
  return {
    major: Number(m[1]),
    minor: m[2] ? Number(m[2]) : 0,
    patch: m[3] ? Number(m[3]) : 0,
    pre,
  };
}

function cmpPre(a: readonly (string | number)[], b: readonly (string | number)[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // no pre > pre
  if (b.length === 0) return -1;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ai = a[i];
    const bi = b[i];
    if (ai === undefined) return -1;
    if (bi === undefined) return 1;
    const an = typeof ai === "number";
    const bn = typeof bi === "number";
    if (an && bn) {
      if (ai !== bi) return ai < bi ? -1 : 1;
      continue;
    }
    if (an !== bn) return an ? -1 : 1; // numeric < non-numeric
    if (ai !== bi) return ai < bi ? -1 : 1;
  }
  return 0;
}

export function cmp(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return a.localeCompare(b);
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;
  return cmpPre(pa.pre, pb.pre);
}

export interface Range {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly last_affected?: string;
}

/**
 * Range check: `version` is affected if introduced <= version < fixed
 * (or <= last_affected). Missing `introduced` is treated as "0".
 */
export function inRange(version: string, range: Range): boolean {
  const introduced = range.introduced ?? "0";
  if (cmp(version, introduced) < 0) return false;
  if (range.fixed !== undefined && cmp(version, range.fixed) >= 0) return false;
  if (range.last_affected !== undefined && cmp(version, range.last_affected) > 0) return false;
  return true;
}

/**
 * Levenshtein edit distance, capped at `max` for early exit. Used by
 * the typosquat detector. `null` return means distance > max.
 */
export function levenshtein(a: string, b: string, max: number): number | null {
  if (Math.abs(a.length - b.length) > max) return null;
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    let rowMin = i;
    for (let j = 1; j <= n; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      const ins = (curr[j - 1] ?? 0) + 1;
      const del = (prev[j] ?? 0) + 1;
      const sub = (prev[j - 1] ?? 0) + cost;
      const v = Math.min(ins, del, sub);
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return null;
    [prev, curr] = [curr, prev];
  }
  const result = prev[n] ?? 0;
  return result > max ? null : result;
}
