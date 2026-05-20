// Full CWE taxonomy lookup (altais_lookup_cwe).
//
// Reads the same bundled `data/cwe-database.json` file that the core
// module's `altais_explain_cwe` uses, reusing the `CweEntry` shape and
// loading approach from `src/modules/core/cwe.ts`. This tool is richer:
// it also surfaces related CWEs via a curated parent/child relation map
// and by scanning other entries for textual cross-references.

import { CweDatabase, type CweEntry, normalizeCweId } from "../core/cwe.js";

export { CweDatabase, normalizeCweId };
export type { CweEntry };

export interface CweRelation {
  readonly id: string;
  readonly name: string;
  readonly relation: "ChildOf" | "ParentOf" | "PeerOf";
}

/**
 * Curated parent/child relations for the most commonly referenced CWEs.
 * Keyed by canonical "CWE-N" id; each value lists the canonical ids of
 * directly related weaknesses. Names are filled in from the loaded
 * database at lookup time so this map stays small and id-only.
 */
const PARENTS: Readonly<Record<string, readonly string[]>> = {
  "CWE-79": ["CWE-74", "CWE-20"],
  "CWE-89": ["CWE-943", "CWE-74"],
  "CWE-78": ["CWE-77"],
  "CWE-77": ["CWE-74"],
  "CWE-90": ["CWE-943", "CWE-74"],
  "CWE-91": ["CWE-74"],
  "CWE-94": ["CWE-913"],
  "CWE-22": ["CWE-668", "CWE-706"],
  "CWE-23": ["CWE-22"],
  "CWE-73": ["CWE-642", "CWE-610"],
  "CWE-434": ["CWE-669"],
  "CWE-502": ["CWE-913"],
  "CWE-611": ["CWE-610"],
  "CWE-918": ["CWE-610"],
  "CWE-601": ["CWE-610"],
  "CWE-125": ["CWE-119", "CWE-118"],
  "CWE-787": ["CWE-119", "CWE-118"],
  "CWE-416": ["CWE-672", "CWE-825"],
  "CWE-476": ["CWE-754", "CWE-710"],
  "CWE-190": ["CWE-682"],
  "CWE-862": ["CWE-285"],
  "CWE-863": ["CWE-285"],
  "CWE-306": ["CWE-287"],
  "CWE-287": ["CWE-284"],
  "CWE-285": ["CWE-284"],
  "CWE-269": ["CWE-284"],
  "CWE-352": ["CWE-345"],
  "CWE-384": ["CWE-664"],
  "CWE-798": ["CWE-1391", "CWE-344"],
  "CWE-321": ["CWE-798"],
  "CWE-256": ["CWE-522"],
  "CWE-532": ["CWE-200", "CWE-552"],
  "CWE-209": ["CWE-200", "CWE-755"],
  "CWE-319": ["CWE-311"],
  "CWE-311": ["CWE-693"],
  "CWE-327": ["CWE-693"],
  "CWE-326": ["CWE-693"],
  "CWE-295": ["CWE-287"],
  "CWE-297": ["CWE-295"],
  "CWE-330": ["CWE-693"],
  "CWE-338": ["CWE-330"],
  "CWE-347": ["CWE-345"],
  "CWE-400": ["CWE-664"],
  "CWE-770": ["CWE-400"],
  "CWE-1333": ["CWE-400", "CWE-407"],
  "CWE-1321": ["CWE-915", "CWE-471"],
  "CWE-915": ["CWE-913"],
  "CWE-307": ["CWE-799"],
  "CWE-521": ["CWE-287"],
  "CWE-613": ["CWE-287"],
  "CWE-639": ["CWE-863"],
  "CWE-732": ["CWE-285"],
  "CWE-276": ["CWE-732"],
};

/**
 * Invert the parent map so a parent entry can also list its children.
 * Computed once at module load.
 */
const CHILDREN: ReadonlyMap<string, readonly string[]> = (() => {
  const map = new Map<string, string[]>();
  for (const [child, parents] of Object.entries(PARENTS)) {
    for (const parent of parents) {
      const list = map.get(parent) ?? [];
      list.push(child);
      map.set(parent, list);
    }
  }
  return map;
})();

const CWE_REF_RE = /CWE-\d{1,5}/gi;

/** Extract every distinct `CWE-N` token mentioned in the given strings. */
function extractCweRefs(texts: readonly string[]): readonly string[] {
  const found = new Set<string>();
  for (const text of texts) {
    let m: RegExpExecArray | null;
    const re = new RegExp(CWE_REF_RE.source, CWE_REF_RE.flags);
    while ((m = re.exec(text)) !== null) {
      found.add(m[0].toUpperCase());
    }
  }
  return [...found];
}

export interface CweLookupSuccess {
  readonly found: true;
  readonly entry: CweEntry;
  readonly related: readonly CweRelation[];
}

export interface CweLookupFailure {
  readonly found: false;
  readonly message: string;
}

export type CweLookupResult = CweLookupSuccess | CweLookupFailure;

/**
 * Look up a CWE id and assemble its related weaknesses. Relations come
 * from two sources: the curated parent/child map above, and any other
 * `CWE-N` ids cross-referenced in this entry's own description, examples,
 * or references. Peer relations are limited to entries that actually
 * exist in the bundled database.
 */
export function lookupCwe(db: CweDatabase, id: string): CweLookupResult {
  const normalized = normalizeCweId(id);
  if (normalized === null) {
    return {
      found: false,
      message: `\`${id}\` is not a valid CWE identifier. Expected the form CWE-N (e.g. CWE-79 or 79).`,
    };
  }
  const entry = db.lookup(normalized);
  if (entry === undefined) {
    return {
      found: false,
      message:
        `${normalized} is not in the bundled CWE database. The database covers ${String(db.size())} ` +
        `commonly encountered weaknesses. Consult https://cwe.mitre.org/data/definitions/ for the ` +
        `full MITRE CWE taxonomy.`,
    };
  }

  const canonicalId = entry.id.toUpperCase();
  const seen = new Set<string>([canonicalId]);
  const related: CweRelation[] = [];

  const addRelation = (refId: string, relation: CweRelation["relation"]): void => {
    const norm = normalizeCweId(refId);
    if (norm === null) return;
    const key = norm.toUpperCase();
    if (seen.has(key)) return;
    const refEntry = db.lookup(key);
    if (refEntry === undefined) return;
    seen.add(key);
    related.push({ id: refEntry.id, name: refEntry.name, relation });
  };

  for (const parent of PARENTS[canonicalId] ?? []) addRelation(parent, "ChildOf");
  for (const child of CHILDREN.get(canonicalId) ?? []) addRelation(child, "ParentOf");
  for (const ref of extractCweRefs([entry.description, ...entry.examples, ...entry.references])) {
    addRelation(ref, "PeerOf");
  }

  return { found: true, entry, related };
}
