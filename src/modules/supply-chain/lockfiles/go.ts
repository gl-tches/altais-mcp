// `go.sum` parser.
//
// Each line has the form:
//   <module> <version>[/go.mod] h1:<base64-hash>=
// One module gets two lines (one for the module zip, one for go.mod).
// We dedupe on (name, version).

import type { DependencyPackage, LockfileParseResult } from "../types.js";
import { makePurl } from "../types.js";

const LINE = /^(\S+)\s+(\S+?)(?:\/go\.mod)?\s+(h1:\S+)\s*$/;

export function parseGoSum(text: string): LockfileParseResult {
  const map = new Map<string, DependencyPackage>();
  for (const line of text.split(/\r?\n/)) {
    if (line.trim().length === 0 || line.trim().startsWith("//")) continue;
    const m = LINE.exec(line);
    if (!m?.[1] || !m[2] || !m[3]) continue;
    const name = m[1];
    const version = m[2];
    const integrity = m[3];
    const key = `${name}@${version}`;
    if (!map.has(key)) {
      map.set(key, {
        name,
        version,
        ecosystem: "go",
        integrity,
        purl: makePurl({ ecosystem: "go", name, version }),
      });
    }
  }
  return {
    ecosystem: "go",
    package_manager: "go",
    packages: Array.from(map.values()),
  };
}
