// Prototype pollution patterns: writes that reach Object.prototype via
// `__proto__` / `constructor` / `prototype` keys, unsafe recursive merges,
// and request input spread into config objects.
//
// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes.

import type { Pattern } from "./types.js";

const REFS_PP = [
  "https://cwe.mitre.org/data/definitions/1321.html",
  "https://portswigger.net/web-security/prototype-pollution",
];

export const PROTOTYPE_POLLUTION_PATTERNS: readonly Pattern[] = [
  {
    id: "prototype-pollution-proto-assignment-js",
    category: "prototype-pollution",
    title: "Assignment to a `__proto__` / `constructor` / `prototype` key",
    description:
      "An object property whose key is `__proto__`, `constructor`, or `prototype` is being written. When the key is attacker-controlled, the write reaches `Object.prototype` and contaminates every object in the runtime.",
    severity: "high",
    cwe: ["CWE-1321"],
    remediation:
      "Reject `__proto__`, `constructor`, and `prototype` keys before assignment. Prefer `Map` for arbitrary key/value storage, or create objects with `Object.create(null)`.",
    references: REFS_PP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\[\s*["'`](?:__proto__|constructor|prototype)["'`]\s*\]\s*(?:\[|=(?!=))|\.__proto__\s*(?:\[|=(?!=))/,
    },
  },
  {
    id: "prototype-pollution-computed-proto-chain-js",
    category: "prototype-pollution",
    title: "Computed property write through `constructor.prototype`",
    description:
      "A write traverses `constructor.prototype` (e.g. `obj[key].constructor.prototype[x] = v`). This is a classic prototype-pollution gadget that mutates the shared prototype.",
    severity: "high",
    cwe: ["CWE-1321"],
    remediation:
      "Never expose `constructor` or `prototype` as reachable property names. Validate every path segment against an allowlist before traversing.",
    references: REFS_PP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\.constructor\s*\.\s*prototype\s*(?:\[|\.[A-Za-z_$])/,
    },
  },
  {
    id: "prototype-pollution-unsafe-merge-js",
    category: "prototype-pollution",
    title: "Recursive merge/extend without `__proto__` filtering",
    description:
      "A `merge`, `deepMerge`, or `extend` function copies keys from a source object into a target without skipping `__proto__` / `constructor` / `prototype`. Recursive merges of attacker JSON pollute the prototype.",
    severity: "high",
    cwe: ["CWE-1321"],
    remediation:
      "Skip dangerous keys inside the copy loop: `if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;`. Use a vetted library version with prototype-pollution fixes.",
    references: REFS_PP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "function",
      fn: (ctx) => {
        const text = ctx.stripped;
        const mergeRe =
          /\bfunction\s+(?:deepMerge|merge|extend|deepExtend|mergeDeep)\s*\(|\b(?:deepMerge|merge|extend|deepExtend|mergeDeep)\s*[:=]\s*(?:function\b|\([^)]*\)\s*=>)/g;
        const out: { line_start: number; column: number; evidence: string }[] = [];
        let m: RegExpExecArray | null;
        while ((m = mergeRe.exec(text)) !== null) {
          // Look at the next ~600 chars of the function body for an
          // unguarded key-copy and the absence of a __proto__ filter.
          const body = text.slice(m.index, m.index + 600);
          const copiesKeys =
            /\bfor\s*\(\s*(?:const|let|var)?\s*\w+\s+in\b/.test(body) ||
            /\b(?:Object\.keys|Object\.entries)\s*\(/.test(body);
          const hasGuard = /__proto__|constructor|prototype|hasOwnProperty/.test(body);
          if (copiesKeys && !hasGuard) {
            const before = text.slice(0, m.index);
            const line = before.split("\n").length;
            const lastNl = before.lastIndexOf("\n");
            out.push({
              line_start: line,
              column: m.index - lastNl,
              evidence: m[0].trim().replace(/\s+/g, " "),
            });
          }
        }
        return out;
      },
    },
  },
  {
    id: "prototype-pollution-lodash-merge-request-js",
    category: "prototype-pollution",
    title: "lodash merge / defaultsDeep / set fed request input",
    description:
      "`_.merge`, `_.mergeWith`, `_.defaultsDeep`, or `_.set` is called with `req.body`/`req.query`/`req.params`. Older lodash versions and the `set` path syntax are well-known prototype-pollution sinks.",
    severity: "high",
    cwe: ["CWE-1321"],
    remediation:
      "Upgrade lodash to a patched version and validate request input against a schema before merging. Avoid `_.set` with user-supplied paths entirely.",
    references: REFS_PP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:_\.|lodash\.)?(?:merge|mergeWith|defaultsDeep|set|setWith)\s*\([^;{]*\breq\.(?:body|query|params)\b/,
    },
  },
  {
    id: "prototype-pollution-request-spread-js",
    category: "prototype-pollution",
    title: "Request body spread / Object.assign into a config object",
    description:
      "`Object.assign(target, req.body)` or `{ ...req.body }` copies attacker-controlled keys into a server-side object. If the target later flows into a merge or path write, this enables prototype pollution.",
    severity: "medium",
    cwe: ["CWE-1321"],
    remediation:
      "Pick known fields explicitly instead of spreading request input. Validate the body with Zod/Joi and copy only the validated result.",
    references: REFS_PP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bObject\.assign\s*\([^;)]*,\s*req\.(?:body|query|params)\b|\{\s*\.\.\.\s*req\.(?:body|query|params)\b/,
    },
  },
];
