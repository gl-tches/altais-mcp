// Regular-expression denial-of-service (ReDoS) patterns.
//
// Flags regex literals and constructed regexes whose pattern text has a
// catastrophic-backtracking shape, plus regexes built from untrusted input.
//
// CWE-1333: Inefficient Regular Expression Complexity.
// CWE-400: Uncontrolled Resource Consumption.

import type { Pattern, PatternMatch } from "./types.js";

const REFS_REDOS = [
  "https://cwe.mitre.org/data/definitions/1333.html",
  "https://cwe.mitre.org/data/definitions/400.html",
  "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
];

/**
 * Returns true if `pattern` (the inner text of a regex) contains a
 * catastrophic-backtracking shape: a quantified group whose body is itself
 * quantified, or an alternation of overlapping branches under a quantifier.
 */
function hasCatastrophicShape(pattern: string): boolean {
  // Nested quantifier: a quantified group containing a quantifier, e.g.
  // (a+)+, (.*)*, (\d+)+, ([\s\S]*)*, (a+)*, (\w*)+
  const nestedQuantifier = /\([^()]*[+*][^()]*\)\s*[+*]/;
  if (nestedQuantifier.test(pattern)) return true;
  // Overlapping alternation under a quantifier, e.g. (a|a)*, (.|\s)*, (\d|\d)+
  const alternationQuantified = /\([^()]*\|[^()]*\)\s*[+*]/;
  if (alternationQuantified.test(pattern)) return true;
  return false;
}

export const REDOS_PATTERNS: readonly Pattern[] = [
  {
    id: "redos-nested-quantifier-js",
    category: "redos",
    title: "Regex literal with catastrophic backtracking",
    description:
      "A JavaScript regex literal contains a nested quantifier (e.g. `(a+)+`) or an overlapping quantified alternation (e.g. `(.|\\s)*`). Such patterns backtrack exponentially on certain inputs, freezing the event loop.",
    severity: "high",
    cwe: ["CWE-1333", "CWE-400"],
    remediation:
      "Rewrite the regex to remove nested/overlapping quantifiers. Use atomic groups, possessive quantifiers, or a linear-time engine (e.g. RE2). Cap input length before matching.",
    references: REFS_REDOS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        // Regex literals are kept by the stripper; scan the raw source so
        // string content is intact. Match /.../flags not preceded by an
        // identifier or a closing bracket (crude division guard).
        const re = /(^|[\s(,=:!&|?{[;])\/((?:\\.|\[(?:\\.|[^\]])*\]|[^/\n\\])+)\/[a-z]*/g;
        const out: PatternMatch[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(ctx.source)) !== null) {
          const body = m[2];
          if (body === undefined) continue;
          if (!hasCatastrophicShape(body)) continue;
          const idx = m.index + (m[1] === undefined ? 0 : m[1].length);
          const before = ctx.source.slice(0, idx);
          const line = before.split("\n").length;
          const lastNl = before.lastIndexOf("\n");
          out.push({
            line_start: line,
            column: idx - lastNl,
            evidence: `/${body}/`.slice(0, 120),
          });
        }
        return out;
      },
    },
  },
  {
    id: "redos-new-regexp-nested-quantifier-js",
    category: "redos",
    title: "new RegExp() with a catastrophic-backtracking pattern",
    description:
      'A `new RegExp("...")` is constructed from a string literal that contains a nested quantifier or overlapping quantified alternation. The resulting regex is vulnerable to exponential backtracking.',
    severity: "high",
    cwe: ["CWE-1333", "CWE-400"],
    remediation:
      "Rewrite the pattern to eliminate nested/overlapping quantifiers. Validate and length-cap input before matching, or move to a linear-time regex engine.",
    references: REFS_REDOS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        const re = /\bnew\s+RegExp\s*\(\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
        const out: PatternMatch[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(ctx.source)) !== null) {
          const body = m[2];
          if (body === undefined) continue;
          if (!hasCatastrophicShape(body)) continue;
          const before = ctx.source.slice(0, m.index);
          const line = before.split("\n").length;
          const lastNl = before.lastIndexOf("\n");
          out.push({
            line_start: line,
            column: m.index - lastNl,
            evidence: m[0].trim().replace(/\s+/g, " ").slice(0, 120),
          });
        }
        return out;
      },
    },
  },
  {
    id: "redos-regex-from-input-js",
    category: "redos",
    title: "new RegExp() built from a non-literal (regex injection)",
    description:
      "`new RegExp(...)` is constructed from a variable or request input. An attacker who controls the pattern can craft a catastrophic-backtracking regex (regex-injection ReDoS).",
    severity: "high",
    cwe: ["CWE-1333", "CWE-400"],
    remediation:
      "Do not build regexes from untrusted input. If a search term is needed, escape regex metacharacters and length-cap the input, or use plain string matching.",
    references: REFS_REDOS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bnew\s+RegExp\s*\(\s*(?!["'`/])[A-Za-z_$]/,
    },
  },
  {
    id: "redos-re-compile-nested-quantifier-py",
    category: "redos",
    title: "re.compile() with a catastrophic-backtracking pattern (Python)",
    description:
      '`re.compile("...")` is given a string literal containing a nested quantifier or overlapping quantified alternation. Python\'s `re` engine backtracks and can hang on adversarial input.',
    severity: "high",
    cwe: ["CWE-1333", "CWE-400"],
    remediation:
      "Rewrite the pattern to remove nested/overlapping quantifiers. Use the `regex` module's atomic groups, or `re2`, and length-cap input before matching.",
    references: REFS_REDOS,
    languages: ["python"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        const re = /\bre\.compile\s*\(\s*[rRbB]?(["'])((?:\\.|(?!\1)[^\\])*)\1/g;
        const out: PatternMatch[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(ctx.source)) !== null) {
          const body = m[2];
          if (body === undefined) continue;
          if (!hasCatastrophicShape(body)) continue;
          const before = ctx.source.slice(0, m.index);
          const line = before.split("\n").length;
          const lastNl = before.lastIndexOf("\n");
          out.push({
            line_start: line,
            column: m.index - lastNl,
            evidence: m[0].trim().replace(/\s+/g, " ").slice(0, 120),
          });
        }
        return out;
      },
    },
  },
  {
    id: "redos-re-compile-from-input-py",
    category: "redos",
    title: "re.compile() built from a non-literal (Python)",
    description:
      "`re.compile(...)` receives a variable rather than a string literal. If the pattern derives from user input, an attacker can supply a catastrophic-backtracking regex.",
    severity: "high",
    cwe: ["CWE-1333", "CWE-400"],
    remediation:
      "Avoid compiling regexes from untrusted input. Escape with `re.escape()` and length-cap the input, or use literal string operations instead.",
    references: REFS_REDOS,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bre\.compile\s*\(\s*(?![rRbB]?["'])[A-Za-z_]/,
    },
  },
];
