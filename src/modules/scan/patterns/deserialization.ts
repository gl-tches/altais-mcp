// Insecure deserialization patterns.
//
// Flags deserialization of untrusted data with formats and APIs that can
// instantiate arbitrary types or execute code during decoding.
//
// CWE-502: Deserialization of Untrusted Data.

import type { Pattern, PatternMatch } from "./types.js";

const REFS_DESER = [
  "https://cwe.mitre.org/data/definitions/502.html",
  "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
];

export const DESERIALIZATION_PATTERNS: readonly Pattern[] = [
  {
    id: "deserialization-pickle-py",
    category: "deserialization",
    title: "pickle.load / pickle.loads on untrusted data",
    description:
      "`pickle` reconstructs arbitrary Python objects and invokes `__reduce__`, allowing code execution while unpickling. Loading attacker-controlled pickle data is remote code execution.",
    severity: "critical",
    cwe: ["CWE-502"],
    remediation:
      "Never unpickle data from an untrusted source. Use a data-only format such as JSON. If pickle is unavoidable, sign payloads with HMAC and verify before loading.",
    references: REFS_DESER,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bpickle\.(?:load|loads)\s*\(/,
    },
  },
  {
    id: "deserialization-yaml-unsafe-load-py",
    category: "deserialization",
    title: "yaml.load() without SafeLoader",
    description:
      "`yaml.load` defaults to a full loader that can construct arbitrary Python objects via tags like `!!python/object/apply`. Calling it without `SafeLoader` (or with `Loader`/`FullLoader`) on untrusted YAML enables code execution.",
    severity: "critical",
    cwe: ["CWE-502"],
    remediation:
      "Use `yaml.safe_load(...)` or pass `Loader=yaml.SafeLoader`. `FullLoader` is not sufficient for fully untrusted input.",
    references: REFS_DESER,
    languages: ["python"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        const re = /\byaml\.load\s*\(([^)]*)\)/g;
        const out: PatternMatch[] = [];
        let m: RegExpExecArray | null;
        while ((m = re.exec(ctx.stripped)) !== null) {
          const args = m[1] ?? "";
          const safe =
            /Loader\s*=\s*(?:yaml\.)?SafeLoader\b|Loader\s*=\s*(?:yaml\.)?CSafeLoader\b/.test(args);
          if (safe) continue;
          const before = ctx.stripped.slice(0, m.index);
          const line = before.split("\n").length;
          const lastNl = before.lastIndexOf("\n");
          out.push({
            line_start: line,
            column: m.index - lastNl,
            evidence: m[0].trim().replace(/\s+/g, " ").slice(0, 160),
          });
        }
        return out;
      },
    },
  },
  {
    id: "deserialization-marshal-dill-py",
    category: "deserialization",
    title: "marshal / dill / jsonpickle decoding untrusted data",
    description:
      "`marshal.loads`, `dill.loads`, and `jsonpickle.decode` can instantiate arbitrary objects or code objects from their input, with the same risk profile as `pickle`.",
    severity: "critical",
    cwe: ["CWE-502"],
    remediation:
      "Do not use these formats for untrusted input. Use JSON for data interchange. If object graphs must cross a trust boundary, validate against a strict schema after parsing.",
    references: REFS_DESER,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\b(?:marshal\.loads|dill\.loads|dill\.load|jsonpickle\.decode)\s*\(/,
    },
  },
  {
    id: "deserialization-node-serialize-js",
    category: "deserialization",
    title: "node-serialize / serialize-to-js unserialize() on untrusted data",
    description:
      "`unserialize`/`deserialize` from `node-serialize` or `serialize-to-js` evaluates function expressions embedded in the payload (the `_$$ND_FUNC$$_` gadget), so a crafted string runs arbitrary code.",
    severity: "critical",
    cwe: ["CWE-502"],
    remediation:
      "Replace these libraries with `JSON.parse`. If functions genuinely must be transported, use a allowlisted, sandboxed reviver — never an engine that revives function bodies.",
    references: REFS_DESER,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\b(?:unserialize|deserialize|funcster\.deepDeserialize)\s*\(/,
    },
  },
  {
    id: "deserialization-go-gob-decoder",
    category: "deserialization",
    title: "gob.NewDecoder().Decode() on an untrusted reader (Go)",
    description:
      "`encoding/gob` decodes Go values from a stream. Decoding from a network connection or other untrusted reader exposes the process to resource-exhaustion and type-confusion attacks; gob is intended for trusted, self-describing streams.",
    severity: "high",
    cwe: ["CWE-502"],
    remediation:
      "Use gob only between trusted endpoints. For external input prefer a schema-validated format (Protocol Buffers, JSON) and bound the input size before decoding.",
    references: REFS_DESER,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\bgob\.NewDecoder\s*\(\s*(?:conn|r|req|request|resp|response|reader|body|[A-Za-z_]\w*\.Body)\b/,
    },
  },
];
