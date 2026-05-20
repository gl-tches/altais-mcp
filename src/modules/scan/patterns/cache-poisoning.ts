// Web cache poisoning patterns: cacheable responses built from unkeyed inputs.
//
// CWE-525 (cacheable sensitive information) and CWE-444 are the closest CWEs.
// Cache poisoning happens when a response reflects an input that the cache does
// not include in its key (an "unkeyed" header) and the response is then cached
// and served to other users.

import type { Pattern, PatternMatch } from "./types.js";

const REFS_CACHE = [
  "https://cwe.mitre.org/data/definitions/525.html",
  "https://portswigger.net/web-security/web-cache-poisoning",
];
const REFS_CACHE_VARY = [
  "https://cwe.mitre.org/data/definitions/444.html",
  "https://portswigger.net/web-security/web-cache-poisoning",
];

export const CACHE_POISONING_PATTERNS: readonly Pattern[] = [
  {
    id: "cache-poisoning-reflect-unkeyed-header-js",
    category: "cache-poisoning",
    title: "Response reflects an unkeyed request header",
    description:
      "The response is built from an unkeyed request header such as `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-For`, `X-Host`, or `X-Original-URL`. Because caches do not key on these headers, an attacker's value can be cached and served to every subsequent visitor.",
    severity: "high",
    cwe: ["CWE-525"],
    remediation:
      "Do not reflect unkeyed headers into responses. If you must use a forwarded header, add it to the cache key via `Vary`, or disable caching for that response.",
    references: REFS_CACHE,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\breq\.(?:headers\s*\[\s*["']|get\s*\(\s*["']|header\s*\(\s*["'])(?:x-forwarded-host|x-forwarded-scheme|x-forwarded-proto|x-forwarded-for|x-host|x-original-url|x-rewrite-url|x-forwarded-server)["']/i,
    },
  },
  {
    id: "cache-poisoning-reflect-unkeyed-header-py",
    category: "cache-poisoning",
    title: "Response reflects an unkeyed request header (Python)",
    description:
      "A Python handler reads an unkeyed forwarding header (`X-Forwarded-Host`, `X-Forwarded-For`, `X-Original-URL`, etc.) from `request.headers`. Reflecting it into a cacheable response enables web cache poisoning.",
    severity: "high",
    cwe: ["CWE-525"],
    remediation:
      "Avoid reflecting forwarding headers. Where unavoidable, add them to the response `Vary` header or mark the response uncacheable.",
    references: REFS_CACHE,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\brequest\.headers\s*(?:\.get\s*\(\s*["']|\[\s*["'])(?:x-forwarded-host|x-forwarded-scheme|x-forwarded-proto|x-forwarded-for|x-host|x-original-url|x-rewrite-url)["']/i,
    },
  },
  {
    id: "cache-poisoning-public-cache-on-request-data-js",
    category: "cache-poisoning",
    title: "Cache-Control: public set on a response built from request input",
    description:
      "A response sets `Cache-Control: public` (or an `s-maxage` directive) while also incorporating request-specific input. A shared cache will store this user-specific response and serve it to other clients.",
    severity: "high",
    cwe: ["CWE-525"],
    remediation:
      "Mark responses that depend on request input as `Cache-Control: private, no-store`. Only use `public` caching for responses derived entirely from the URL path.",
    references: REFS_CACHE,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bres\.(?:set|setHeader|header)\s*\(\s*["']cache-control["']\s*,\s*["'][^"']*(?:public|s-maxage)[^"']*["'][\s\S]{0,200}?\breq\.(?:body|query|params|headers|cookies)\b/i,
    },
  },
  {
    id: "cache-poisoning-public-cache-on-request-data-py",
    category: "cache-poisoning",
    title: "Cache-Control: public set on a response built from request input (Python)",
    description:
      "A Python response sets `Cache-Control: public` / `s-maxage` near code that reads request-specific data. A shared cache will retain the user-specific response.",
    severity: "high",
    cwe: ["CWE-525"],
    remediation:
      "Use `Cache-Control: private, no-store` for responses that depend on request input. Reserve public caching for fully static content.",
    references: REFS_CACHE,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /["']cache-control["']\s*\]\s*=\s*["'][^"']*(?:public|s-maxage)[^"']*["'][\s\S]{0,200}?\brequest\.(?:args|form|json|data|headers|cookies)\b/i,
    },
  },
  {
    id: "cache-poisoning-missing-vary-on-header-dependence-js",
    category: "cache-poisoning",
    title: "Cacheable response varies on a request header but sets no Vary",
    description:
      "A response is made cacheable (`Cache-Control: public`/`max-age`) yet is built from a request header, and no `Vary` header is set on the same response. Caches will key only on the URL and serve one user's header-dependent response to everyone.",
    severity: "medium",
    cwe: ["CWE-444", "CWE-525"],
    remediation:
      "Add a `Vary` header listing every request header the response depends on, or set `Cache-Control: private`. Caching keyed only on the path is unsafe for header-dependent responses.",
    references: REFS_CACHE_VARY,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "function",
      fn: (ctx): readonly PatternMatch[] => {
        const text = ctx.stripped;
        const out: PatternMatch[] = [];
        const cacheableRe =
          /\bres\.(?:set|setHeader|header)\s*\(\s*["']cache-control["']\s*,\s*["'][^"']*(?:public|max-age)[^"']*["']/gi;
        const headerUseRe = /\breq\.headers\b/;
        const varyRe = /["']vary["']/i;
        let m: RegExpExecArray | null;
        while ((m = cacheableRe.exec(text)) !== null) {
          const windowStart = Math.max(0, m.index - 400);
          const windowEnd = Math.min(text.length, m.index + 400);
          const win = text.slice(windowStart, windowEnd);
          if (!headerUseRe.test(win)) continue;
          if (varyRe.test(win)) continue;
          let line = 1;
          let lineStartIdx = 0;
          for (let i = 0; i < ctx.lineOffsets.length; i++) {
            const off = ctx.lineOffsets[i] ?? 0;
            if (off <= m.index) {
              line = i + 1;
              lineStartIdx = off;
            } else {
              break;
            }
          }
          const full = m[0];
          out.push({
            line_start: line,
            column: m.index - lineStartIdx + 1,
            evidence: full.trim().replace(/\s+/g, " "),
          });
        }
        return out;
      },
    },
  },
];
