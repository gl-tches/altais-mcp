// HTTP request smuggling patterns: ambiguous framing headers and proxies that
// forward hop-by-hop headers verbatim to an upstream.
//
// CWE-444 (Inconsistent Interpretation of HTTP Requests). Smuggling arises when
// a front-end and back-end disagree on where a request ends — typically because
// both Content-Length and Transfer-Encoding are present, or hop-by-hop headers
// leak across a proxy boundary.

import type { Pattern } from "./types.js";

const REFS_SMUGGLING = [
  "https://cwe.mitre.org/data/definitions/444.html",
  "https://portswigger.net/web-security/request-smuggling",
];

export const REQUEST_SMUGGLING_PATTERNS: readonly Pattern[] = [
  {
    id: "request-smuggling-manual-transfer-encoding-js",
    category: "request-smuggling",
    title: "Application code manually sets the Transfer-Encoding header",
    description:
      "Application code sets a `Transfer-Encoding` header explicitly. This header governs message framing and must be controlled by the HTTP stack; setting it by hand creates parser disagreements that enable request smuggling.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Remove the manual `Transfer-Encoding` header. Let the HTTP library manage chunked encoding. If you need streaming, use the library's streaming API instead of setting the header yourself.",
    references: REFS_SMUGGLING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(?:setHeader|set|header)\s*\(\s*["']transfer-encoding["']|["']transfer-encoding["']\s*:/i,
    },
  },
  {
    id: "request-smuggling-manual-transfer-encoding-py",
    category: "request-smuggling",
    title: "Application code manually sets the Transfer-Encoding header (Python)",
    description:
      "Python application code assigns a `Transfer-Encoding` header. Hand-setting this framing header desynchronizes front-end and back-end HTTP parsers.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Do not set `Transfer-Encoding` manually. Let WSGI/ASGI servers and HTTP clients negotiate chunked encoding.",
    references: REFS_SMUGGLING,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bheaders\s*\[\s*["']transfer-encoding["']\s*\]\s*=|["']transfer-encoding["']\s*:/i,
    },
  },
  {
    id: "request-smuggling-manual-transfer-encoding-go",
    category: "request-smuggling",
    title: "Application code manually sets the Transfer-Encoding header (Go)",
    description:
      "Go code calls `Header().Set` / `Header().Add` for `Transfer-Encoding`. Go's `net/http` already manages framing; an explicit value produces ambiguous framing exploitable for smuggling.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Remove the manual header. Set `Request.TransferEncoding` or rely on `net/http` defaults rather than writing the header directly.",
    references: REFS_SMUGGLING,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\.Header\(\)\.(?:Set|Add)\s*\(\s*"Transfer-Encoding"/,
    },
  },
  {
    id: "request-smuggling-conflicting-framing-headers-js",
    category: "request-smuggling",
    title: "Both Content-Length and Transfer-Encoding set on the same message",
    description:
      "A message carries both a `Content-Length` and a `Transfer-Encoding` header. RFC 9112 requires `Transfer-Encoding` to win, but real proxies disagree — this is the classic CL.TE / TE.CL request smuggling primitive.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Send exactly one framing header. Drop `Content-Length` when using chunked encoding and let the HTTP stack pick the framing.",
    references: REFS_SMUGGLING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /["']content-length["']\s*:[^,}]*,[\s\S]{0,160}?["']transfer-encoding["']\s*:|["']transfer-encoding["']\s*:[^,}]*,[\s\S]{0,160}?["']content-length["']\s*:/i,
    },
  },
  {
    id: "request-smuggling-forward-raw-headers-js",
    category: "request-smuggling",
    title: "Proxy forwards raw inbound headers to an upstream request",
    description:
      "A proxy or forwarder passes the entire inbound `req.headers` object as the headers of an upstream request. Hop-by-hop headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Upgrade`) must be stripped at each hop; forwarding them verbatim enables smuggling and connection-state confusion.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Build the upstream header set explicitly from an allowlist. Strip hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization`) before forwarding.",
    references: REFS_SMUGGLING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bheaders\s*:\s*(?:\{\s*\.\.\.\s*req\.headers\b|req\.headers\s*[,}])/,
    },
  },
  {
    id: "request-smuggling-forward-raw-headers-py",
    category: "request-smuggling",
    title: "Proxy forwards raw inbound headers to an upstream request (Python)",
    description:
      "A Python proxy passes inbound `request.headers` straight through as the headers of an outbound `requests`/`httpx` call. Hop-by-hop headers should never cross a proxy boundary unmodified.",
    severity: "high",
    cwe: ["CWE-444"],
    remediation:
      "Copy only an allowlisted set of end-to-end headers to the upstream call. Strip `Connection`, `Transfer-Encoding`, `Keep-Alive`, `TE`, `Trailer`, and `Upgrade`.",
    references: REFS_SMUGGLING,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:requests|httpx|session)\.(?:get|post|put|delete|patch|head|request)\s*\([^)]*\bheaders\s*=\s*(?:dict\s*\(\s*)?request\.headers\b/,
    },
  },
  {
    id: "request-smuggling-manual-content-length-forwarded-js",
    category: "request-smuggling",
    title: "Manual Content-Length set on a forwarded/proxied request",
    description:
      "A `Content-Length` header is set by hand on an outbound or proxied request. A miscalculated or stale length desynchronizes the upstream parser from the actual body, a core request-smuggling primitive.",
    severity: "medium",
    cwe: ["CWE-444"],
    remediation:
      "Let the HTTP client compute `Content-Length` from the body it sends. Do not copy the inbound request's `Content-Length` onto a re-serialized body.",
    references: REFS_SMUGGLING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\.(?:setHeader|set|header)\s*\(\s*["']content-length["']/i,
    },
  },
];
