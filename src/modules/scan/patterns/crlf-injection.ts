// CRLF injection patterns: carriage-return/line-feed sequences reaching HTTP
// response headers (response splitting) or log files (log injection).
//
// CWE-93 (CRLF injection), CWE-113 (HTTP response splitting), CWE-117 (log
// injection / improper output neutralization for logs).

import type { Pattern } from "./types.js";

const REFS_RESPONSE_SPLITTING = [
  "https://cwe.mitre.org/data/definitions/113.html",
  "https://cwe.mitre.org/data/definitions/93.html",
  "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
];
const REFS_LOG_INJECTION = [
  "https://cwe.mitre.org/data/definitions/117.html",
  "https://owasp.org/www-community/attacks/Log_Injection",
];

export const CRLF_INJECTION_PATTERNS: readonly Pattern[] = [
  {
    id: "crlf-header-from-request-js",
    category: "crlf-injection",
    title: "Response header value built from request input",
    description:
      "A response header is set with `res.setHeader` / `res.writeHead` using a value taken from request input. Unsanitized `\\r\\n` in that value can inject extra headers or split the response (HTTP response splitting).",
    severity: "high",
    cwe: ["CWE-93", "CWE-113"],
    remediation:
      "Strip CR and LF from any value placed into a header. Prefer framework APIs that reject control characters, and validate header values against a strict allowlist.",
    references: REFS_RESPONSE_SPLITTING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bres\.(?:setHeader|writeHead|append)\s*\([^)]*\breq\.(?:body|query|params|headers|cookies)\b/,
    },
  },
  {
    id: "crlf-redirect-from-request-js",
    category: "crlf-injection",
    title: "Location/redirect header built from request input",
    description:
      "A `Location` header or `res.redirect` target is constructed from request input. CRLF characters in that input can inject headers; the same sink is also an open-redirect risk.",
    severity: "high",
    cwe: ["CWE-93", "CWE-113"],
    remediation:
      "Strip CR/LF from redirect targets and validate them against an allowlist of permitted paths or hosts before redirecting.",
    references: REFS_RESPONSE_SPLITTING,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bres\.(?:redirect|location)\s*\([^)]*\breq\.(?:body|query|params|headers)\b|\.(?:setHeader|set)\s*\(\s*["']location["']\s*,[^)]*\breq\./i,
    },
  },
  {
    id: "crlf-header-from-request-py",
    category: "crlf-injection",
    title: "Response header assigned from request input (Python)",
    description:
      "A response header dictionary entry is assigned from `request` input. CR/LF characters in the value can split the HTTP response or inject additional headers.",
    severity: "high",
    cwe: ["CWE-93", "CWE-113"],
    remediation:
      "Remove `\\r` and `\\n` from header values. Modern WSGI servers reject control characters, but do not rely on that — validate explicitly.",
    references: REFS_RESPONSE_SPLITTING,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:response|resp)\.headers\s*\[\s*["'][^"']+["']\s*\]\s*=\s*[^=\n]*\brequest\.|\bresponse\.headers\.(?:add|__setitem__)\s*\([^)]*\brequest\./,
    },
  },
  {
    id: "crlf-header-from-request-go",
    category: "crlf-injection",
    title: "Response header value built from request input (Go)",
    description:
      "`w.Header().Set` / `Add` receives a value derived from `r.URL.Query()`, `r.FormValue`, or another request source. Go's `net/http` strips most invalid runes, but composed values still warrant CRLF validation.",
    severity: "high",
    cwe: ["CWE-93", "CWE-113"],
    remediation:
      "Validate header values; reject anything containing CR or LF. Avoid building header values from raw request parameters.",
    references: REFS_RESPONSE_SPLITTING,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\.Header\(\)\.(?:Set|Add)\s*\([^)]*\br\.(?:URL\.Query\(\)|FormValue\b|Form\b|PostFormValue\b|Header\.Get\b)/,
    },
  },
  {
    id: "crlf-literal-in-header-value",
    category: "crlf-injection",
    title: "Literal CRLF/newline interpolated into a header value",
    description:
      "A header-setting call includes a literal `\\r\\n` or `\\n` escape inside its value. Embedding line terminators in a header is the mechanism of HTTP response splitting and should never appear in normal code.",
    severity: "medium",
    cwe: ["CWE-93", "CWE-113"],
    remediation:
      "Never place CR/LF in a header value. Use separate `setHeader` calls for separate headers and the framework's cookie API for cookies.",
    references: REFS_RESPONSE_SPLITTING,
    languages: ["javascript", "typescript", "python"],
    matcher: {
      type: "regex",
      regex: /\.(?:setHeader|writeHead|set|header|add)\s*\([^)]*["'`][^"'`]*\\r?\\n[^"'`]*["'`]/i,
    },
  },
  {
    id: "crlf-log-injection-request-input-js",
    category: "crlf-injection",
    title: "Raw request input written to a log without sanitization",
    description:
      "Request input is interpolated into a `console.log` / `logger.info` / `logger.error` call. Unsanitized CR/LF lets an attacker forge log lines (log injection / log forging), corrupting audit trails.",
    severity: "medium",
    cwe: ["CWE-117"],
    remediation:
      "Encode or strip CR/LF (and other control characters) from user input before logging. Prefer structured logging where user values are discrete fields rather than concatenated into the message.",
    references: REFS_LOG_INJECTION,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:console\.(?:log|info|warn|error|debug)|logger\.(?:log|info|warn|error|debug|trace))\s*\(\s*(?:`[^`]*\$\{[^}]*\breq\.|["'][^"']*["']\s*\+\s*req\.|[^)]*\+\s*req\.(?:body|query|params|headers|cookies)\b)/,
    },
  },
  {
    id: "crlf-log-injection-request-input-py",
    category: "crlf-injection",
    title: "Raw request input written to a log without sanitization (Python)",
    description:
      "Request input is interpolated into a `logging` call via an f-string or concatenation. CR/LF in the value forges additional log lines (log injection).",
    severity: "medium",
    cwe: ["CWE-117"],
    remediation:
      "Strip control characters from user input before logging, or pass user values as `%s` arguments to the logging call rather than building the message string yourself.",
    references: REFS_LOG_INJECTION,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:logging|logger|log)\.(?:info|warning|warn|error|debug|critical|exception)\s*\(\s*(?:[fF]["'][^"']*\{[^}]*\brequest\.|["'][^"']*["']\s*\+\s*request\.|[^)]*\+\s*request\.(?:args|form|json|data|headers|cookies)\b)/,
    },
  },
];
