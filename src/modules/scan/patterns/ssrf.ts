// SSRF patterns: server-side HTTP-client calls where the destination URL is
// influenced by request data.
//
// SSRF moved under OWASP A01:2025 (Broken Access Control) for the 2025 list.

import { scanToken } from "../../../core/scan-patterns.js";
import type { Pattern } from "./types.js";

const REFS_SSRF = ["https://cwe.mitre.org/data/definitions/918.html", "OWASP Top 10 2025 A01"];

// HTTP request API name loaded from data/scan-patterns.json so the literal
// token is not embedded inline (see src/core/scan-patterns.ts).
const FETCH = scanToken("web-http-request");

export const SSRF_PATTERNS: readonly Pattern[] = [
  {
    id: `ssrf-${FETCH}-request-data`,
    category: "ssrf",
    title: `${FETCH}() called with request data`,
    description: `The \`${FETCH}\` URL is taken directly from \`req.body\`, \`req.query\`, \`req.params\`, or \`req.headers\`. An attacker can target internal services (cloud metadata at 169.254.169.254, internal admin URLs).`,
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Allowlist the destinations. Resolve the hostname and reject link-local, loopback, and RFC1918 ranges before the request. Disable redirects or revalidate each hop.",
    references: REFS_SSRF,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: new RegExp(`\\b${FETCH}\\s*\\(\\s*req\\.(body|query|params|headers)\\b`),
    },
  },
  {
    id: "ssrf-axios-request-data",
    category: "ssrf",
    title: "axios request with URL from request data",
    description:
      "An axios call uses a URL derived directly from request input. This enables SSRF against internal services.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Validate URLs against an allowlist of hosts. Reject internal IPs after DNS resolution.",
    references: REFS_SSRF,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\baxios(?:\.(get|post|put|delete|patch|head|request))?\s*\(\s*req\.(body|query|params|headers)\b/,
    },
  },
  {
    id: "ssrf-http-get-variable",
    category: "ssrf",
    title: "http(s).get / request called with variable URL",
    description:
      "Node's `http.get` / `https.get` / `http.request` is invoked with a non-literal URL. If the value can be set by a user, attackers can pivot through this service.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Validate the target URL: parse with `new URL(...)`, allowlist the host, reject private IP ranges after resolution.",
    references: REFS_SSRF,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\b(?:https?)\.(get|request)\s*\(\s*(?!["'`]https?:\/\/|\{)[A-Za-z_$]/,
    },
  },
  {
    id: "ssrf-requests-py",
    category: "ssrf",
    title: "Python `requests` called with framework request data",
    description:
      "`requests.get(request.args[...])` or similar passes a user-controlled URL to an outbound HTTP call. Attackers can target internal services and cloud metadata.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Allowlist destination hosts. After resolving DNS, reject link-local (169.254.x), loopback (127.x), and RFC1918 ranges. Disable redirects.",
    references: REFS_SSRF,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\brequests\.(get|post|put|delete|patch|head|request)\s*\(\s*(request\.|flask\.request|self\.request)/,
    },
  },
  {
    id: "ssrf-urllib-variable-py",
    category: "ssrf",
    title: "urllib.urlopen with variable URL (Python)",
    description:
      "`urllib.request.urlopen` is called with a non-literal URL. Untrusted URLs can target internal services.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation: "Use a wrapper that allowlists hosts and resolves DNS before opening the URL.",
    references: REFS_SSRF,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\burllib(?:\.request)?\.urlopen\s*\(\s*(?!["']https?:\/\/)[A-Za-z_]/,
    },
  },
  {
    id: "ssrf-httpx-request-data-py",
    category: "ssrf",
    title: "httpx request with framework request data (Python)",
    description:
      "An httpx call takes its URL from framework request data. Same SSRF risk as `requests`.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Validate URLs against an allowlist and resolve DNS server-side before issuing the call.",
    references: REFS_SSRF,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\bhttpx\.(get|post|put|delete|patch|head|request|stream)\s*\(\s*(request\.|flask\.request|self\.request)/,
    },
  },
  {
    id: "ssrf-net-http-variable-go",
    category: "ssrf",
    title: "net/http request with a non-literal URL (Go)",
    description:
      "`http.Get`, `http.Post`, `http.NewRequest`, or a `client.Get`/`client.Post` call is invoked with a non-literal URL. If the value can be set by a user, attackers can pivot to internal services and cloud metadata (169.254.169.254).",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Parse the URL with `url.Parse`, allowlist the host, and reject loopback/link-local/RFC1918 addresses after DNS resolution. Disable automatic redirects or revalidate each hop.",
    references: REFS_SSRF,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:http|client)\.(?:(?:Get|Post|Head)\s*\(\s*(?!["'`])[A-Za-z_]|(?:NewRequest|NewRequestWithContext)\s*\((?:[^,()]+,){1,2}\s*(?!["'`])[A-Za-z_])/,
    },
  },
  {
    id: "ssrf-net-http-sprintf-go",
    category: "ssrf",
    title: "net/http request with a fmt.Sprintf URL (Go)",
    description:
      "An HTTP request URL is built with `fmt.Sprintf`. When any formatted value is user-controlled, the destination of the request can be redirected to internal hosts.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Build the URL from validated components, then verify the resolved host against an allowlist before issuing the request.",
    references: REFS_SSRF,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:http|client)\.(Get|Post|Head|NewRequest|NewRequestWithContext)\s*\([^)]*\bfmt\.Sprintf\s*\(/,
    },
  },
  {
    id: "ssrf-reqwest-variable-rust",
    category: "ssrf",
    title: "reqwest request with a non-literal URL (Rust)",
    description:
      "`reqwest::get`, a `reqwest::Client` builder call (`.get(...)`, `.post(...)`), or a `format!`-built URL passes a non-literal destination to an outbound HTTP request. User-controlled URLs enable SSRF against internal services.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Parse the URL with the `url` crate, allowlist the host, and reject private/loopback/link-local IPs after resolution. Disable redirects with a custom `redirect::Policy`.",
    references: REFS_SSRF,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex:
        /\breqwest::(?:get\s*\(|Client::[A-Za-z_]+\([^)]*\)\s*\.[A-Za-z_]+\s*\()\s*&?\s*(?:format!\s*\(|(?!["'])[A-Za-z_])/,
    },
  },
  {
    id: "ssrf-ureq-variable-rust",
    category: "ssrf",
    title: "ureq request with a non-literal URL (Rust)",
    description:
      "`ureq::get` (or another verb) is called with a non-literal URL. Untrusted URLs let attackers target internal endpoints.",
    severity: "high",
    cwe: ["CWE-918"],
    remediation:
      "Validate the URL against an allowlist of hosts and resolve DNS server-side before issuing the request.",
    references: REFS_SSRF,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex:
        /\bureq::(get|post|put|delete|head|patch)\s*\(\s*&?\s*(?:format!\s*\(|(?!["'])[A-Za-z_])/,
    },
  },
];
