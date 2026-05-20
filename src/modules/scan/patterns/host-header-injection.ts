// Host header injection patterns: the request Host header (or X-Forwarded-Host)
// used to build absolute URLs, links, redirects, or cache keys.
//
// CWE-644 (Improper Neutralization of HTTP Headers for Scripting Syntax) is the
// closest CWE for trusting the Host header. The classic impact is poisoned
// password-reset links pointing at an attacker-controlled domain.

import type { Pattern } from "./types.js";

const REFS_HOST_HEADER = [
  "https://cwe.mitre.org/data/definitions/644.html",
  "https://portswigger.net/web-security/host-header",
];

export const HOST_HEADER_INJECTION_PATTERNS: readonly Pattern[] = [
  {
    id: "host-header-url-from-host-js",
    category: "host-header-injection",
    title: "Absolute URL built from the request Host header",
    description:
      "A string or URL is built by interpolating `req.headers.host`, `req.hostname`, or `req.get('host')`. The Host header is attacker-controlled, so any link, redirect, or callback derived from it can point at a malicious domain.",
    severity: "high",
    cwe: ["CWE-644"],
    remediation:
      "Build absolute URLs from a server-configured canonical base URL, not the request Host header. Validate the Host against an allowlist of expected domains.",
    references: REFS_HOST_HEADER,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /(?:`[^`]*\$\{\s*(?:req\.headers\.host|req\.hostname|req\.get\s*\(\s*["']host["']\s*\))|["'][^"'\n]*["']\s*\+\s*(?:req\.headers\.host|req\.hostname|req\.get\s*\(\s*["']host["']\s*\))|(?:req\.headers\.host|req\.hostname|req\.get\s*\(\s*["']host["']\s*\))\s*\+\s*["'])/,
    },
  },
  {
    id: "host-header-forwarded-host-js",
    category: "host-header-injection",
    title: "URL built from the X-Forwarded-Host header",
    description:
      "A URL or link is constructed from `req.headers['x-forwarded-host']` / `req.header('x-forwarded-host')`. `X-Forwarded-Host` is fully attacker-controlled unless a trusted proxy sets it; trusting it enables host header injection.",
    severity: "high",
    cwe: ["CWE-644"],
    remediation:
      "Only trust `X-Forwarded-Host` when it is set by a proxy you control and the app is not directly reachable. Otherwise build URLs from a configured canonical host.",
    references: REFS_HOST_HEADER,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\breq\.(?:headers\s*\[\s*["']x-forwarded-host["']\s*\]|header\s*\(\s*["']x-forwarded-host["']\s*\)|get\s*\(\s*["']x-forwarded-host["']\s*\))/i,
    },
  },
  {
    id: "host-header-password-reset-link-js",
    category: "host-header-injection",
    title: "Password-reset / email link built from the request Host header",
    description:
      "A reset or verification link appears to be assembled from the request Host header. A poisoned Host header sends the password-reset URL — and its token — to an attacker-controlled domain when the victim clicks it.",
    severity: "critical",
    cwe: ["CWE-644"],
    remediation:
      "Generate password-reset and email-verification links from a hardcoded, server-configured base URL. Never derive security-sensitive links from the Host header.",
    references: REFS_HOST_HEADER,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /(?:reset|verify|verification|confirm|activation|magicLink|magic_link)[\w]*\s*(?:=|:)[^;\n]*(?:req\.headers\.host|req\.hostname|req\.get\s*\(\s*["']host["']\s*\)|req\.headers\s*\[\s*["']x-forwarded-host["']\s*\])/i,
    },
  },
  {
    id: "host-header-url-from-host-py",
    category: "host-header-injection",
    title: "URL built from the request Host header (Python)",
    description:
      "A link or URL is built from `request.host`, `request.host_url`, `request.headers['Host']`, or Django's `request.get_host()`. These reflect the client-supplied Host header and must not be trusted for URL construction.",
    severity: "high",
    cwe: ["CWE-644"],
    remediation:
      "In Flask, configure `SERVER_NAME` and use `url_for(..., _external=True)`. In Django, set `ALLOWED_HOSTS` (and `USE_X_FORWARDED_HOST` only behind a trusted proxy). Build links from configured hosts, not the request.",
    references: REFS_HOST_HEADER,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\brequest\.(?:host_url\b|host\b|get_host\s*\(\s*\)|headers\s*(?:\.get\s*\(\s*["']|\[\s*["'])(?:host|x-forwarded-host)["'])/i,
    },
  },
  {
    id: "host-header-password-reset-link-py",
    category: "host-header-injection",
    title: "Password-reset / email link built from the request Host header (Python)",
    description:
      "A reset or verification URL is assembled from `request.host` / `request.get_host()` / `request.host_url`. A poisoned Host header redirects the reset link and its token to an attacker.",
    severity: "critical",
    cwe: ["CWE-644"],
    remediation:
      "Build password-reset and verification links from a configured canonical domain. Do not derive security links from `request.get_host()` or `request.host`.",
    references: REFS_HOST_HEADER,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /(?:reset|verify|verification|confirm|activation|magic)[\w]*\s*=\s*[^;\n]*(?:request\.host_url|request\.host\b|request\.get_host\s*\(\s*\))/i,
    },
  },
  {
    id: "host-header-url-from-host-go",
    category: "host-header-injection",
    title: "URL built from the request Host header (Go)",
    description:
      'A URL string is built from `r.Host` or `r.Header.Get("X-Forwarded-Host")`. Both reflect the client-supplied Host header; using them to construct links or redirects enables host header injection.',
    severity: "high",
    cwe: ["CWE-644"],
    remediation:
      "Construct absolute URLs from a configured base host. Validate `r.Host` against an allowlist if it must be used.",
    references: REFS_HOST_HEADER,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /(?:https?:\/\/"\s*\+\s*(?:r\.Host\b|r\.Header\.Get\s*\(\s*"X-Forwarded-Host")|Sprintf\s*\([^)]*(?:r\.Host\b|r\.Header\.Get\s*\(\s*"X-Forwarded-Host"))/,
    },
  },
];
