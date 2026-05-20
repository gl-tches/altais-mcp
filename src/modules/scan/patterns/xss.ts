// XSS patterns: DOM XSS sinks, server-side HTML concat, framework escape hatches.

import type { Pattern } from "./types.js";

const REFS_XSS = ["https://cwe.mitre.org/data/definitions/79.html", "OWASP Top 10 2025 A03"];

export const XSS_PATTERNS: readonly Pattern[] = [
  {
    id: "xss-dom-innerhtml",
    category: "xss",
    title: "innerHTML/outerHTML assignment from untrusted source",
    description:
      "Assigning to `.innerHTML` or `.outerHTML` parses the string as HTML, allowing `<script>` and event-handler attributes to execute. If the value can be influenced by user input, this is DOM-based XSS.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Use `.textContent` for plain text. For rich content, use a trusted templating engine or `DOMPurify.sanitize()` before assignment.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\.(innerHTML|outerHTML)\s*=\s*(?!["'`]\s*$)/,
    },
  },
  {
    id: "xss-document-write",
    category: "xss",
    title: "document.write / document.writeln call",
    description:
      "`document.write` parses its argument as HTML. With any user-controlled portion this is a DOM XSS sink.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Replace `document.write` with DOM construction (`createElement`, `textContent`). Modern browsers also penalize it for performance.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bdocument\.write(?:ln)?\s*\(/,
    },
  },
  {
    id: "xss-eval",
    category: "xss",
    title: "eval / new Function with dynamic argument",
    description:
      "`eval` and `new Function(...)` execute arbitrary JavaScript. They are not strictly XSS but are equivalent code-injection sinks.",
    severity: "critical",
    cwe: ["CWE-94", "CWE-79"],
    remediation:
      "Remove `eval` and `Function` constructors. Replace dynamic code with data-driven configuration or a sandboxed parser.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /(?<![.\w$])(?:eval\s*\(|new\s+Function\s*\()/,
    },
  },
  {
    id: "xss-settimeout-string",
    category: "xss",
    title: "setTimeout / setInterval with string argument",
    description:
      "When `setTimeout` or `setInterval` is called with a string, it is parsed and executed as JavaScript — effectively `eval` with a delay.",
    severity: "high",
    cwe: ["CWE-94"],
    remediation:
      "Pass a function reference instead of a string. `setTimeout(() => doThing(arg), 100)`.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\b(setTimeout|setInterval)\s*\(\s*["'`]/,
    },
  },
  {
    id: "xss-react-dangerously-set-inner-html",
    category: "xss",
    title: "React `dangerouslySetInnerHTML` used",
    description:
      "`dangerouslySetInnerHTML` bypasses React's automatic escaping. Any untrusted value passed through `__html` is rendered as raw HTML.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Avoid `dangerouslySetInnerHTML` whenever possible. If unavoidable, sanitize with `DOMPurify.sanitize()` first and assign the result to `__html`.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bdangerouslySetInnerHTML\s*=\s*\{/,
    },
  },
  {
    id: "xss-jquery-html",
    category: "xss",
    title: "jQuery `.html()` with non-literal argument",
    description:
      "jQuery `.html(value)` sets innerHTML on matched elements. Passing user input here is a DOM XSS sink.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation: "Use `.text(value)` for plain text. For HTML, sanitize with DOMPurify first.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\$\([^)]*\)\.html\s*\(\s*[A-Za-z_$][\w$.]*\s*\)/,
    },
  },
  {
    id: "xss-server-html-concat-js",
    category: "xss",
    title: "Server response built by HTML string concatenation",
    description:
      "A response is being assembled by concatenating literal HTML tags with a variable. Without contextual escaping this is a reflected/stored XSS source.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Use a templating engine that auto-escapes by default (EJS with escaping, React SSR, etc.). Set a strict CSP that disallows inline scripts.",
    references: REFS_XSS,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /(res|response|reply)\.(send|end|write)\s*\(\s*["'`][^"'`\n]*<\/?\w+[^"'`\n]*["'`]\s*\+\s*[A-Za-z_$]/,
    },
  },
  {
    id: "xss-django-mark-safe",
    category: "xss",
    title: "Django `mark_safe` with non-literal argument",
    description:
      "`mark_safe` tells Django's template engine to render the string as raw HTML. Marking untrusted input as safe is the classic XSS path in Django.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Do not call `mark_safe` on values that include user input. Use the `|safe` filter only on values you fully control.",
    references: REFS_XSS,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bmark_safe\s*\(\s*[A-Za-z_]\w*/,
    },
  },
  {
    id: "xss-fstring-html-py",
    category: "xss",
    title: "HTML built with Python f-string containing user input",
    description:
      "Building HTML responses with f-strings does not escape special characters. Any substituted value can break out of the surrounding context.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Render HTML through a templating engine with autoescape (Jinja2 with `autoescape=True`, Django templates). Never assemble HTML by f-string.",
    references: REFS_XSS,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /[fF]["'][^"'\n]*<\/?\w+[^"'\n]*\{[A-Za-z_]/,
    },
  },
  {
    id: "xss-go-template-html-cast",
    category: "xss",
    title: "template.HTML cast on a non-literal value (Go)",
    description:
      "Converting a value to `template.HTML` (or `template.JS`/`template.URL`) tells `html/template` the content is already safe and disables contextual auto-escaping. Casting a variable that may carry user input is a direct XSS path.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Let `html/template` escape values by passing plain strings. Only cast to `template.HTML` for fully server-controlled, trusted markup; sanitize untrusted HTML (e.g. with bluemonday) first.",
    references: REFS_XSS,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\btemplate\.(HTML|JS|URL|HTMLAttr|CSS)\s*\(\s*(?!["'`])[A-Za-z_]/,
    },
  },
  {
    id: "xss-go-fprintf-html",
    category: "xss",
    title: "HTML response built with Fprintf/Sprintf (Go)",
    description:
      "An HTTP response writer receives HTML assembled by `fmt.Fprintf`/`fmt.Sprintf` with format verbs. `fmt` does not escape HTML metacharacters, so interpolated user input can inject markup or scripts.",
    severity: "high",
    cwe: ["CWE-79"],
    remediation:
      "Render responses through `html/template`, which escapes per context. Never build HTML output with the `fmt` package.",
    references: REFS_XSS,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\bfmt\.(Fprintf|Sprintf)\s*\([^)]*["'`][^"'`\n]*<\/?\w+[^"'`\n]*%[svdq]/,
    },
  },
];
