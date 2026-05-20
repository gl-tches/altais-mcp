// Server-Side Template Injection (SSTI) patterns.
//
// A template engine is compiled or rendered from a non-literal source —
// a variable, a concatenation, or request input. Attacker-controlled
// template text leads to remote code execution.
//
// CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine.
// CWE-94: Improper Control of Generation of Code.

import type { Pattern } from "./types.js";

const REFS_SSTI = [
  "https://cwe.mitre.org/data/definitions/1336.html",
  "https://cwe.mitre.org/data/definitions/94.html",
  "https://portswigger.net/web-security/server-side-template-injection",
];

export const SSTI_PATTERNS: readonly Pattern[] = [
  {
    id: "ssti-handlebars-compile-nonliteral-js",
    category: "ssti",
    title: "Handlebars.compile() called with a non-literal template",
    description:
      "`Handlebars.compile` receives a variable, a concatenation, or request input instead of a literal template string. Attacker-controlled template text can be crafted into a prototype-pollution-to-RCE gadget.",
    severity: "critical",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Compile only static, developer-authored templates. Treat user input strictly as data passed to the rendered template, never as the template itself.",
    references: REFS_SSTI,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bHandlebars\.compile\s*\(\s*(?!["'`])[A-Za-z_$]/,
    },
  },
  {
    id: "ssti-ejs-render-nonliteral-js",
    category: "ssti",
    title: "ejs.render() / ejs.compile() with a non-literal template",
    description:
      "An EJS template is compiled or rendered from a variable or request input. EJS templates execute arbitrary JavaScript, so untrusted template text is direct RCE.",
    severity: "critical",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Render only static `.ejs` files or string constants. Never pass `req.body`/`req.query` as the template argument.",
    references: REFS_SSTI,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bejs\.(?:render|compile)\s*\(\s*(?!["'`])[A-Za-z_$]/,
    },
  },
  {
    id: "ssti-pug-lodash-template-nonliteral-js",
    category: "ssti",
    title: "pug.compile() or _.template() with a non-literal template",
    description:
      "`pug.compile` or lodash `_.template` is invoked with a non-literal string. Both engines evaluate embedded JavaScript expressions; a user-controlled template yields code execution.",
    severity: "critical",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Compile only trusted template files or constants. If users supply formatting, use a logic-less engine and pass their input strictly as data.",
    references: REFS_SSTI,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\b(?:pug\.compile|_\.template)\s*\(\s*(?!["'`])[A-Za-z_$]/,
    },
  },
  {
    id: "ssti-nunjucks-renderstring-nonliteral-js",
    category: "ssti",
    title: "nunjucks.renderString() with a non-literal template",
    description:
      "`nunjucks.renderString` compiles and renders a template from a runtime string. With autoescaping bypasses and global access, an attacker-controlled template can reach `process` and execute code.",
    severity: "critical",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Use `nunjucks.render` against static template files. Never call `renderString` with user input as the template.",
    references: REFS_SSTI,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bnunjucks\.renderString\s*\(\s*(?!["'`])[A-Za-z_$]/,
    },
  },
  {
    id: "ssti-jinja-template-string-py",
    category: "ssti",
    title: "Jinja2/Django template built from a non-literal string",
    description:
      "`Template(...)`, `render_template_string(...)`, or `Environment(...).from_string(...)` receives a variable, an f-string, or a concatenation. Jinja2/Mako SSTI escalates to RCE via `__globals__` and `__subclasses__`.",
    severity: "critical",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Render only static templates from the loader. Pass user input through the template context, never as the template source. Use a sandboxed environment if dynamic templates are unavoidable.",
    references: REFS_SSTI,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:render_template_string|Template)\s*\(\s*(?!["']|r["'])[A-Za-z_]|\.from_string\s*\(\s*(?!["']|r["'])[A-Za-z_]/,
    },
  },
  {
    id: "ssti-go-template-parse-nonliteral",
    category: "ssti",
    title: "text/template Parse() with a non-literal template (Go)",
    description:
      "`template.New(...).Parse(...)` (or wrapped in `template.Must`) is given a variable rather than a string constant. `text/template` performs no HTML escaping and exposes method calls, so untrusted template text is dangerous.",
    severity: "high",
    cwe: ["CWE-1336", "CWE-94"],
    remediation:
      "Parse only constant templates. Keep user input in the data passed to `Execute`. Use `html/template` for HTML output and never parse user-supplied template text.",
    references: REFS_SSTI,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\.Parse\s*\(\s*(?!["'`])[A-Za-z_]/,
    },
  },
];
