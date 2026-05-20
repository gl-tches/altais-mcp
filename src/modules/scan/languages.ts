// Language detection for the scan module.
//
// Phase 1 fully supports TypeScript/JavaScript and Python.
// Other languages are recognized but match only a subset of patterns
// (or none); they ship as full analyzers in Phase 3.

export type Language =
  | "typescript"
  | "javascript"
  | "python"
  | "go"
  | "rust"
  | "java"
  | "ruby"
  | "php"
  | "csharp"
  | "unknown";

export const SUPPORTED_LANGUAGES: readonly Language[] = [
  "typescript",
  "javascript",
  "python",
  "go",
  "rust",
];

const EXTENSION_MAP: Readonly<Record<string, Language>> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".pyw": "python",
  ".pyi": "python",
  ".go": "go",
  ".rs": "rust",
  ".java": "java",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
};

const ALIAS_MAP: Readonly<Record<string, Language>> = {
  ts: "typescript",
  tsx: "typescript",
  typescript: "typescript",
  js: "javascript",
  jsx: "javascript",
  javascript: "javascript",
  node: "javascript",
  nodejs: "javascript",
  py: "python",
  python: "python",
  python3: "python",
  go: "go",
  golang: "go",
  rs: "rust",
  rust: "rust",
  java: "java",
  rb: "ruby",
  ruby: "ruby",
  php: "php",
  cs: "csharp",
  csharp: "csharp",
  "c#": "csharp",
};

export function languageFromExtension(filename: string): Language {
  const lower = filename.toLowerCase();
  const dot = lower.lastIndexOf(".");
  if (dot < 0) return "unknown";
  const ext = lower.slice(dot);
  return EXTENSION_MAP[ext] ?? "unknown";
}

export function normalizeLanguage(input: string): Language {
  const key = input.trim().toLowerCase();
  return ALIAS_MAP[key] ?? "unknown";
}

/**
 * Best-effort language detection. Prefers the caller-supplied `language`
 * parameter; falls back to extension from `filename`; if both are missing,
 * sniffs shebangs and pragma lines.
 */
export function detectLanguage(opts: {
  language?: string;
  filename?: string;
  source?: string;
}): Language {
  if (opts.language) {
    const fromAlias = normalizeLanguage(opts.language);
    if (fromAlias !== "unknown") return fromAlias;
  }
  if (opts.filename) {
    const fromExt = languageFromExtension(opts.filename);
    if (fromExt !== "unknown") return fromExt;
  }
  if (opts.source) {
    const firstLine = opts.source.split(/\r?\n/, 1)[0] ?? "";
    if (/^#!.*\bpython\d*\b/.test(firstLine)) return "python";
    if (/^#!.*\bnode\b/.test(firstLine)) return "javascript";
  }
  return "unknown";
}

export function isSupported(lang: Language): boolean {
  return SUPPORTED_LANGUAGES.includes(lang);
}
