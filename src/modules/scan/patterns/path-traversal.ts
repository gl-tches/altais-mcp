// Path traversal patterns: filesystem access with user-controlled path components.

import type { Pattern } from "./types.js";

const REFS_PT = ["https://cwe.mitre.org/data/definitions/22.html", "OWASP Top 10 2025 A01"];

export const PATH_TRAVERSAL_PATTERNS: readonly Pattern[] = [
  {
    id: "path-traversal-fs-request-js",
    category: "path-traversal",
    title: "fs operation with request data",
    description:
      "An `fs.*` call uses `req.body`, `req.query`, or `req.params` directly as a path. Attackers can supply `../../etc/passwd` (or platform equivalent) to escape the intended directory.",
    severity: "high",
    cwe: ["CWE-22", "CWE-73"],
    remediation:
      "Map external identifiers to server-controlled paths via a lookup table. If a path must be derived from input, resolve with `path.resolve` and verify the result is under the allowed base directory.",
    references: REFS_PT,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bfs(?:Promises)?\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|open|openSync|unlink|unlinkSync|rmSync|rm|stat|statSync)\s*\(\s*req\.(body|query|params)\b/,
    },
  },
  {
    id: "path-traversal-fs-concat-js",
    category: "path-traversal",
    title: "fs path built by string concatenation",
    description:
      "A path argument is being concatenated with a variable. If the variable contains `..` segments, the resulting path can escape the base directory.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Build paths with `path.join` only after validating components. Resolve the final path and verify it stays under a known base.",
    references: REFS_PT,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\bfs(?:Promises)?\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|open|openSync)\s*\(\s*["'][^"'\n]*["']\s*\+\s*[A-Za-z_$]/,
    },
  },
  {
    id: "path-traversal-require-dynamic",
    category: "path-traversal",
    title: "Dynamic require with non-literal path",
    description:
      "`require(variable)` loads a module path determined at runtime. With user influence, this becomes arbitrary code loading from disk.",
    severity: "high",
    cwe: ["CWE-22", "CWE-829"],
    remediation:
      "Resolve module names through an explicit allowlist. Never call `require` with a value derived from request input.",
    references: REFS_PT,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\brequire\s*\(\s*(?!["'`])[A-Za-z_$][\w$.]*/,
    },
  },
  {
    id: "path-traversal-open-request-py",
    category: "path-traversal",
    title: "open() called with framework request data (Python)",
    description:
      "`open()` is being called with a path that originates in `request.*`. User-supplied `..` segments can read or write files outside the intended scope.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Validate that the resolved path stays inside an allowlisted directory: `if not Path(full).resolve().is_relative_to(base): raise`.",
    references: REFS_PT,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bopen\s*\(\s*(request\.|flask\.request|self\.request)/,
    },
  },
  {
    id: "path-traversal-os-path-join-request-py",
    category: "path-traversal",
    title: "os.path.join with framework request data (Python)",
    description:
      "A path is constructed via `os.path.join(...)` that includes data from `request.*`. An absolute path or `..` components in input bypasses the intended scope.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "After join, call `Path(p).resolve()` and verify the result is under the allowed base directory.",
    references: REFS_PT,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bos\.path\.join\s*\([^)]*(request\.|flask\.request|self\.request)/,
    },
  },
  {
    id: "path-traversal-send-file-py",
    category: "path-traversal",
    title: "Flask send_file with request data (Python)",
    description:
      "`send_file(...)` is called with a path drawn from the request. Without normalization, this exposes arbitrary files to the client.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Use `send_from_directory(safe_dir, filename)` and validate `filename` against a whitelist or pattern. Reject any value containing path separators.",
    references: REFS_PT,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /\bsend_file\s*\(\s*(request\.|flask\.request|self\.request)/,
    },
  },
  {
    id: "path-traversal-os-join-go",
    category: "path-traversal",
    title: "File access with a joined/formatted path (Go)",
    description:
      "An `os.Open`, `os.ReadFile`, `os.Create`, or `ioutil.ReadFile` call receives a path built with `filepath.Join`, `path.Join`, or `fmt.Sprintf`. Note that `filepath.Join` cleans `..` segments but does not confine the result to a base directory, so user input can still escape the intended scope.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "After joining, call `filepath.Clean` and verify the result has the intended base directory as a prefix (e.g. `strings.HasPrefix(abs, baseAbs)`). Reject absolute inputs.",
    references: REFS_PT,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:os\.(?:Open|OpenFile|ReadFile|Create)|ioutil\.ReadFile)\s*\(\s*(?:filepath\.Join|path\.Join|fmt\.Sprintf)\s*\(/,
    },
  },
  {
    id: "path-traversal-fs-concat-go",
    category: "path-traversal",
    title: "File access with a concatenated path (Go)",
    description:
      "A file path is concatenated with a variable using `+` before being passed to a filesystem call. If the variable contains `..` segments or an absolute path, the operation can escape the base directory.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Build paths with `filepath.Join` after validating each component, then confirm the cleaned result stays under the allowed base directory.",
    references: REFS_PT,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:os\.(?:Open|OpenFile|ReadFile|Create)|ioutil\.ReadFile)\s*\(\s*["'][^"'\n]*["']\s*\+\s*[A-Za-z_]/,
    },
  },
  {
    id: "path-traversal-fs-format-rust",
    category: "path-traversal",
    title: "File access with a format!-built path (Rust)",
    description:
      "`File::open`, `fs::read`, `fs::read_to_string`, `Path::new`, or `PathBuf::from` receives a path produced by the `format!` macro. Interpolated values containing `..` or an absolute path escape the intended directory.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Canonicalize the joined path with `Path::canonicalize` and verify it starts with the allowed base directory. Reject inputs containing path separators or `..`.",
    references: REFS_PT,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:File::open|fs::read|fs::read_to_string|fs::write|Path::new|PathBuf::from)\s*\(\s*&?\s*format!\s*\(/,
    },
  },
  {
    id: "path-traversal-fs-variable-rust",
    category: "path-traversal",
    title: "File access with a non-literal path (Rust)",
    description:
      "A filesystem call (`File::open`, `fs::read`, `fs::read_to_string`, `Path::new`, `PathBuf::from`) is given a variable path. If that value derives from user input, attackers can read or write files outside the intended scope.",
    severity: "high",
    cwe: ["CWE-22"],
    remediation:
      "Map external identifiers to server-controlled paths, or canonicalize the path and confirm it is contained within an allowlisted base directory before the operation.",
    references: REFS_PT,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex:
        /\b(?:File::open|fs::read|fs::read_to_string|fs::write)\s*\(\s*&?\s*(?!["'])[A-Za-z_][\w]*\s*\)/,
    },
  },
];
