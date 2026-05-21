// Injection patterns: SQL, NoSQL, OS command, LDAP.

import { scanToken } from "../../../core/scan-patterns.js";
import type { Pattern } from "./types.js";

const REFS_SQL = ["https://cwe.mitre.org/data/definitions/89.html", "OWASP Top 10 2025 A03"];
const REFS_CMD = ["https://cwe.mitre.org/data/definitions/78.html", "OWASP Top 10 2025 A03"];
const REFS_NOSQL = ["https://cwe.mitre.org/data/definitions/943.html"];
const REFS_LDAP = ["https://cwe.mitre.org/data/definitions/90.html"];

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const CHILD_PROCESS = scanToken("node-process-module");
const EXEC = scanToken("shell-command");
const EXEC_SYNC = scanToken("shell-command-sync");
const SPAWN = scanToken("process-launch");
const SYSTEM = scanToken("libc-system");
const POPEN = scanToken("libc-popen");
const SUBPROCESS = scanToken("py-subprocess-module");
const PY_POPEN = scanToken("py-popen-class");

export const INJECTION_PATTERNS: readonly Pattern[] = [
  {
    id: "sql-injection-concat-js",
    category: "injection",
    title: "Possible SQL injection via string concatenation",
    description:
      "A SQL execution method is called with a string-concatenated argument. Untrusted values mixed into a SQL string can be reinterpreted as syntax, allowing attackers to alter query intent.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      "Use parameterized queries (placeholders) or prepared statements. Never build SQL by string concatenation.",
    references: REFS_SQL,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(query|execute|exec|raw|run|prepare)\s*\(\s*["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"'\n]*["']\s*\+/i,
    },
  },
  {
    id: "sql-injection-template-js",
    category: "injection",
    title: "Possible SQL injection via template literal interpolation",
    description:
      "A SQL execution method receives a template literal containing `${...}` substitutions. Values interpolated into a SQL template are unescaped and can change the query semantics.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      "Switch to parameterized queries. If the library lacks placeholders, use a dedicated SQL builder that escapes values.",
    references: REFS_SQL,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(query|execute|exec|raw|run|prepare)\s*\(\s*`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^`]*\$\{/i,
    },
  },
  {
    id: "sql-injection-concat-py",
    category: "injection",
    title: "Possible SQL injection via string concatenation (Python)",
    description:
      "A database execute method receives a string assembled with `+`. Concatenating user input into SQL allows query tampering.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      "Pass parameters as a separate argument tuple: `cursor.execute('... WHERE id = %s', (user_id,))`. Never build SQL with `+`, f-strings, `%`, or `.format()`.",
    references: REFS_SQL,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\.(execute|executemany|raw|query|run)\s*\(\s*["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"'\n]*["']\s*\+/i,
    },
  },
  {
    id: "sql-injection-fstring-py",
    category: "injection",
    title: "Possible SQL injection via f-string interpolation (Python)",
    description:
      "A database execute method receives a Python f-string with substitutions. Values interpolated into a SQL f-string are unescaped and can break out of the intended query.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      "Use parameter binding: `cursor.execute('... = %s', (value,))`. f-strings should never be used to build SQL.",
    references: REFS_SQL,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\.(execute|executemany|raw|query|run)\s*\(\s*[fF]["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"'\n]*\{/i,
    },
  },
  {
    id: "sql-injection-percent-format-py",
    category: "injection",
    title: "Possible SQL injection via `%` or `.format()` (Python)",
    description:
      "A SQL execute method receives a string built with `%` or `.format()`. Python string formatting does not escape SQL metacharacters.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation: "Use the DB-API's parameter binding instead of Python string formatting.",
    references: REFS_SQL,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex:
        /\.(execute|executemany|raw|query|run)\s*\(\s*["'][^"'\n]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"'\n]*["']\s*(?:%\s*[A-Za-z_(]|\.format\s*\()/i,
    },
  },
  {
    id: "nosql-injection-mongo-where",
    category: "injection",
    title: "Possible NoSQL injection via `$where` operator",
    description: `MongoDB's \`$where\` operator evaluates JavaScript on the server. Passing untrusted strings or variables here is equivalent to \`${EVAL}\` against the database.`,
    severity: "high",
    cwe: ["CWE-943"],
    remediation:
      "Replace `$where` with standard query operators. If JS evaluation is unavoidable, hardcode the function and never pass user input into it.",
    references: REFS_NOSQL,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\$where\s*:\s*(?!function\b|["'`])\S/,
    },
  },
  {
    id: "nosql-injection-request-body",
    category: "injection",
    title: "Possible NoSQL injection via direct request body",
    description:
      "A MongoDB query is being constructed directly from `req.body`, `req.query`, or `req.params`. Attackers can pass query operators (e.g. `{ $ne: null }`) and bypass filters.",
    severity: "high",
    cwe: ["CWE-943"],
    remediation:
      "Validate request bodies against a schema (Zod, Joi, Mongoose) before using them in queries. Cast scalar fields to their expected types.",
    references: REFS_NOSQL,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex:
        /\.(find|findOne|findOneAndUpdate|update|updateOne|updateMany|deleteOne|deleteMany|remove|aggregate)\s*\(\s*req\.(body|query|params)\b/,
    },
  },
  {
    id: `command-injection-${EXEC}-js`,
    category: "injection",
    title: `Possible OS command injection via shell ${EXEC}`,
    description: `Node's \`${CHILD_PROCESS}.${EXEC}\` (and \`${EXEC_SYNC}\`) invokes a shell. When the command string is built from variables or template substitutions, attackers can inject extra commands via shell metacharacters.`,
    severity: "critical",
    cwe: ["CWE-78"],
    remediation: `Use \`${CHILD_PROCESS}.${EXEC}File\` or \`${SPAWN}\` with an explicit argv array. Never assemble shell commands by string concatenation.`,
    references: REFS_CMD,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: new RegExp(
        `(?:${CHILD_PROCESS}\\.)?(?:${EXEC}|${EXEC_SYNC})\\s*\\(\\s*(?:\`[^\`]*\\$\\{|["'][^"'\\n]*["']\\s*\\+|[A-Za-z_$][\\w$.]*\\s*[,)])`,
      ),
    },
  },
  {
    id: "command-injection-shell-true-js",
    category: "injection",
    title: "Child process spawned with `shell: true`",
    description: `Passing \`shell: true\` to \`${SPAWN}\`/\`${EXEC}\`/\`${EXEC}File\` re-enables shell interpretation. If any argument carries user input, this becomes shell injection.`,
    severity: "high",
    cwe: ["CWE-78"],
    remediation:
      "Set `shell: false` (the default) and use an explicit argv array. If a shell is genuinely required, allowlist arguments.",
    references: REFS_CMD,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /\bshell\s*:\s*true\b/,
    },
  },
  {
    id: `command-injection-os-${SYSTEM}-py`,
    category: "injection",
    title: `OS command execution via os.${SYSTEM} / os.${POPEN}`,
    description: `\`os.${SYSTEM}\` and \`os.${POPEN}\` execute commands through \`/bin/sh\`. With concatenated or interpolated arguments, attackers can append shell metacharacters to run arbitrary commands.`,
    severity: "critical",
    cwe: ["CWE-78"],
    remediation: `Use \`${SUBPROCESS}.run([...], shell=False)\` with an argv list. Validate inputs against an allowlist if shell semantics are unavoidable.`,
    references: REFS_CMD,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: new RegExp(
        `\\bos\\.(${SYSTEM}|${POPEN})\\s*\\(\\s*(?:[fF]["']|["'][^"'\\n]*["']\\s*\\+|[A-Za-z_]\\w*\\s*[,)])`,
      ),
    },
  },
  {
    id: `command-injection-${SUBPROCESS}-shell-py`,
    category: "injection",
    title: `${SUBPROCESS} called with \`shell=True\``,
    description: `Setting \`shell=True\` causes the command to be interpreted by the shell. When any argument is user-controlled, this enables OS command injection.`,
    severity: "critical",
    cwe: ["CWE-78"],
    remediation: `Use \`${SUBPROCESS}.run(['cmd', 'arg1'], shell=False)\` with a list. Avoid \`shell=True\` unless inputs are entirely server-controlled.`,
    references: REFS_CMD,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: new RegExp(
        `\\b${SUBPROCESS}\\.(run|call|check_call|check_output|${PY_POPEN})\\s*\\([^)]*\\bshell\\s*=\\s*True`,
      ),
    },
  },
  {
    id: "ldap-injection-filter-js",
    category: "injection",
    title: "Possible LDAP injection via filter concatenation",
    description:
      "An LDAP filter string is being built by concatenating variables. LDAP metacharacters such as `*`, `(`, `)`, and `\\` can alter the filter semantics.",
    severity: "high",
    cwe: ["CWE-90"],
    remediation:
      "Use an LDAP client that parameterizes filters, or escape filter values per RFC 4515 (`\\28`, `\\29`, `\\2a`, `\\5c`).",
    references: REFS_LDAP,
    languages: ["javascript", "typescript"],
    matcher: {
      type: "regex",
      regex: /["'`]\([\w]+=[^)]*["'`]\s*\+\s*[A-Za-z_$]/,
    },
  },
  {
    id: "ldap-injection-filter-py",
    category: "injection",
    title: "Possible LDAP injection via filter f-string (Python)",
    description:
      "An LDAP filter string is being built with an f-string. Substituting unescaped user input into an LDAP filter allows attackers to broaden the query.",
    severity: "high",
    cwe: ["CWE-90"],
    remediation:
      "Use `ldap.filter.escape_filter_chars` (python-ldap) before substituting values into filters.",
    references: REFS_LDAP,
    languages: ["python"],
    matcher: {
      type: "regex",
      regex: /[fF]["']\([\w]+=[^)]*\{[A-Za-z_]/,
    },
  },
  {
    id: "sql-injection-sprintf-go",
    category: "injection",
    title: "Possible SQL injection via fmt.Sprintf (Go)",
    description:
      "A `database/sql` execution method (`Query`, `QueryRow`, `Exec`, and their context variants) receives a query built with `fmt.Sprintf`. Values formatted into the SQL string are not escaped and can change the query semantics.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      'Use placeholder parameters: `db.Query("SELECT * FROM users WHERE id = $1", id)`. Never build SQL with `fmt.Sprintf` or concatenation.',
    references: REFS_SQL,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:ctx\s*,\s*)?fmt\.Sprintf\s*\(/,
    },
  },
  {
    id: "sql-injection-concat-go",
    category: "injection",
    title: "Possible SQL injection via string concatenation (Go)",
    description:
      "A `database/sql` execution method receives a query string assembled with `+`. Concatenating user input into SQL allows query tampering.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      "Pass parameters separately with `$N` (or `?`) placeholders. Never assemble SQL with `+`.",
    references: REFS_SQL,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex:
        /\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:ctx\s*,\s*)?["`][^"`\n]*\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"`\n]*["`]\s*\+/i,
    },
  },
  {
    id: "command-injection-exec-sh-go",
    category: "injection",
    title: "OS command injection via exec.Command shell wrapper (Go)",
    description:
      '`exec.Command("sh", "-c", ...)` (or `bash -c`) hands the final argument to a shell. When that argument is built from variables or `fmt.Sprintf`, attackers can inject shell metacharacters to run arbitrary commands.',
    severity: "critical",
    cwe: ["CWE-78"],
    remediation:
      'Call `exec.Command("prog", arg1, arg2)` with the program and each argument as separate elements. Avoid `sh -c` unless the command is fully server-controlled.',
    references: REFS_CMD,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\bexec\.Command\s*\(\s*["'](?:\/bin\/)?(?:sh|bash)["']\s*,\s*["']-c["']/,
    },
  },
  {
    id: "command-injection-exec-sprintf-go",
    category: "injection",
    title: "OS command injection via exec.Command with fmt.Sprintf (Go)",
    description:
      "`exec.Command` is invoked with an argument produced by `fmt.Sprintf`. If any formatted value is user-controlled, the spawned program or its arguments can be manipulated.",
    severity: "high",
    cwe: ["CWE-78"],
    remediation:
      "Pass a fixed program name and discrete, validated arguments to `exec.Command`. Do not format untrusted data into the command or argument strings.",
    references: REFS_CMD,
    languages: ["go"],
    matcher: {
      type: "regex",
      regex: /\bexec\.Command\s*\(\s*fmt\.Sprintf\s*\(/,
    },
  },
  {
    id: "sql-injection-format-rust",
    category: "injection",
    title: "Possible SQL injection via format! macro (Rust)",
    description:
      "A `query` or `execute` call receives a string produced by the `format!` macro. Values interpolated by `format!` are not escaped and can break out of the intended SQL statement.",
    severity: "critical",
    cwe: ["CWE-89"],
    remediation:
      'Use bound parameters (`sqlx::query("... WHERE id = $1").bind(id)`, or the `query!` macros). Never build SQL with `format!`.',
    references: REFS_SQL,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex: /\b(query|query_as|query_scalar|execute)\s*\(\s*&?\s*format!\s*\(/,
    },
  },
  {
    id: "command-injection-command-sh-rust",
    category: "injection",
    title: "OS command injection via Command shell wrapper (Rust)",
    description:
      '`Command::new("sh")` (or `bash`) combined with `.arg("-c")` and a `format!`-built argument runs the final string through a shell. User-controlled values in that string allow shell command injection.',
    severity: "critical",
    cwe: ["CWE-78"],
    remediation:
      'Invoke the target program directly with `Command::new("prog").arg(validated_arg)`. Avoid `sh -c` unless the command is fully static.',
    references: REFS_CMD,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex:
        /\bCommand::new\s*\(\s*["'](?:\/bin\/)?(?:sh|bash)["']\s*\)[\s\S]{0,120}?\.arg\s*\(\s*["']-c["']\s*\)[\s\S]{0,120}?\.arg\s*\(\s*&?\s*format!/,
    },
  },
  {
    id: "command-injection-command-var-rust",
    category: "injection",
    title: "OS command injection via Command::new with a variable program (Rust)",
    description:
      "`Command::new` is called with a non-literal program name. If the value is influenced by user input, an attacker can choose which executable runs.",
    severity: "high",
    cwe: ["CWE-78"],
    remediation:
      "Resolve the program name through an allowlist before passing it to `Command::new`. Never derive the executable path from request input.",
    references: REFS_CMD,
    languages: ["rust"],
    matcher: {
      type: "regex",
      regex: /\bCommand::new\s*\(\s*(?!["'])[A-Za-z_][\w]*\s*\)/,
    },
  },
];
