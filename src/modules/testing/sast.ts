// SAST tool configuration generator (altais_generate_sast_config).
//
// Produces a ready-to-use config file body for a chosen static-analysis
// tool, the recommended rule packs for the requested languages, and a CI
// invocation snippet. Pure text generation — no tool is executed.

export type SastTool = "semgrep" | "codeql" | "bandit" | "gosec" | "eslint-security" | "brakeman";

export interface SastConfigInput {
  readonly tool: SastTool;
  readonly languages: readonly string[];
}

export interface SastConfigResult {
  readonly tool: SastTool;
  readonly languages: readonly string[];
  readonly config_file: { readonly filename: string; readonly content: string };
  readonly rule_packs: readonly string[];
  readonly ci_snippet: { readonly filename: string; readonly content: string };
  readonly notes: readonly string[];
  readonly references: readonly string[];
}

const REFERENCES: Readonly<Record<SastTool, readonly string[]>> = {
  semgrep: ["https://semgrep.dev/docs/", "https://semgrep.dev/p/security-audit"],
  codeql: ["https://codeql.github.com/docs/", "https://github.com/github/codeql-action"],
  bandit: ["https://bandit.readthedocs.io/", "https://github.com/PyCQA/bandit"],
  gosec: ["https://github.com/securego/gosec"],
  "eslint-security": [
    "https://github.com/eslint-community/eslint-plugin-security",
    "https://eslint.org/docs/latest/use/configure/",
  ],
  brakeman: ["https://brakemanscanner.org/docs/"],
};

function semgrepConfig(languages: readonly string[]): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const packs = ["p/security-audit", "p/secrets", "p/owasp-top-ten", "p/cwe-top-25"];
  const langComment = languages.length > 0 ? languages.join(", ") : "all detected";
  const content = [
    "# .semgrep.yml — Semgrep ruleset",
    `# Target languages: ${langComment}`,
    "rules: []",
    "# Curated registry packs are referenced from the CI command via --config.",
    "# Add project-specific rules below using the Semgrep pattern syntax:",
    "#   - id: no-hardcoded-secret",
    "#     patterns:",
    '#       - pattern: $X = "..."',
    '#     message: "Possible hardcoded secret"',
    "#     severity: ERROR",
    "#     languages: [generic]",
  ].join("\n");
  const ci = [
    "# .github/workflows/semgrep.yml",
    "name: semgrep",
    "on: [pull_request]",
    "jobs:",
    "  semgrep:",
    "    runs-on: ubuntu-latest",
    "    container: { image: semgrep/semgrep }",
    "    steps:",
    "      - uses: actions/checkout@v4",
    `      - run: semgrep ci ${packs.map((p) => `--config ${p}`).join(" ")}`,
  ].join("\n");
  return {
    config_file: { filename: ".semgrep.yml", content },
    rule_packs: packs,
    ci_snippet: { filename: ".github/workflows/semgrep.yml", content: ci },
  };
}

function codeqlConfig(languages: readonly string[]): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const langs = languages.length > 0 ? languages : ["javascript"];
  const packs = ["security-extended", "security-and-quality"];
  const content = [
    "# .github/codeql/codeql-config.yml",
    "name: codeql-config",
    "queries:",
    "  - uses: security-extended",
    "  - uses: security-and-quality",
    "paths-ignore:",
    "  - '**/node_modules'",
    "  - '**/vendor'",
    "  - '**/*.test.*'",
  ].join("\n");
  const matrix = langs.map((l) => `          - ${l}`).join("\n");
  const ci = [
    "# .github/workflows/codeql.yml",
    "name: codeql",
    "on: [pull_request]",
    "jobs:",
    "  analyze:",
    "    runs-on: ubuntu-latest",
    "    permissions: { security-events: write }",
    "    strategy:",
    "      matrix:",
    "        language:",
    matrix,
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: github/codeql-action/init@v3",
    "        with:",
    "          languages: ${{ matrix.language }}",
    "          config-file: ./.github/codeql/codeql-config.yml",
    "      - uses: github/codeql-action/autobuild@v3",
    "      - uses: github/codeql-action/analyze@v3",
  ].join("\n");
  return {
    config_file: { filename: ".github/codeql/codeql-config.yml", content },
    rule_packs: packs,
    ci_snippet: { filename: ".github/workflows/codeql.yml", content: ci },
  };
}

function banditConfig(): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const content = [
    "# .bandit — Bandit configuration",
    "[bandit]",
    "exclude = /tests,/.venv,/build",
    "# Skip nothing by default; suppress specific findings inline with",
    "# `# nosec BXXX` and a justification comment.",
    "skips =",
  ].join("\n");
  const ci = [
    "# .github/workflows/bandit.yml",
    "name: bandit",
    "on: [pull_request]",
    "jobs:",
    "  bandit:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - run: pip install bandit",
    "      - run: bandit -r . -c .bandit -ll -f sarif -o bandit.sarif",
  ].join("\n");
  return {
    config_file: { filename: ".bandit", content },
    rule_packs: ["B1xx injection", "B3xx blocklist calls", "B6xx injection sinks"],
    ci_snippet: { filename: ".github/workflows/bandit.yml", content: ci },
  };
}

function gosecConfig(): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const content = [
    "// .gosec.json — gosec configuration",
    "{",
    '  "global": {',
    '    "nosec": "false",',
    '    "audit": "true"',
    "  },",
    '  "G104": "false"',
    "}",
  ].join("\n");
  const ci = [
    "# .github/workflows/gosec.yml",
    "name: gosec",
    "on: [pull_request]",
    "jobs:",
    "  gosec:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: securego/gosec@master",
    "        with:",
    "          args: -conf .gosec.json -fmt sarif -out gosec.sarif ./...",
  ].join("\n");
  return {
    config_file: { filename: ".gosec.json", content },
    rule_packs: [
      "G1xx audit (injection, crypto)",
      "G2xx code-quality",
      "G3xx file-permission",
      "G4xx crypto-misuse",
    ],
    ci_snippet: { filename: ".github/workflows/gosec.yml", content: ci },
  };
}

function eslintSecurityConfig(): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const content = [
    "// eslint.config.js — flat config with the security plugin",
    'import security from "eslint-plugin-security";',
    "",
    "export default [",
    "  security.configs.recommended,",
    "  {",
    "    rules: {",
    '      "security/detect-child-process": "error",',
    '      "security/detect-non-literal-fs-filename": "error",',
    '      "security/detect-unsafe-regex": "error",',
    "    },",
    "  },",
    "];",
  ].join("\n");
  const ci = [
    "# .github/workflows/eslint-security.yml",
    "name: eslint-security",
    "on: [pull_request]",
    "jobs:",
    "  eslint:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - run: npm ci",
    "      - run: npx eslint . --format @microsoft/eslint-formatter-sarif -o eslint.sarif",
  ].join("\n");
  return {
    config_file: { filename: "eslint.config.js", content },
    rule_packs: [
      "eslint-plugin-security recommended",
      "detect-child-process",
      "detect-non-literal-fs-filename",
      "detect-unsafe-regex",
    ],
    ci_snippet: { filename: ".github/workflows/eslint-security.yml", content: ci },
  };
}

function brakemanConfig(): {
  config_file: { filename: string; content: string };
  rule_packs: readonly string[];
  ci_snippet: { filename: string; content: string };
} {
  const content = [
    "# config/brakeman.yml — Brakeman configuration",
    "---",
    ":run_all_checks: true",
    ":confidence_level: 2",
    ":skip_files:",
    "  - vendor/",
    "  - spec/",
    ":ignore_file: config/brakeman.ignore",
  ].join("\n");
  const ci = [
    "# .github/workflows/brakeman.yml",
    "name: brakeman",
    "on: [pull_request]",
    "jobs:",
    "  brakeman:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: ruby/setup-ruby@v1",
    "        with: { ruby-version: '3.3' }",
    "      - run: gem install brakeman",
    "      - run: brakeman -c config/brakeman.yml -f sarif -o brakeman.sarif",
  ].join("\n");
  return {
    config_file: { filename: "config/brakeman.yml", content },
    rule_packs: [
      "SQL injection",
      "Cross-site scripting",
      "Mass assignment",
      "Command injection",
      "Unsafe redirects",
    ],
    ci_snippet: { filename: ".github/workflows/brakeman.yml", content: ci },
  };
}

const NOTES: Readonly<Record<SastTool, readonly string[]>> = {
  semgrep: [
    "Run `semgrep ci` rather than `semgrep scan` in CI — it diff-scans only changed code on pull requests.",
    "Triage false positives with inline `// nosemgrep: rule-id` comments that include a justification.",
  ],
  codeql: [
    "CodeQL needs to observe a build for compiled languages; use `autobuild` or a manual build step.",
    "`security-extended` adds lower-precision queries — expect more findings to triage than the default suite.",
  ],
  bandit: [
    "Bandit only analyses Python; pair it with a dependency scanner for full coverage.",
    "Use `-ll` to report medium-and-above severity and keep the signal-to-noise ratio high.",
  ],
  gosec: [
    "gosec analyses Go source via the AST; keep it on the latest release so new rules land.",
    "Avoid blanket `#nosec` — annotate the specific rule id and explain why it is safe.",
  ],
  "eslint-security": [
    "The security plugin is heuristic; treat findings as leads, not confirmed vulnerabilities.",
    "Combine with a typed linter (typescript-eslint) for taint-adjacent coverage.",
  ],
  brakeman: [
    "Brakeman is Rails-specific and runs without executing the app — fast enough for every PR.",
    "Maintain `brakeman.ignore` through `brakeman -I` so triaged findings stay suppressed with context.",
  ],
};

export class SastConfigError extends Error {
  override readonly name = "SastConfigError";
}

export function generateSastConfig(input: SastConfigInput): SastConfigResult {
  if (input.languages.length === 0) {
    throw new SastConfigError("`languages` must list at least one target language.");
  }
  let built: {
    config_file: { filename: string; content: string };
    rule_packs: readonly string[];
    ci_snippet: { filename: string; content: string };
  };
  switch (input.tool) {
    case "semgrep":
      built = semgrepConfig(input.languages);
      break;
    case "codeql":
      built = codeqlConfig(input.languages);
      break;
    case "bandit":
      built = banditConfig();
      break;
    case "gosec":
      built = gosecConfig();
      break;
    case "eslint-security":
      built = eslintSecurityConfig();
      break;
    case "brakeman":
      built = brakemanConfig();
      break;
  }
  return {
    tool: input.tool,
    languages: input.languages,
    config_file: built.config_file,
    rule_packs: built.rule_packs,
    ci_snippet: built.ci_snippet,
    notes: NOTES[input.tool],
    references: REFERENCES[input.tool],
  };
}
