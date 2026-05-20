// Interactive Application Security Testing setup generator
// (altais_generate_iast_config).
//
// Produces IAST agent setup steps, an instrumentation configuration, CI/CD
// integration, and coverage guidance for the chosen tool and language.
// Static text generation only — no agent is downloaded or run.

export type IastTool = "contrast" | "seeker" | "dynatrace" | "open-source";

export type IastLanguage = "c" | "cpp" | "rust" | "go" | "python" | "javascript" | "java";

export interface IastConfigInput {
  readonly tool: IastTool;
  readonly language: IastLanguage;
  readonly framework?: string;
}

export interface IastConfigResult {
  readonly tool: IastTool;
  readonly language: IastLanguage;
  readonly framework: string;
  readonly setup_steps: readonly string[];
  readonly instrumentation: { readonly filename: string; readonly content: string };
  readonly ci_integration: { readonly filename: string; readonly content: string };
  readonly coverage_guidance: readonly string[];
  readonly supported: boolean;
  readonly notes: readonly string[];
  readonly references: readonly string[];
}

const REFERENCES: Readonly<Record<IastTool, readonly string[]>> = {
  contrast: ["https://docs.contrastsecurity.com/"],
  seeker: ["https://www.blackduck.com/static-dynamic-analysis/seeker.html"],
  dynatrace: ["https://docs.dynatrace.com/docs/secure/application-security"],
  "open-source": ["https://owasp.org/www-project-zap/", "https://github.com/jtesta/iast"],
};

// IAST instruments a running app; it needs a managed runtime with a hook
// point. Compiled-to-native languages have no general IAST agent.
const RUNTIME_SUPPORTED: Readonly<Record<IastLanguage, boolean>> = {
  c: false,
  cpp: false,
  rust: false,
  go: true,
  python: true,
  javascript: true,
  java: true,
};

const DEFAULT_FRAMEWORK: Readonly<Record<IastLanguage, string>> = {
  c: "none",
  cpp: "none",
  rust: "none",
  go: "net-http",
  python: "django",
  javascript: "express",
  java: "spring-boot",
};

const FRAMEWORK_RE = /^[A-Za-z0-9._-]{1,48}$/;

function setupSteps(tool: IastTool, language: IastLanguage): readonly string[] {
  const agentName =
    tool === "contrast"
      ? "Contrast agent"
      : tool === "seeker"
        ? "Seeker agent"
        : tool === "dynatrace"
          ? "Dynatrace OneAgent"
          : "open-source IAST agent";
  const langStep: Readonly<Record<IastLanguage, string>> = {
    java: `Attach the ${agentName} as a JVM \`-javaagent\` so bytecode is instrumented at class load.`,
    python: `Install the ${agentName} package and import / enable it as the first thing in the app entrypoint.`,
    javascript: `Install the ${agentName} package and \`require\` it before any application module loads.`,
    go: `Build the application with the ${agentName} compile-time instrumentation toolchain (Go has no runtime attach).`,
    c: `IAST has no general agent for native C — use DAST plus fuzzing instead.`,
    cpp: `IAST has no general agent for native C++ — use DAST plus fuzzing instead.`,
    rust: `IAST has no general agent for native Rust — use DAST plus fuzzing instead.`,
  };
  return [
    `Provision the ${agentName} and obtain the API key / connection token from your secrets manager (never commit it).`,
    langStep[language],
    "Run the existing functional / integration test suite with the agent attached so it observes real request flows.",
    "The agent reports vulnerabilities as instrumented sinks are exercised — review the dashboard or SARIF export after the run.",
  ];
}

function instrumentationFor(
  tool: IastTool,
  language: IastLanguage,
  framework: string,
): { filename: string; content: string } {
  if (!RUNTIME_SUPPORTED[language]) {
    return {
      filename: "iast/NOT_SUPPORTED.md",
      content: [
        `# IAST is not applicable to ${language}`,
        "",
        "IAST instruments a managed runtime at a hook point. Natively compiled",
        "languages have no general-purpose IAST agent.",
        "",
        "Recommended alternative: combine DAST against the running service with",
        "coverage-guided fuzzing of the parsing / input-handling code.",
      ].join("\n"),
    };
  }
  switch (language) {
    case "java":
      return {
        filename: "iast/iast.properties",
        content: [
          "# IAST agent configuration (" + tool + ")",
          `# framework: ${framework}`,
          "agent.enable=true",
          "agent.mode=iast",
          "assess.enable=true",
          "assess.rules.exclude=",
          "# Attach via JVM arg:  java -javaagent:/opt/iast/agent.jar -jar app.jar",
        ].join("\n"),
      };
    case "python":
      return {
        filename: "iast/iast_config.yaml",
        content: [
          "# IAST agent configuration (" + tool + ")",
          `# framework: ${framework}`,
          "agent:",
          "  enable: true",
          "  mode: iast",
          "assess:",
          "  enable: true",
          "  sampling: 100   # observe every request during the test run",
        ].join("\n"),
      };
    case "javascript":
      return {
        filename: "iast/iast.config.js",
        content: [
          "// IAST agent configuration (" + tool + ")",
          `// framework: ${framework}`,
          "module.exports = {",
          "  agent: { enable: true, mode: 'iast' },",
          "  assess: { enable: true, sampling: 100 },",
          "};",
        ].join("\n"),
      };
    case "go":
      return {
        filename: "iast/iast.yaml",
        content: [
          "# IAST compile-time instrumentation (" + tool + ")",
          `# framework: ${framework}`,
          "instrumentation:",
          "  enable: true",
          "  mode: iast",
          "  build_tags: [iast]",
        ].join("\n"),
      };
    case "c":
    case "cpp":
    case "rust":
      // Unreachable: RUNTIME_SUPPORTED is false for these.
      return { filename: "iast/NOT_SUPPORTED.md", content: "Not supported." };
  }
}

function ciIntegration(language: IastLanguage): { filename: string; content: string } {
  const runCmd: Readonly<Record<IastLanguage, string>> = {
    java: "mvn verify   # agent attached via MAVEN_OPTS=-javaagent:...",
    python: "pytest tests/integration   # agent enabled in conftest.py",
    javascript: "npm run test:integration   # agent required via NODE_OPTIONS=-r ...",
    go: "go test -tags iast ./...",
    c: "# IAST not applicable",
    cpp: "# IAST not applicable",
    rust: "# IAST not applicable",
  };
  return {
    filename: ".github/workflows/iast.yml",
    content: [
      "# .github/workflows/iast.yml",
      "name: iast",
      "on: [pull_request]",
      "jobs:",
      "  iast:",
      "    runs-on: ubuntu-latest",
      "    env:",
      "      IAST_API_KEY: ${{ secrets.IAST_API_KEY }}",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - name: Run tests with the IAST agent attached",
      `        run: ${runCmd[language]}`,
      "      - name: Fail the build on new high-severity findings",
      "        run: iast-cli gate --severity high --baseline iast-baseline.json",
    ].join("\n"),
  };
}

const COVERAGE_GUIDANCE: readonly string[] = [
  "IAST only reports on code paths that are actually exercised — its coverage equals your functional and integration test coverage.",
  "Run IAST against the integration / end-to-end suite, not unit tests; it needs real request flows through the instrumented sinks.",
  "Track route and endpoint coverage and fill gaps with targeted tests so every entry point is observed at least once.",
  "Maintain a baseline of triaged findings so CI gates only on new issues, not the existing backlog.",
  "Pair IAST with SAST and DAST: SAST sees unexecuted code, DAST sees the outside view, IAST confirms exploitability from inside.",
];

const NOTES: Readonly<Record<IastTool, readonly string[]>> = {
  contrast: [
    "Contrast Assess runs continuously; keep it enabled in QA / staging for ongoing coverage, not just in CI.",
  ],
  seeker: [
    "Seeker performs active verification of findings, which lowers false positives but adds runtime overhead.",
  ],
  dynatrace: [
    "Dynatrace Application Security reuses the OneAgent already deployed for observability — no separate agent install.",
  ],
  "open-source": [
    "Open-source IAST coverage is narrower than commercial tools; validate it instruments your framework before relying on it.",
  ],
};

export class IastConfigError extends Error {
  override readonly name = "IastConfigError";
}

export function generateIastConfig(input: IastConfigInput): IastConfigResult {
  const framework = input.framework ?? DEFAULT_FRAMEWORK[input.language];
  if (!FRAMEWORK_RE.test(framework)) {
    throw new IastConfigError(
      "`framework` must be a short identifier (letters, digits, dot, dash, underscore).",
    );
  }
  const supported = RUNTIME_SUPPORTED[input.language];
  const notes: readonly string[] = supported
    ? NOTES[input.tool]
    : [
        `IAST is not applicable to ${input.language}: it has no managed-runtime hook point.`,
        "Use DAST and coverage-guided fuzzing for native code instead.",
      ];
  return {
    tool: input.tool,
    language: input.language,
    framework,
    setup_steps: setupSteps(input.tool, input.language),
    instrumentation: instrumentationFor(input.tool, input.language, framework),
    ci_integration: ciIntegration(input.language),
    coverage_guidance: COVERAGE_GUIDANCE,
    supported,
    notes,
    references: REFERENCES[input.tool],
  };
}
