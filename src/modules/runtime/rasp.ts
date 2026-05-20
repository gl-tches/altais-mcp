// RASP recommendation generator (altais_recommend_rasp).
//
// Given an application's language, framework, deployment model, and the
// team's risk tolerance, this generator recommends a Runtime Application
// Self-Protection configuration: the product category to evaluate, the
// protections to enable, agent/instrumentation steps for the stack,
// blocking-vs-monitoring guidance, and performance considerations. It is
// a pure function that returns an artifact; it pushes no Finding objects.

export type RaspLanguage = "java" | "dotnet" | "node" | "python" | "ruby" | "go";

export type RaspDeployment = "container" | "vm" | "serverless";

export type RaspRiskTolerance = "low" | "medium" | "high";

export interface RaspGeneratorInput {
  readonly language: RaspLanguage;
  readonly framework: string;
  readonly deployment: RaspDeployment;
  readonly risk_tolerance: RaspRiskTolerance;
}

export interface RaspProtection {
  readonly name: string;
  readonly cwe: readonly string[];
  /** Recommended enforcement: "block" or "monitor". */
  readonly mode: "block" | "monitor";
  readonly rationale: string;
}

export interface RaspGeneratorResult {
  readonly language: RaspLanguage;
  readonly framework: string;
  readonly deployment: RaspDeployment;
  readonly risk_tolerance: RaspRiskTolerance;
  readonly product_category: string;
  readonly instrumentation: string;
  readonly setup_steps: readonly string[];
  readonly protections: readonly RaspProtection[];
  readonly blocking_guidance: string;
  readonly performance_considerations: readonly string[];
  readonly references: readonly string[];
}

const REFERENCES: readonly string[] = [
  "https://owasp.org/www-community/Runtime_Application_Self_Protection",
  "https://owasp.org/Top10/A03_2021-Injection/",
  "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
  "https://cwe.mitre.org/data/definitions/502.html",
];

interface LanguageProfile {
  /** The agent attachment / instrumentation mechanism for the stack. */
  readonly instrumentation: string;
  /** Whether unsafe deserialization is a first-class risk for the stack. */
  readonly deserializationRisk: boolean;
  readonly setup: readonly string[];
}

const LANGUAGE_PROFILES: Readonly<Record<RaspLanguage, LanguageProfile>> = {
  java: {
    instrumentation:
      "JVM bytecode instrumentation via a `-javaagent:` Java agent attached at process start.",
    deserializationRisk: true,
    setup: [
      "Add the RASP agent JAR to the image / host and reference it with `-javaagent:/opt/rasp/agent.jar` in `JAVA_OPTS`.",
      "Confirm the agent attaches before the application server (Tomcat / Spring Boot embedded) initializes.",
      "Restart the JVM — agents cannot be hot-attached safely in production.",
    ],
  },
  dotnet: {
    instrumentation:
      "CLR profiling via the .NET Profiler API (`CORECLR_ENABLE_PROFILING`) plus a managed RASP assembly.",
    deserializationRisk: true,
    setup: [
      "Set `CORECLR_ENABLE_PROFILING=1`, `CORECLR_PROFILER`, and `CORECLR_PROFILER_PATH` for the worker process.",
      "Deploy the RASP profiler DLL alongside the application and grant the runtime read access.",
      "Recycle the application pool / Kestrel host so the profiler loads at startup.",
    ],
  },
  node: {
    instrumentation:
      "Module-loader hooks and async-hook instrumentation loaded via `--require` (or `NODE_OPTIONS`) before application code.",
    deserializationRisk: false,
    setup: [
      "Add `--require @vendor/rasp/register` to the Node start command or `NODE_OPTIONS`.",
      "Ensure the RASP package is the first module required so it can wrap `http`, `fs`, and `child_process`.",
      "Restart the Node process; verify the RASP banner appears on stderr at boot.",
    ],
  },
  python: {
    instrumentation:
      "Import hooks and a `sitecustomize` / `.pth` bootstrap that patches WSGI/ASGI entrypoints before the app loads.",
    deserializationRisk: true,
    setup: [
      "Install the RASP package into the application virtual environment.",
      "Enable the bootstrap via the vendor `rasp-run` wrapper or a `.pth` file on `sys.path`.",
      "Restart the WSGI / ASGI server (Gunicorn / Uvicorn) so the import hooks take effect.",
    ],
  },
  ruby: {
    instrumentation:
      "Rack middleware plus method instrumentation loaded from a Bundler `require` in `config/application.rb`.",
    deserializationRisk: true,
    setup: [
      "Add the RASP gem to the `Gemfile` and run `bundle install`.",
      "Require the gem early in `config/application.rb` so it inserts its Rack middleware.",
      "Restart the application server (Puma) to load the instrumentation.",
    ],
  },
  go: {
    instrumentation:
      "Compile-time SDK integration: Go has no runtime agent, so RASP is added as middleware / wrapped standard-library calls linked into the binary.",
    deserializationRisk: false,
    setup: [
      "Add the RASP SDK as a Go module dependency (`go get`).",
      "Wrap the HTTP handler / router with the RASP middleware and use the SDK's safe wrappers for `os/exec` and `database/sql`.",
      "Rebuild and redeploy the binary — there is no drop-in agent for Go.",
    ],
  },
};

interface DeploymentProfile {
  readonly note: string;
  readonly performance: readonly string[];
}

const DEPLOYMENT_PROFILES: Readonly<Record<RaspDeployment, DeploymentProfile>> = {
  container: {
    note: "Bake the agent into the container image as an immutable layer; do not download it at runtime (CLAUDE.md / supply-chain hygiene).",
    performance: [
      "Add the agent layer to the image build so cold starts are not delayed by a runtime download.",
      "Budget roughly 30-80 MB extra memory per container for the agent; size container limits accordingly.",
      "Expect 2-8% request-latency overhead under typical load; benchmark against the application's SLO.",
    ],
  },
  vm: {
    note: "Install the agent via the host's configuration-management tooling and pin its version alongside the application.",
    performance: [
      "Pin the agent version in configuration management so fleet hosts stay consistent.",
      "Expect 2-8% request-latency overhead; verify headroom on long-running VMs before enforcing.",
      "Schedule agent updates with the normal patch window — a JVM/CLR agent change requires a process restart.",
    ],
  },
  serverless: {
    note: "Use a RASP build that supports a Lambda layer / extension; full instrumentation agents often do not fit the serverless cold-start budget.",
    performance: [
      "Prefer a lightweight RASP layer / extension — heavy bytecode agents inflate cold-start time significantly.",
      "Measure the cold-start penalty; if it exceeds the function's latency budget, fall back to monitor-only mode.",
      "Provisioned concurrency hides agent init cost but raises baseline spend — weigh the trade-off.",
    ],
  },
};

interface ProtectionSpec {
  readonly name: string;
  readonly cwe: readonly string[];
  readonly rationale: string;
  /** True when this protection only applies to deserialization-prone stacks. */
  readonly deserializationOnly?: boolean;
}

const PROTECTION_SPECS: readonly ProtectionSpec[] = [
  {
    name: "Unsafe deserialization protection",
    cwe: ["CWE-502"],
    rationale:
      "Blocks gadget-chain exploitation when untrusted data reaches a native deserializer — the highest-impact class for JVM/CLR/Ruby/Python stacks.",
    deserializationOnly: true,
  },
  {
    name: "OS command-injection protection",
    cwe: ["CWE-78"],
    rationale:
      "Intercepts process-spawn calls and blocks execution when attacker-controlled input reaches the command line.",
  },
  {
    name: "SQL-injection protection",
    cwe: ["CWE-89"],
    rationale:
      "Correlates request parameters with the executed SQL statement to catch injection that bypasses input validation.",
  },
  {
    name: "Path-traversal / arbitrary file access protection",
    cwe: ["CWE-22"],
    rationale:
      "Blocks file-system calls that resolve outside the application's intended directory scope.",
  },
  {
    name: "Server-side request forgery protection",
    cwe: ["CWE-918"],
    rationale:
      "Blocks outbound requests from the app to internal / metadata endpoints driven by attacker-controlled URLs.",
  },
];

/**
 * Risk tolerance drives how aggressively protections are enforced and
 * which RASP product tier to evaluate.
 */
function modeForProtection(spec: ProtectionSpec, risk: RaspRiskTolerance): "block" | "monitor" {
  // Deserialization and command injection are catastrophic; block them
  // unless the team has explicitly accepted high risk (e.g. cannot
  // tolerate any false-positive request blocks).
  const isCatastrophic = spec.cwe.includes("CWE-502") || spec.cwe.includes("CWE-78");
  switch (risk) {
    case "low":
      return "block";
    case "medium":
      return isCatastrophic ? "block" : "monitor";
    case "high":
      return "monitor";
  }
}

const PRODUCT_CATEGORY: Readonly<Record<RaspRiskTolerance, string>> = {
  low: "A full enforcing RASP / IAST-capable platform with in-line blocking and SIEM export. Evaluate enterprise RASP suites that support automatic enforcement.",
  medium:
    "A RASP platform that supports per-rule block/monitor tuning, so catastrophic classes can enforce while noisier rules stay in monitor mode.",
  high: "A monitor-first RASP or application-runtime observability product. Use it to gather evidence and tune before enabling any in-line blocking.",
};

export function recommendRasp(input: RaspGeneratorInput): RaspGeneratorResult {
  const langProfile = LANGUAGE_PROFILES[input.language];
  const deployProfile = DEPLOYMENT_PROFILES[input.deployment];

  const protections: readonly RaspProtection[] = PROTECTION_SPECS.filter(
    (spec) => spec.deserializationOnly !== true || langProfile.deserializationRisk,
  ).map((spec) => ({
    name: spec.name,
    cwe: spec.cwe,
    mode: modeForProtection(spec, input.risk_tolerance),
    rationale: spec.rationale,
  }));

  const setupSteps: readonly string[] = [...langProfile.setup, deployProfile.note];

  const blockingByRisk: Readonly<Record<RaspRiskTolerance, string>> = {
    low: "Risk tolerance is low: enable in-line blocking for every protection from day one. Accept that a small false-positive rate is preferable to an exploited vulnerability, and keep an allowlist process for any legitimate request that trips a rule.",
    medium:
      "Risk tolerance is medium: block the catastrophic classes (unsafe deserialization, command injection) immediately and run the remaining protections in monitor mode. Promote each rule to blocking once a tuning window confirms a low false-positive rate.",
    high: "Risk tolerance is high (availability-sensitive): start every protection in monitor mode. Use the collected telemetry to tune signatures, then promote rules to blocking one at a time, beginning with unsafe deserialization.",
  };

  return {
    language: input.language,
    framework: input.framework,
    deployment: input.deployment,
    risk_tolerance: input.risk_tolerance,
    product_category: PRODUCT_CATEGORY[input.risk_tolerance],
    instrumentation: langProfile.instrumentation,
    setup_steps: setupSteps,
    protections,
    blocking_guidance: blockingByRisk[input.risk_tolerance],
    performance_considerations: deployProfile.performance,
    references: REFERENCES,
  };
}
