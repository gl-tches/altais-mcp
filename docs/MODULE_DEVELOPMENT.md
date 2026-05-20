# Module Development Guide

This guide explains how to add a new module to altais-mcp. It covers the `ModuleDefinition` contract, the standard module file layout, the `ToolDefinition` shape and required annotations, deterministic finding IDs, Zod input-schema conventions, registration in the server entry point and config schema, testing expectations, and the lint/build gates.

The `container` module (`src/modules/container/`) is used as the worked example throughout — it is small, self-contained, and exercises the full pattern.

Before starting, read [`CLAUDE.md`](../CLAUDE.md) — its **MCP Server Security Rules** and **Code Conventions** are non-negotiable and apply to every module.

---

## 1. The `ModuleDefinition` contract

Every module exports a factory function that returns a `ModuleDefinition` (defined in `src/core/types.ts`):

```typescript
export interface ModuleDefinition {
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly dependencies?: readonly string[];
  readonly tools: readonly ToolDefinition[];
  readonly init: (config: ModuleConfig) => Promise<void> | void;
}
```

| Field          | Rule                                                                                                            |
| -------------- | --------------------------------------------------------------------------------------------------------------- |
| `name`         | snake_case, must match the key in `[modules]` config (e.g. `container`, `supply_chain`, `ml_security`).          |
| `description`  | One concise sentence describing what the module audits — surfaces in module listings.                           |
| `version`      | Semantic version string for the module (the `container` module is `0.3.0`, matching its delivery phase).        |
| `dependencies` | Optional array of other module names. The registry topologically sorts and initializes dependencies first.      |
| `tools`        | The module's `ToolDefinition[]`. Tool names are `altais_{action}_{resource}` in snake_case.                     |
| `init`         | Called once before tool registration. Use it to load bundled data (CWE DB, OSV snapshot). May be a sync no-op.  |

The factory takes a `deps` object — at minimum the shared session `FindingStore`, plus any config the module needs. The `container` module:

```typescript
export interface ContainerModuleDeps {
  readonly findingStore: FindingStore;
}

export function createContainerModule(deps: ContainerModuleDeps): ModuleDefinition {
  const tools: readonly ToolDefinition[] = [
    buildDockerfileTool(deps),
    buildComposeTool(deps),
    buildBaseImageTool(deps),
  ];
  return {
    name: "container",
    description:
      "Container audits: Dockerfile best practices, Docker Compose misconfigurations, and base image hygiene (version / digest pinning, end-of-life images, image bloat).",
    version: "0.3.0",
    tools,
    init() {
      // No async resources to load.
    },
  };
}
```

If your module loads a bundled database, `init` becomes `async` and stores the result in a closure variable for the tool handlers to read — see how `core`, `secrets`, `owasp`, `supply_chain`, `vuln_db`, and `compliance` resolve their data lazily after `init()`.

---

## 2. Standard module file layout

Each module lives in `src/modules/<kebab-case-name>/`. Directory names are kebab-case; the module `name` is snake_case (e.g. directory `supply-chain/`, name `supply_chain`). The `container` module:

```
src/modules/container/
├── index.ts            # createContainerModule() — factory, ToolDefinitions, schemas
├── finding.ts          # buildContainerFinding() — the module's Finding builder
├── dockerfile.ts       # one analyzer per tool
├── dockerfile.test.ts  # tests live alongside the source they cover
├── compose.ts
├── compose.test.ts
├── base-image.ts
└── base-image.test.ts
```

Conventions:

- **`index.ts`** — the factory, the Zod input schemas, and the `ToolDefinition`s. It wires parsing, calls the analyzers, pushes findings to the store, and shapes the response. It contains no analysis logic itself.
- **`finding.ts`** — a `build<Module>Finding` helper that turns an analyzer's draft into a fully-formed `Finding` with a deterministic ID. Larger modules name this file `finding.ts` (container, compliance); some keep the builder inline. Prefer a dedicated `finding.ts`.
- **One analyzer file per tool** — `dockerfile.ts`, `compose.ts`, `base-image.ts`. Each exports a pure function (`auditDockerfile`, `auditCompose`, `checkBaseImage`) that takes parsed input and returns `readonly Finding[]`. Analyzers do no I/O and never touch the MCP server.
- **`*.test.ts` alongside** — `dockerfile.test.ts` sits next to `dockerfile.ts`. TypeScript files are kebab-case.

Bundled data files (if any) go in the top-level `data/` directory, not inside the module.

---

## 3. The `ToolDefinition` shape and required annotations

```typescript
export interface ToolDefinition {
  readonly name: string;
  readonly title?: string;
  readonly description: string;
  readonly inputSchema?: z.ZodRawShape;
  readonly outputSchema?: z.ZodRawShape;
  readonly annotations: ToolAnnotations;
  readonly handler: ToolHandler;
}
```

- **`name`** — `altais_{action}_{resource}`, snake_case, globally unique (e.g. `altais_audit_dockerfile`).
- **`title`** — short human-readable label.
- **`description`** — a precise description of what the tool checks. Be specific: the `container` module's Dockerfile tool enumerates "running as root, mutable / `latest` base image tags, `ADD` of remote URLs, ..." so a client's tool search can match an agent's intent.
- **`inputSchema`** — a `z.ZodRawShape` (a plain object of Zod fields, i.e. the `.shape` of a `z.object`, not the object itself). See §5.
- **`annotations`** — **mandatory and identical for every altais-mcp tool.** Define them once per module file as a constant:

```typescript
const COMMON_ANNOTATIONS = {
  readOnlyHint: true,      // altais-mcp only analyzes — it never modifies code
  destructiveHint: false,  // no tool performs a destructive action
  idempotentHint: true,    // same input always yields the same output
  openWorldHint: false,    // no tool reaches an external system
} as const;
```

These four values are non-negotiable: altais-mcp is read-only, non-destructive, idempotent, and closed-world. A tool that cannot honestly declare all four does not belong in altais-mcp.

A `container` tool definition:

```typescript
function buildDockerfileTool(deps: ContainerModuleDeps): ToolDefinition {
  return {
    name: "altais_audit_dockerfile",
    title: "Audit a Dockerfile",
    description: "Analyze a Dockerfile for security best-practice violations: ...",
    inputSchema: dockerfileSchema.shape,
    annotations: COMMON_ANNOTATIONS,
    handler: makeRunner(deps, zodParser(dockerfileSchema), (d) => auditDockerfile(d)),
  };
}
```

The handler must never throw. Catch every error and return a structured result with `isError: true` and an actionable message. Most modules use a small `makeRunner` / `zodParser` pair (see the `container` module) that parses input, returns a sanitized `errorResult` on a Zod failure, runs the analyzer, pushes findings to the store, and returns the `summary` + `findings` JSON.

---

## 4. Deterministic finding IDs and the `build<Module>Finding` helper

Every finding ID is `{module}:{rule}:{contentHash}`. The hash is a truncated SHA-256 over the module, rule, location, and evidence — so re-scanning identical input yields an identical ID and duplicate scans never produce duplicate findings. This is implemented once in `src/core/utils.ts`:

```typescript
export function findingId(
  module: string,
  rule: string,
  location: FindingLocation | undefined,
  evidence: string | undefined,
): string;
```

**Never construct an ID by hand.** Each module wraps `findingId` in a `build<Module>Finding` helper that fills in the module name, default tags, and `status`. The `container` module's `buildContainerFinding` (`src/modules/container/finding.ts`):

```typescript
export function buildContainerFinding(
  draft: ContainerFindingDraft,
  filename: string | undefined,
): Finding {
  const location: FindingLocation | undefined =
    filename !== undefined
      ? { file: filename, line_start: draft.line ?? 1, ...(draft.column !== undefined ? { column: draft.column } : {}) }
      : undefined;
  return {
    id: findingId("container", draft.rule, location, draft.evidence ?? ""),
    module: "container",
    rule: draft.rule,
    severity: draft.severity,
    cwe: draft.cwe,
    title: draft.title,
    description: draft.description,
    ...(location !== undefined ? { location } : {}),
    ...(draft.evidence !== undefined ? { evidence: draft.evidence } : {}),
    remediation: draft.remediation,
    references: draft.references,
    tags: ["container", ...(draft.tags ?? [])],
    status: "open",
  };
}
```

Your analyzer builds a `<Module>FindingDraft` (rule, severity, title, description, remediation, cwe, references, optional evidence/tags/line/column) and passes it through this helper. A `Finding` (see `src/core/types.ts`) must always have `id`, `module`, `rule`, `severity`, `title`, `description`, `remediation`, `references`, `tags`, and `status`; `cwe`, `cvss`, `cvss_version`, `location`, and `evidence` are optional.

Notes:

- **Redact secrets in `evidence`.** Never echo a literal credential or PII value — store a short masked form (the `secrets` and `data` modules do this).
- **`status` starts as `"open"`.** Other statuses (`confirmed`, `false_positive`, `mitigated`) are for downstream tracking.
- Push findings into the shared store with `deps.findingStore.addMany(findings)` so `altais_report` and `altais_risk_summary` can aggregate them. Pure generator/lookup tools (`testing`, parts of `incident`/`runtime`/`vuln_db`) intentionally do **not** push findings — they return a self-contained artifact.

---

## 5. Zod input-schema conventions

**Every tool input must use a Zod schema, and every field must carry explicit constraints.** No raw, unbounded string ever reaches a filesystem, parser, or analyzer. This is MCP Security Rule 1.

- **Strings:** always `.min()` and `.max()`. File content fields cap at a sensible byte limit (the `container` module uses `512 * 1024`); filenames at `512`.
- **Arrays:** always `.max()` on the array, and `.min()`/`.max()` on the element type.
- **Numbers:** `.int()` where integral, and explicit `.min()`/`.max()`.
- **Closed value sets:** use `z.enum([...])`, never a free string.
- **`.describe()` every field.** The description is surfaced to the agent and must explain what the field is for.

The `container` module's shared fields and a tool schema:

```typescript
const filenameField = z
  .string().min(1).max(512).optional()
  .describe("Optional filename used for the finding location.");

const fileContentField = z
  .string().min(1).max(512 * 1024)
  .describe("Full text of the file to audit.");

const dockerfileSchema = z.object({
  content: fileContentField,
  filename: filenameField,
});
```

Pass `someSchema.shape` (the `ZodRawShape`) as `inputSchema` — the SDK validates the raw arguments against it before your handler runs. Re-parse inside the handler with `someSchema.safeParse(args)` so you get a typed object and can return a sanitized error on failure.

For a tool that reads from disk, follow the `scan` module's `altais_scan_file`: resolve with `path.resolve()`, canonicalize with `realpath()` to defeat symlinks, and reject any path outside the configured `scan_root` before reading. Container, IaC, and most other modules avoid this entirely by accepting file *content* as a string input rather than a path.

---

## 6. Registering the module

Two edits wire a new module into the server. (These touch source files — only do them when actually adding a module.)

### 6.1 Register in `src/index.ts`

1. Import the factory near the other module imports:

   ```typescript
   import { createContainerModule } from "./modules/container/index.js";
   ```

   (Note the `.js` extension — altais-mcp is ES modules; imports use `.js` even though the source is `.ts`.)

2. Construct it inside `loadEnabledModules()`, passing the shared dependencies:

   ```typescript
   createContainerModule({
     findingStore: deps.findingStore,
   }),
   ```

3. Add a one-line summary to `MODULE_DESCRIPTIONS`, keyed by the module's `name`. This feeds the `instructions` field of the MCP `InitializeResult` so tool search can surface your tools:

   ```typescript
   container:
     "altais_audit_dockerfile (root user, unpinned base, ADD/curl-pipe-shell, secrets in ENV/ARG), altais_audit_compose (...), altais_check_base_image (...)",
   ```

The registry only *activates* a loaded module when its config flag is enabled, so it is safe to always construct it in `loadEnabledModules()`.

### 6.2 Add the config toggle in `src/config.ts`

Add a boolean to `modulesSchema`. Default modules are `true`; new modules are almost always opt-in, so default to `false`:

```typescript
const modulesSchema = z
  .object({
    // ...
    container: z.boolean().default(false),
    // ...
  })
  .prefault({});
```

If the module needs its own configuration section, add a dedicated schema (like `scanSchema`, `iacSchema`, `agenticSchema`) and reference it from `configSchema`. Document the new keys in `altais.config.toml` with their defaults.

Also tick the relevant box in the **PR Checklist** in `CLAUDE.md`: every Zod schema constrained, no code execution, no network calls, no secrets, accurate annotations, actionable errors, deterministic IDs, tests pass, build succeeds, `npm audit` clean, and the `instructions` field updated.

---

## 7. Testing expectations

Tests use Vitest and live alongside the source: `dockerfile.test.ts` next to `dockerfile.ts`.

- **Cover every analyzer.** Each `*.ts` analyzer gets a `*.test.ts` with positive cases (a misconfiguration is flagged with the expected `rule` and `severity`) and negative cases (clean input produces no finding).
- **Assert deterministic IDs.** Verify that scanning the same input twice produces the same finding `id`.
- **Assert the security invariants.** Confirm tools never throw on malformed input (they return `isError: true`) and that secret/PII evidence is redacted.
- **Eval questions.** Per `CLAUDE.md`, every module ships 10+ eval questions in Phase 6 (`evals/`).
- **Integration.** `src/integration.test.ts` connects an MCP `Client` to the server over `InMemoryTransport` and exercises every active tool end-to-end; new tools should be reachable through it.

Run the suite with `npm test`.

---

## 8. Lint and build gates

Before opening a PR, all of the following must pass:

```bash
npm run build         # tsc -p tsconfig.build.json — strict mode, must compile clean
npm test              # vitest run — all tests pass
npm run lint          # typescript-eslint strict — no warnings
npm run format:check  # prettier --check — formatting is clean
npm audit             # no high/critical advisories
```

TypeScript conventions enforced by these gates: strict mode, ES modules with `.js` import extensions, **no `any`** (use `unknown` and narrow), explicit return types on every function, `interface` for object shapes. Commit messages follow `module(scope): description` — for a new module, `container(module): add container audit module`.

---

## 9. Packaging strategy

altais-mcp currently ships as a **single npm package** (`altais-mcp`) that bundles all 24 modules; users select which modules load via `altais.config.toml`. A recurring roadmap question — noted in `altais-mcp-architecture.md` — is whether to split into **scoped packages** (`@altais/core`, `@altais/scan`, `@altais/supply-chain`, …) so consumers install only what they need.

### Trade-offs

**Arguments for scoped packages**

- **Smaller install surface.** A consumer who only wants `scan` and `secrets` avoids pulling code for 22 unused modules.
- **Independent versioning.** A module could ship a fix without a whole-package release.
- **Tree-shaking and bundle size.** Matters for an embedded or serverless deployment.
- **Clearer ownership.** Each package can have its own maintainers and changelog.

**Arguments against (in favor of the current single package)**

- **Operational simplicity.** One `npm install`, one version to reason about, one `package.json` to audit. This directly serves Security Rule 4 ("minimize the attack surface") — more packages means more `package.json` files and supply-chain entry points to audit.
- **The single package is already lean.** altais-mcp has only three runtime dependencies (`@modelcontextprotocol/sdk`, `smol-toml`, `zod`) and no native modules. The unused-module cost is bundled *text and JSON*, not transitive dependencies — the marginal weight of a disabled module is small.
- **Config-driven loading already solves the runtime concern.** Disabled modules are constructed but never initialized or registered; they add no tools and do no work. Users get the "only what I need" behavior at runtime without package fragmentation.
- **Coordinated releases.** Modules share `core` types, the `FindingStore`, finding-ID helpers, and CVSS scoring. A scoped split would need a tightly version-locked `@altais/core` dependency in every module package — cross-package version skew becomes a real failure mode and a real supply-chain risk.
- **Coherent security review.** A single package can be audited, signed, and released as one unit with one SBOM.

### Recommendation

**Stay with the single `altais-mcp` package for now.** Config-driven module loading already delivers the practical benefit of scoped packages (load only what you need) without the versioning, coordination, and supply-chain costs of fragmentation, and it keeps the project's own attack surface minimal — which is the point of a security tool. Revisit a scoped split only if a concrete need emerges: a much larger runtime-dependency footprint in some modules, genuinely independent release cadences, or third-party module contributions that warrant separate ownership. If a split ever happens, `@altais/core` (types, `FindingStore`, scoring, finding-ID helpers) should be carved out first, with all other packages depending on an exact pinned version of it.
