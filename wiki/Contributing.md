# Contributing to altais-mcp

Thanks for contributing. This page is the complete guide to working on
**altais-mcp** — environment setup, the **branch naming rules**, commit
conventions, and the pull-request process. Read it before you open your
first PR.

By contributing you agree that your contributions are licensed under the
project's [MIT License](../LICENSE).

---

## Table of contents

- [Ground rules](#ground-rules)
- [Development setup](#development-setup)
- [Branch naming rules](#branch-naming-rules)
- [Commit message convention](#commit-message-convention)
- [Code conventions](#code-conventions)
- [Testing requirements](#testing-requirements)
- [The MCP security rules](#the-mcp-security-rules)
- [Pull request process](#pull-request-process)
- [Adding a new module](#adding-a-new-module)

---

## Ground rules

- **`main` is protected.** Never commit directly to `main`. All work lands
  through a pull request from a feature branch.
- **One logical change per branch / PR.** Keep PRs focused and reviewable.
- **The build must stay green.** `npm run build`, `npm test`, `npm run lint`,
  `npm run format:check`, and `npm audit` all pass before a PR is merged.
- **altais-mcp is a read-only analyzer.** It must never execute, `eval`, or
  dynamically load scanned code, and it must never make network calls at
  runtime. See [the security rules](#the-mcp-security-rules).
- Be respectful in reviews and issues. Assume good intent.

---

## Development setup

Requires **Node.js >= 20** (the CI and the maintainers use Node 22).

```bash
# 1. Fork, then clone your fork
git clone <your-fork-url> altais-mcp
cd altais-mcp

# 2. Install dependencies (exact, pinned versions)
npm install

# 3. Verify a clean baseline before you change anything
npm run build        # tsc -> dist/
npm test             # vitest
npm run lint         # eslint (typescript-eslint strict)
npm run format:check # prettier
```

Useful scripts:

| Script | Purpose |
|--------|---------|
| `npm run build` | Type-check and compile to `dist/` |
| `npm test` | Run the full Vitest suite |
| `npm run lint` | ESLint (strict, type-checked) |
| `npm run format` | Auto-format with Prettier |
| `npm run format:check` | Verify formatting (CI gate) |
| `npm start` | Run the built server (`dist/index.js`) |

---

## Branch naming rules

Every contribution happens on its own branch, created from an up-to-date
`main`. Branch names are **mechanically checked** in review — a PR from a
non-conforming branch will be asked to rename.

### Format

```
<type>/<short-description>
```

or, when the work tracks an issue:

```
<type>/<issue-number>-<short-description>
```

- Exactly **one** `/` — the `<type>` segment, then the description.
- **Lowercase ASCII, kebab-case** (words joined by single hyphens).
- **No** spaces, underscores, uppercase letters, or `..`.
- Keep it short: aim for **≤ 50 characters** and **≤ 6 words** of description.
- The description summarizes the change, not the file names.

### Allowed `<type>` values

| Type | Use for |
|------|---------|
| `feat` | A new feature or capability in an existing module |
| `fix` | A bug fix |
| `module` | Adding a whole new module (see [Adding a new module](#adding-a-new-module)) |
| `docs` | Documentation only (README, the wiki, code comments) |
| `test` | Tests only — no production-code change |
| `refactor` | Restructuring with no behavior change |
| `perf` | A performance improvement |
| `security` | A security fix to altais-mcp itself (coordinate first — see [SECURITY.md](../SECURITY.md)) |
| `chore` | Tooling, dependencies, repo configuration |
| `ci` | CI/CD pipeline changes |

### Examples

```
feat/graphql-cost-analysis
fix/jwt-alg-none-false-negative
module/sca-graph
docs/project-wiki
test/auth-rbac-edge-cases
refactor/scan-engine-line-offsets
chore/bump-zod-4-4-4
security/redact-error-paths
feat/142-host-header-cache-key        # references issue #142
```

Not acceptable: `Feature/NewThing`, `fix_bug`, `my-branch`, `patch-1`,
`feat/add-the-new-graphql-query-depth-and-cost-analysis-checks`.

### Historical note — the `phase-N/...` scheme

altais-mcp v0.1.0 → v1.0.0 was built in six numbered phases, and that work
used release-phase branches: `phase-<n>/<task-range>-<topic>` (for example
`phase-3/3.3-container-module`, `phase-5/advanced`). That scheme is
**retired** now that v1.0 has shipped. New contributions use the
`<type>/<short-description>` scheme above.

---

## Commit message convention

Commits follow the project format:

```
module(scope): description
```

- **`module`** — the conventional change category: the affected module name
  (`scan`, `auth`, `crypto`, …) or one of `core`, `infra`, `docs`, `ci`.
- **`scope`** — the narrower area, often a sub-component (`patterns`,
  `transport`, `report`). Use the module name again if there is no narrower
  scope.
- **`description`** — lowercase, **imperative mood**, **no trailing period**.
- Reference issues when applicable: `scan(patterns): add CRLF injection (#42)`.

Examples:

```
scan(patterns): add prototype-pollution detection
auth(jwt): reject tokens with alg confusion
core(transport): require a bearer token on HTTP requests
docs(wiki): add per-tool reference pages
```

Keep the subject line ≤ ~72 characters; put detail in the body. If an AI
assistant co-authored the change, keep its `Co-Authored-By:` trailer.

---

## Code conventions

TypeScript, strict throughout:

- `"strict": true`; **no `any`** — use `unknown` and narrow with type guards.
- **Explicit return types** on every function.
- ES modules only — include the `.js` extension in import paths.
- Prefer `interface` over `type` for object shapes.
- **Naming:** tool names `altais_{action}_{resource}` (snake_case); module
  directories kebab-case; config keys snake_case; TypeScript files
  kebab-case; types/interfaces PascalCase; constants SCREAMING_SNAKE_CASE.
- ESLint runs `typescript-eslint` **strict + stylistic, type-checked**.
  Formatting is Prettier — run `npm run format` before committing.
- Pin exact dependency versions (no `^` / `~`). Keep runtime dependencies
  minimal; no native modules.

---

## Testing requirements

- Unit tests with **Vitest**, co-located with the source
  (`foo.ts` → `foo.test.ts`).
- Every new tool needs tests — **positive and negative** cases, a
  determinism check (same input → same finding IDs), and a shape check
  (correct `module`, a CWE, correct tags).
- Findings must use **deterministic IDs** (`{module}:{rule}:{contentHash}`).
- A PR must not lower coverage of the area it touches. The full suite must
  pass: `npm test`.

---

## The MCP security rules

altais-mcp follows nine non-negotiable security rules (full text in
[SECURITY.md](../SECURITY.md)). The ones most likely to affect a
contribution:

1. **Input validation** — every tool input is a Zod schema with explicit
   constraints (max lengths, enums, numeric ranges). No raw passthrough.
2. **No code execution** — never `eval`, `new Function`, `vm.*`,
   `child_process.exec`, or `import()` of scanned input.
3. **No runtime network calls** — analysis is local; bundled databases ship
   with the package.
4. **No secrets** in source, tests, or fixtures.
5. **Transport security** — stdio logs only to stderr; HTTP binds
   `127.0.0.1`, validates `Origin`, and requires a bearer token.
6. **Output safety** — no internal paths, env vars, or stack traces in tool
   responses.
7. **Deterministic finding IDs.**
8. **Accurate tool annotations** — `readOnlyHint: true`,
   `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`.
9. **`instructions` field** kept in sync when modules change.

A PR that violates rule 2 or 3 will not be merged.

---

## Pull request process

1. **Branch** from an up-to-date `main` using the
   [naming rules](#branch-naming-rules).
2. Make your change with tests and docs.
3. Run the full local gate:
   ```bash
   npm run build && npm test && npm run lint && npm run format:check && npm audit
   ```
4. Push your branch and open a PR **against `main`**. Describe what changed
   and why; link any issue.
5. Confirm the **PR checklist**:
   - [ ] All Zod schemas have explicit constraints (max lengths, enums, ranges)
   - [ ] No `eval`, `exec`, `Function()`, or dynamic code execution
   - [ ] No network calls from tool handlers
   - [ ] No secrets or credentials in source
   - [ ] Tool annotations are accurate (`readOnlyHint: true`, `destructiveHint: false`)
   - [ ] Error messages are actionable but do not leak internals
   - [ ] Finding IDs are deterministic
   - [ ] Unit tests pass (`npm test`)
   - [ ] Build succeeds (`npm run build`)
   - [ ] `npm audit` reports no high/critical vulnerabilities
   - [ ] `instructions` field updated if tools were added or removed
6. Address review feedback. Keep the branch rebased on `main` if it drifts.
7. A maintainer merges. The branch is deleted after merge.

---

## Adding a new module

Use a `module/<name>` branch and follow the dedicated
[Module Development guide](Module-Development.md). In short: create
`src/modules/<name>/` with `finding.ts`, `index.ts`, one analyzer file per
tool, and co-located tests; register the module in `src/index.ts` (loader +
`MODULE_DESCRIPTIONS`); add its toggle to `src/config.ts` and
`altais.config.toml`; and add a wiki page under `wiki/modules/` plus a
`wiki/tools/` page for each new tool.

---

See also: [Wiki home](Home.md) · [Deployment](Deployment.md) ·
[Security policy](../SECURITY.md)
