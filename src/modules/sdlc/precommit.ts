// Pre-commit hook configuration generator (altais_generate_precommit).
//
// Produces a ready-to-use `.pre-commit-config.yaml` body that wires the
// requested security and quality checks. This is a generator: it returns
// an artifact as structured data and does not push Finding objects.

export type PrecommitCheck =
  | "secrets"
  | "lint"
  | "format"
  | "sast"
  | "dependency-audit"
  | "large-files"
  | "private-key";

export interface PrecommitConfig {
  readonly languages: readonly string[];
  readonly checks: readonly PrecommitCheck[];
}

export interface PrecommitArtifact {
  readonly filename: string;
  readonly checks: readonly PrecommitCheck[];
  readonly languages: readonly string[];
  readonly hooks: readonly string[];
  readonly content: string;
  readonly notes: readonly string[];
}

interface RepoBlock {
  readonly repo: string;
  readonly rev: string;
  readonly hookLines: readonly string[];
  readonly hookIds: readonly string[];
}

const LANGUAGE_LINTERS: Readonly<Record<string, RepoBlock>> = {
  python: {
    repo: "https://github.com/astral-sh/ruff-pre-commit",
    rev: "v0.6.9",
    hookLines: ["      - id: ruff", "        args: [--fix]", "      - id: ruff-format"],
    hookIds: ["ruff", "ruff-format"],
  },
  javascript: {
    repo: "https://github.com/pre-commit/mirrors-eslint",
    rev: "v9.12.0",
    hookLines: ["      - id: eslint"],
    hookIds: ["eslint"],
  },
  typescript: {
    repo: "https://github.com/pre-commit/mirrors-eslint",
    rev: "v9.12.0",
    hookLines: ["      - id: eslint"],
    hookIds: ["eslint"],
  },
  go: {
    repo: "https://github.com/dnephin/pre-commit-golang",
    rev: "v0.5.1",
    hookLines: ["      - id: go-fmt", "      - id: go-vet"],
    hookIds: ["go-fmt", "go-vet"],
  },
  rust: {
    repo: "https://github.com/doublify/pre-commit-rust",
    rev: "v1.0",
    hookLines: ["      - id: fmt", "      - id: clippy"],
    hookIds: ["fmt", "clippy"],
  },
  ruby: {
    repo: "https://github.com/rubocop/rubocop",
    rev: "v1.66.1",
    hookLines: ["      - id: rubocop"],
    hookIds: ["rubocop"],
  },
};

function renderBlock(block: RepoBlock): string {
  return [
    `  - repo: ${block.repo}`,
    `    rev: ${block.rev}`,
    "    hooks:",
    ...block.hookLines,
  ].join("\n");
}

/** Generate a `.pre-commit-config.yaml` body for the requested checks. */
export function generatePrecommit(config: PrecommitConfig): PrecommitArtifact {
  const checks = [...new Set(config.checks)];
  const languages = [...new Set(config.languages.map((l) => l.toLowerCase()))];
  const blocks: string[] = [];
  const hookIds: string[] = [];
  const notes: string[] = [];

  // pre-commit-hooks: general hygiene (large files, private keys).
  const baseHooks: string[] = [];
  if (checks.includes("large-files")) {
    baseHooks.push("      - id: check-added-large-files", "        args: [--maxkb=500]");
    hookIds.push("check-added-large-files");
  }
  if (checks.includes("private-key")) {
    baseHooks.push("      - id: detect-private-key");
    hookIds.push("detect-private-key");
  }
  if (baseHooks.length > 0) {
    blocks.push(
      [
        "  - repo: https://github.com/pre-commit/pre-commit-hooks",
        "    rev: v5.0.0",
        "    hooks:",
        ...baseHooks,
      ].join("\n"),
    );
  }

  // Secret scanning.
  if (checks.includes("secrets")) {
    blocks.push(
      [
        "  - repo: https://github.com/gitleaks/gitleaks",
        "    rev: v8.21.1",
        "    hooks:",
        "      - id: gitleaks",
      ].join("\n"),
    );
    blocks.push(
      [
        "  - repo: https://github.com/Yelp/detect-secrets",
        "    rev: v1.5.0",
        "    hooks:",
        "      - id: detect-secrets",
        "        args: [--baseline, .secrets.baseline]",
      ].join("\n"),
    );
    hookIds.push("gitleaks", "detect-secrets");
    notes.push(
      "Run `detect-secrets scan > .secrets.baseline` once to create the baseline before enabling the hook.",
    );
  }

  // Language linters / formatters.
  if (checks.includes("lint") || checks.includes("format")) {
    for (const lang of languages) {
      const block = LANGUAGE_LINTERS[lang];
      if (block === undefined) {
        notes.push(
          `No bundled linter mapping for language \`${lang}\`; add a linter hook manually.`,
        );
        continue;
      }
      blocks.push(renderBlock(block));
      for (const id of block.hookIds) hookIds.push(id);
    }
    if (languages.length === 0) {
      notes.push("No languages supplied; specify `languages` to wire linter / formatter hooks.");
    }
  }

  // SAST.
  if (checks.includes("sast")) {
    blocks.push(
      [
        "  - repo: https://github.com/returntocorp/semgrep",
        "    rev: v1.90.0",
        "    hooks:",
        "      - id: semgrep",
        "        args: [--config, p/security-audit, --error]",
      ].join("\n"),
    );
    hookIds.push("semgrep");
    if (languages.includes("python")) {
      blocks.push(
        [
          "  - repo: https://github.com/PyCQA/bandit",
          "    rev: 1.7.10",
          "    hooks:",
          "      - id: bandit",
          "        args: [-ll]",
        ].join("\n"),
      );
      hookIds.push("bandit");
    }
  }

  // Dependency audit.
  if (checks.includes("dependency-audit")) {
    blocks.push(
      [
        "  - repo: local",
        "    hooks:",
        "      - id: dependency-audit",
        "        name: dependency-audit",
        "        entry: bash -c 'npm audit --audit-level=high || true'",
        "        language: system",
        "        pass_filenames: false",
      ].join("\n"),
    );
    hookIds.push("dependency-audit");
    notes.push(
      "Replace the dependency-audit entry with the auditor for your ecosystem (`pip-audit`, `cargo audit`, `govulncheck`).",
    );
  }

  const header = [
    "# .pre-commit-config.yaml",
    "# Generated by altais-mcp altais_generate_precommit.",
    "# Install with `pre-commit install`. See https://pre-commit.com/.",
    "minimum_pre_commit_version: 3.5.0",
    "repos:",
  ].join("\n");

  const body =
    blocks.length > 0
      ? `${header}\n${blocks.join("\n")}\n`
      : `${header}\n  # No checks selected — add hook repos here.\n`;

  return {
    filename: ".pre-commit-config.yaml",
    checks,
    languages,
    hooks: [...new Set(hookIds)],
    content: body,
    notes,
  };
}
