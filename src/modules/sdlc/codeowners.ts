// CODEOWNERS auditor (altais_check_codeowners).
//
// Parses a CODEOWNERS file and verifies that security-sensitive paths
// each have a required reviewer, that a catch-all rule exists, and that
// no rule is missing an actual owner.

import type { Finding } from "../../core/types.js";
import { buildSdlcFinding } from "./finding.js";

export interface CodeownersAuditInput {
  readonly content: string;
  readonly sensitive_paths?: readonly string[];
  readonly filename?: string;
}

const REFS = [
  "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
  "https://cwe.mitre.org/data/definitions/1220.html",
  "https://cwe.mitre.org/data/definitions/284.html",
];

const DEFAULT_SENSITIVE_PATHS: readonly string[] = [
  "auth",
  "crypto",
  "security",
  ".github/workflows",
  "ci",
  "infra",
  "deploy",
  "iam",
  "secrets",
  "Dockerfile",
];

interface OwnerRule {
  readonly pattern: string;
  readonly owners: readonly string[];
  readonly line: number;
}

const OWNER_TOKEN_RE = /^(?:@[A-Za-z0-9][\w/-]*|[^@\s]+@[^@\s]+\.[^@\s]+)$/;

/** Parse a CODEOWNERS file body into pattern/owner rules. */
export function parseCodeowners(content: string): readonly OwnerRule[] {
  const rules: OwnerRule[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] ?? "";
    const noComment = raw.replace(/#.*$/, "");
    const trimmed = noComment.trim();
    if (trimmed === "") continue;
    const tokens = trimmed.split(/\s+/).filter((t) => t.length > 0);
    const pattern = tokens[0];
    if (pattern === undefined) continue;
    rules.push({ pattern, owners: tokens.slice(1), line: i + 1 });
  }
  return rules;
}

/** Does any rule's pattern plausibly cover `path`? */
function pathCovered(rules: readonly OwnerRule[], path: string): OwnerRule | undefined {
  const needle = path.toLowerCase().replace(/^\/+/, "").replace(/\/+$/, "");
  for (const rule of rules) {
    const pat = rule.pattern
      .toLowerCase()
      .replace(/^\/+/, "")
      .replace(/\*+$/, "")
      .replace(/\/+$/, "");
    if (rule.owners.length === 0) continue;
    if (pat === "" || pat === "*") continue; // catch-all handled separately
    if (pat === needle) return rule;
    if (needle.startsWith(`${pat}/`)) return rule;
    if (pat.startsWith(`${needle}/`)) return rule;
    if (pat.includes(needle) || needle.includes(pat)) return rule;
  }
  return undefined;
}

function mk(
  input: CodeownersAuditInput,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  line: number | undefined,
): Finding {
  return buildSdlcFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["codeowners", "access-control"],
      ...(line !== undefined ? { line } : {}),
    },
    input.filename ?? "CODEOWNERS",
  );
}

export function checkCodeowners(input: CodeownersAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const rules = parseCodeowners(input.content);
  const sensitivePaths =
    input.sensitive_paths !== undefined && input.sensitive_paths.length > 0
      ? input.sensitive_paths
      : DEFAULT_SENSITIVE_PATHS;

  // Rules that name a pattern but no owner.
  for (const rule of rules) {
    if (rule.owners.length === 0) {
      findings.push(
        mk(
          input,
          "codeowners-rule-without-owner",
          "medium",
          `CODEOWNERS rule for \`${rule.pattern}\` has no owner`,
          "A pattern with no owner unsets ownership for the matched paths: changes there require no required reviewer, silently weakening review coverage for everything the pattern matches.",
          "Add at least one team or user owner to the rule, or remove the rule if the unset is unintended.",
          ["CWE-1220", "CWE-284"],
          rule.pattern,
          rule.line,
        ),
      );
    } else {
      for (const owner of rule.owners) {
        if (!OWNER_TOKEN_RE.test(owner)) {
          findings.push(
            mk(
              input,
              "codeowners-malformed-owner",
              "low",
              `CODEOWNERS rule for \`${rule.pattern}\` has a malformed owner \`${owner}\``,
              "An owner token that is not a `@user`, `@org/team`, or email address is not a valid owner. The forge ignores it, so the rule may resolve to fewer required reviewers than intended.",
              "Use a valid owner reference: `@username`, `@org/team`, or an email address registered with the forge.",
              ["CWE-1220"],
              `${rule.pattern} ${owner}`,
              rule.line,
            ),
          );
        }
      }
    }
  }

  // Catch-all `*` rule.
  const catchAll = rules.find((r) => r.pattern === "*" && r.owners.length > 0);
  if (catchAll === undefined) {
    findings.push(
      mk(
        input,
        "codeowners-no-catch-all",
        "medium",
        "CODEOWNERS has no catch-all `*` rule",
        "Without a catch-all `*` rule, any path not matched by a specific rule has no code owner, so changes there can merge with no required review.",
        "Add a final `* @org/default-team` rule so every path has a default required reviewer.",
        ["CWE-1220", "CWE-284"],
        "no `*` rule",
        undefined,
      ),
    );
  }

  // Sensitive paths with no specific owner rule.
  for (const path of sensitivePaths) {
    const covering = pathCovered(rules, path);
    if (covering === undefined) {
      findings.push(
        mk(
          input,
          "codeowners-sensitive-path-uncovered",
          "high",
          `Security-sensitive path \`${path}\` has no specific CODEOWNERS rule`,
          "A security-sensitive path with no dedicated owner rule is only protected by the catch-all (if any). Changes to authentication, cryptography, CI, or infrastructure should require review by a domain owner, not just any reviewer.",
          `Add a CODEOWNERS rule that assigns \`${path}\` to the team responsible for that domain.`,
          ["CWE-1220", "CWE-284"],
          path,
          undefined,
        ),
      );
    }
  }

  // Info: a single owner covers every rule — a bus-factor / availability risk.
  const ownersWithRules = rules.filter((r) => r.owners.length > 0);
  if (ownersWithRules.length > 0) {
    const distinctOwners = new Set<string>();
    for (const rule of ownersWithRules) {
      for (const owner of rule.owners) distinctOwners.add(owner.toLowerCase());
    }
    if (distinctOwners.size === 1 && ownersWithRules.length >= 2) {
      const only = [...distinctOwners][0] ?? "";
      findings.push(
        mk(
          input,
          "codeowners-single-owner-coverage",
          "info",
          `A single owner \`${only}\` is the sole reviewer for every CODEOWNERS rule`,
          "When one user or team owns every path, that owner is a single point of failure for reviews: their absence blocks all merges, and a compromise of that one account defeats required-review across the whole repository.",
          "Distribute ownership across multiple teams so no single owner gates every change, and prefer team owners over individual users.",
          ["CWE-1220"],
          only,
          undefined,
        ),
      );
    }
  }

  return findings;
}
