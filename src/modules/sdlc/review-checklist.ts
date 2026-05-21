// Security code-review checklist generator (altais_generate_review_checklist).
//
// Produces a tailored security review checklist, weighted to the kind of
// change under review and its sensitivity. This is a generator: it
// returns an artifact as structured data and does not push Finding
// objects.

import { scanToken } from "../../core/scan-patterns.js";

// Detection tokens loaded from data/scan-patterns.json so the literal API
// names are not embedded inline (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const FUNC = scanToken("js-function-constructor");
const EXEC = scanToken("shell-command");
const CHILD_PROCESS = scanToken("node-process-module");
const SUBPROCESS = scanToken("py-subprocess-module");

export type ChangeType = "feature" | "bugfix" | "dependency" | "infrastructure" | "auth" | "crypto";

export type Sensitivity = "low" | "medium" | "high";

export interface ReviewChecklistConfig {
  readonly change_type: ChangeType;
  readonly languages: readonly string[];
  readonly sensitivity: Sensitivity;
}

export interface ChecklistItem {
  readonly id: string;
  readonly category: string;
  readonly text: string;
  readonly priority: "must" | "should";
}

export interface ReviewChecklistArtifact {
  readonly change_type: ChangeType;
  readonly sensitivity: Sensitivity;
  readonly languages: readonly string[];
  readonly items: readonly ChecklistItem[];
  readonly content: string;
}

interface RawItem {
  readonly category: string;
  readonly text: string;
  readonly priority: "must" | "should";
}

const BASE_ITEMS: readonly RawItem[] = [
  {
    category: "Input validation",
    text: "Every external input is validated against an explicit allow-list of type, length, format, and range before use.",
    priority: "must",
  },
  {
    category: "Authorization",
    text: "Each new or changed entry point enforces an authorization check; the check cannot be skipped by a missing or default branch.",
    priority: "must",
  },
  {
    category: "Secrets",
    text: "No credentials, tokens, or keys are hardcoded; secrets come from the environment or a secrets manager and are absent from logs.",
    priority: "must",
  },
  {
    category: "Error handling",
    text: "Errors are caught and converted to safe messages; no stack traces, file paths, or internal state leak to the caller.",
    priority: "should",
  },
  {
    category: "Dependencies",
    text: "Any added or upgraded dependency is from a trusted source, is actively maintained, and adds no known-vulnerable transitive packages.",
    priority: "should",
  },
  {
    category: "Tests",
    text: "The change ships with tests, including a negative test for the security-relevant behavior it introduces or fixes.",
    priority: "should",
  },
  {
    category: "Logging",
    text: "Security-relevant events are logged with enough context for incident response, without recording sensitive data.",
    priority: "should",
  },
];

const TYPE_ITEMS: Readonly<Record<ChangeType, readonly RawItem[]>> = {
  feature: [
    {
      category: "Attack surface",
      text: "New endpoints, parameters, and file paths are enumerated and each one's threat exposure is considered.",
      priority: "must",
    },
    {
      category: "Least privilege",
      text: "The feature requests only the permissions, scopes, and data access it actually needs.",
      priority: "should",
    },
  ],
  bugfix: [
    {
      category: "Root cause",
      text: "The fix addresses the root cause, not just the reported symptom, and similar call sites are checked for the same defect.",
      priority: "must",
    },
    {
      category: "Regression",
      text: "A regression test reproduces the original bug and fails without the fix.",
      priority: "must",
    },
  ],
  dependency: [
    {
      category: "Supply chain",
      text: "The dependency's changelog and diff are reviewed for unexpected behavior; the version is pinned and lockfile-verified.",
      priority: "must",
    },
    {
      category: "Provenance",
      text: "The package's maintainership, signing, and download integrity (checksum / digest) are confirmed.",
      priority: "must",
    },
    {
      category: "Advisories",
      text: "The new version resolves, and introduces, no open security advisories across the full transitive tree.",
      priority: "should",
    },
  ],
  infrastructure: [
    {
      category: "Configuration",
      text: "Network exposure, IAM roles, and resource policies follow least privilege; nothing is publicly reachable unintentionally.",
      priority: "must",
    },
    {
      category: "State & secrets",
      text: "Infrastructure-as-code state and variables contain no plaintext secrets; remote state is encrypted and access-controlled.",
      priority: "must",
    },
  ],
  auth: [
    {
      category: "Authentication",
      text: "Credential handling, session lifetime, token revocation, and brute-force protection are reviewed against the threat model.",
      priority: "must",
    },
    {
      category: "Authorization",
      text: "Object-level and function-level access control is enforced server-side for every path, including the negative cases.",
      priority: "must",
    },
    {
      category: "Session",
      text: "Sessions and tokens are invalidated on logout, password change, and privilege change.",
      priority: "must",
    },
  ],
  crypto: [
    {
      category: "Algorithms",
      text: "Only current, vetted algorithms and modes are used; no MD5, SHA-1, ECB, or hand-rolled cryptography.",
      priority: "must",
    },
    {
      category: "Key management",
      text: "Keys are generated with a CSPRNG, stored in a key manager / HSM, scoped per purpose, and rotatable.",
      priority: "must",
    },
    {
      category: "Randomness",
      text: "All security-relevant randomness uses a cryptographically secure generator, not a general-purpose PRNG.",
      priority: "must",
    },
  ],
};

const SENSITIVITY_ITEMS: Readonly<Record<Sensitivity, readonly RawItem[]>> = {
  low: [],
  medium: [
    {
      category: "Review depth",
      text: "At least one reviewer with security context has signed off on the change.",
      priority: "should",
    },
  ],
  high: [
    {
      category: "Review depth",
      text: "Two reviewers, including a security-domain owner, have approved the change.",
      priority: "must",
    },
    {
      category: "Threat model",
      text: "The change is checked against an explicit threat model and any new threats are recorded.",
      priority: "must",
    },
    {
      category: "Rollout",
      text: "A rollback plan and monitoring/alerting for the new behavior are in place before merge.",
      priority: "should",
    },
  ],
};

const LANGUAGE_ITEMS: Readonly<Record<string, RawItem>> = {
  python: {
    category: "Language pitfalls",
    text: `No use of \`${EVAL}\`, \`${EXEC}\`, \`pickle\` on untrusted data, \`${SUBPROCESS}\` with \`shell=True\`, or \`yaml.load\` without \`SafeLoader\`.`,
    priority: "should",
  },
  javascript: {
    category: "Language pitfalls",
    text: `No \`${EVAL}\`, \`${FUNC}()\`, \`${CHILD_PROCESS}.${EXEC}\` with interpolation, prototype-pollution sinks, or unsanitized \`innerHTML\`.`,
    priority: "should",
  },
  typescript: {
    category: "Language pitfalls",
    text: `No \`${EVAL}\` / \`${FUNC}()\`, no \`any\` that defeats type checks at trust boundaries, and no unchecked non-null assertions on external data.`,
    priority: "should",
  },
  go: {
    category: "Language pitfalls",
    text: `Errors are checked, not discarded; no \`os/${EXEC}\` with interpolated input; SQL uses parameterized queries.`,
    priority: "should",
  },
  rust: {
    category: "Language pitfalls",
    text: "Every `unsafe` block is justified and minimal; no `.unwrap()` / `.expect()` on attacker-influenced input in production paths.",
    priority: "should",
  },
  java: {
    category: "Language pitfalls",
    text: "No native deserialization of untrusted data, no XML parsing without XXE protections, and prepared statements for all SQL.",
    priority: "should",
  },
};

/** Generate a tailored security code-review checklist. */
export function generateReviewChecklist(config: ReviewChecklistConfig): ReviewChecklistArtifact {
  const languages = [...new Set(config.languages.map((l) => l.toLowerCase()))];
  const raw: RawItem[] = [
    ...BASE_ITEMS,
    ...TYPE_ITEMS[config.change_type],
    ...SENSITIVITY_ITEMS[config.sensitivity],
  ];
  for (const lang of languages) {
    const item = LANGUAGE_ITEMS[lang];
    if (item !== undefined) raw.push(item);
  }

  // For high-sensitivity changes, every base "should" is elevated to "must".
  const items: ChecklistItem[] = raw.map((item, idx) => ({
    id: `REVIEW-${String(idx + 1).padStart(2, "0")}`,
    category: item.category,
    text: item.text,
    priority: config.sensitivity === "high" && item.priority === "should" ? "must" : item.priority,
  }));

  const lines: string[] = [
    `# Security review checklist — ${config.change_type} change (${config.sensitivity} sensitivity)`,
    "",
    "Generated by altais-mcp altais_generate_review_checklist.",
    `Languages: ${languages.length > 0 ? languages.join(", ") : "unspecified"}`,
    "",
  ];
  for (const item of items) {
    const tag = item.priority === "must" ? "MUST" : "SHOULD";
    lines.push(`- [ ] (${tag}) [${item.category}] ${item.text}`);
  }
  lines.push("");

  return {
    change_type: config.change_type,
    sensitivity: config.sensitivity,
    languages,
    items,
    content: lines.join("\n"),
  };
}
