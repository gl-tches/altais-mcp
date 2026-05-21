// Attack tree generator.
//
// Maps an attacker's high-level goal to a structured attack tree using
// template knowledge. The output is intentionally human-readable JSON:
// each node is either an `or` of sub-goals (any one path achieves it)
// or a `leaf` describing a concrete attack with mitigations and CWE
// references.

import { scanToken } from "../../core/scan-patterns.js";

// Dynamic code-execution API names, loaded from data/scan-patterns.json
// (see src/core/scan-patterns.ts).
const EVAL = scanToken("js-dynamic-code");
const FUNC = scanToken("js-function-constructor");

export type NodeType = "or" | "and" | "leaf";
export type AttackDifficulty = "trivial" | "easy" | "medium" | "hard" | "expert";

export interface AttackNode {
  readonly description: string;
  readonly type: NodeType;
  readonly children?: readonly AttackNode[];
  readonly mitigations?: readonly string[];
  readonly difficulty?: AttackDifficulty;
  readonly cwe?: readonly string[];
  readonly references?: readonly string[];
}

export interface AttackTreeInput {
  readonly goal: string;
  readonly asset?: string;
  readonly context?: string;
}

export interface AttackTreeResult {
  readonly goal: string;
  readonly asset: string | undefined;
  readonly matched_template: string;
  readonly root: AttackNode;
  readonly notes: readonly string[];
}

const TEMPLATES: readonly {
  readonly id: string;
  readonly keywords: readonly RegExp[];
  readonly build: (input: AttackTreeInput) => AttackNode;
}[] = [
  {
    id: "account-takeover",
    keywords: [
      /\bcredential/i,
      /\baccount\b/i,
      /\blogin\b/i,
      /\bpassword\b/i,
      /\btake[- ]?over\b/i,
      /\bphish/i,
    ],
    build: () => accountTakeover(),
  },
  {
    id: "data-exfiltration",
    keywords: [
      /\bexfiltrat/i,
      /\bsteal\s+data\b/i,
      /\bleak\b/i,
      /\bdump\b/i,
      /\bdata\s+(?:breach|theft|loss)\b/i,
      /\bcustomer\s+data\b/i,
    ],
    build: () => dataExfiltration(),
  },
  {
    id: "remote-code-execution",
    keywords: [
      /\bremote code\b/i,
      /\brce\b/i,
      /\bexecute\s+arbitrary\b/i,
      /\bcommand\b/i,
      /\bshell\b/i,
    ],
    build: () => remoteCodeExecution(),
  },
  {
    id: "privilege-escalation",
    keywords: [/\bescalat/i, /\bprivileg/i, /\badmin\b/i, /\broot\b/i],
    build: () => privilegeEscalation(),
  },
  {
    id: "denial-of-service",
    keywords: [/\bden(?:y|ial)\s+of\s+service\b/i, /\bdos\b/i, /\bavailability\b/i, /\boutage\b/i],
    build: () => denialOfService(),
  },
  {
    id: "supply-chain",
    keywords: [/\bsupply[- ]?chain\b/i, /\bdependenc/i, /\bbuild\b/i, /\bpackage\b/i],
    build: () => supplyChain(),
  },
];

export function generateAttackTree(input: AttackTreeInput): AttackTreeResult {
  const matched = TEMPLATES.find((t) => t.keywords.some((re) => re.test(input.goal)));
  const root = matched ? matched.build(input) : genericTree(input);
  return {
    goal: input.goal,
    asset: input.asset,
    matched_template: matched?.id ?? "generic",
    root,
    notes: matched
      ? []
      : [
          "Goal did not match a known template; returning a generic STRIDE-shaped tree. Refine the goal for a more specific attack tree (e.g. 'account takeover', 'data exfiltration', 'remote code execution').",
        ],
  };
}

// ─── Templates ─────────────────────────────────────────────────────────────

function leaf(
  description: string,
  difficulty: AttackDifficulty,
  cwe: readonly string[],
  mitigations: readonly string[],
): AttackNode {
  return { description, type: "leaf", difficulty, cwe, mitigations };
}

function orNode(description: string, children: readonly AttackNode[]): AttackNode {
  return { description, type: "or", children };
}

function accountTakeover(): AttackNode {
  return orNode("Compromise a user account", [
    orNode("Obtain valid credentials", [
      leaf(
        "Credential stuffing using leaked password databases",
        "easy",
        ["CWE-521", "CWE-307"],
        [
          "Block known-breached passwords (HIBP API or local snapshot)",
          "Rate-limit per account and per IP",
          "Require MFA on high-value accounts",
        ],
      ),
      leaf(
        "Phishing the user with a lookalike domain",
        "medium",
        ["CWE-1390"],
        [
          "Deploy phishing-resistant MFA (WebAuthn/passkeys)",
          "Add DMARC/SPF/DKIM on all sending domains",
        ],
      ),
      leaf(
        "Password reset flow abuse (predictable reset tokens / no rate limit)",
        "medium",
        ["CWE-307", "CWE-330"],
        [
          "Generate reset tokens with a CSPRNG; expire after 15 min",
          "Throttle reset requests per email/IP; alert on bursts",
        ],
      ),
    ]),
    orNode("Bypass authentication entirely", [
      leaf(
        "JWT algorithm confusion (alg: none / HS-with-RSA-key)",
        "hard",
        ["CWE-347"],
        ["Pin the expected algorithm; reject tokens that do not match"],
      ),
      leaf(
        "Session fixation: set a known session id before login",
        "medium",
        ["CWE-384"],
        ["Rotate session IDs on authentication; invalidate the pre-login session"],
      ),
    ]),
    orNode("Steal a live session", [
      leaf(
        "Session token theft via XSS",
        "medium",
        ["CWE-79", "CWE-1004"],
        ["Set HttpOnly + Secure + SameSite on session cookies", "Enforce a strict CSP"],
      ),
      leaf(
        "Token leak via Referer or browser history",
        "easy",
        ["CWE-200"],
        [
          "Deliver tokens via fragment or POST response",
          "Set Referrer-Policy: no-referrer on auth pages",
        ],
      ),
    ]),
  ]);
}

function dataExfiltration(): AttackNode {
  return orNode("Exfiltrate sensitive data from the application", [
    orNode("Read data directly from the data store", [
      leaf(
        "SQL injection extracting rows",
        "medium",
        ["CWE-89"],
        [
          "Use parameterized queries",
          "Run the app DB user with read-only access to non-PII tables",
        ],
      ),
      leaf(
        "Misconfigured object storage (S3 / GCS / Azure Blob) is publicly readable",
        "trivial",
        ["CWE-552", "CWE-732"],
        ["BlockPublicAccess; signed URLs for shared objects", "Continuous IAM audit"],
      ),
      leaf(
        "Backup file with full database is reachable from the web root",
        "trivial",
        ["CWE-540", "CWE-552"],
        ["Store backups off the application host; encrypt at rest with KMS"],
      ),
    ]),
    orNode("Bypass application-level authorization (IDOR)", [
      leaf(
        "Iterate object IDs to read records belonging to other users",
        "easy",
        ["CWE-639", "CWE-285"],
        ["Enforce object-level authorization on every fetch", "Use indirect references"],
      ),
    ]),
    orNode("Exfiltrate via a side channel", [
      leaf(
        "Error message leaks sensitive fields or query fragments",
        "easy",
        ["CWE-209"],
        ["Return generic error envelopes; log details server-side with a correlation ID"],
      ),
      leaf(
        "Verbose response leaks fields the UI does not display",
        "easy",
        ["CWE-200"],
        ["Serialize via explicit allowlists, not blacklists"],
      ),
    ]),
  ]);
}

function remoteCodeExecution(): AttackNode {
  return orNode("Execute arbitrary code on the application host", [
    orNode("Inject code through an untrusted input path", [
      leaf(
        "OS command injection via shell-form exec / system call",
        "medium",
        ["CWE-78"],
        ["Use execFile/spawn with argv arrays; never shell=True with user input"],
      ),
      leaf(
        "Server-side template injection (Jinja2 / Twig / Velocity / FreeMarker)",
        "medium",
        ["CWE-1336"],
        ["Render trusted templates with data variables; never compile templates from input"],
      ),
      leaf(
        "Deserialization of untrusted data (Python pickle, Java ObjectInputStream)",
        "hard",
        ["CWE-502"],
        ["Use data-only formats (JSON, MessagePack); validate against a schema"],
      ),
    ]),
    orNode("Abuse an unsafe feature of the language", [
      leaf(
        `\`${EVAL}\` / \`new ${FUNC}\` on caller-supplied string`,
        "easy",
        ["CWE-94"],
        [`Remove ${EVAL} / ${FUNC}; use data-driven configuration`],
      ),
      leaf(
        "Vulnerable dependency loaded by `require(variable)` / dynamic import",
        "hard",
        ["CWE-829"],
        ["Allowlist module names; never accept module paths from user input"],
      ),
    ]),
    orNode("Reach a known-vulnerable dependency", [
      leaf(
        "Outdated library with a published RCE CVE in the dependency tree",
        "medium",
        ["CWE-1395"],
        ["SCA on every PR; SLA-driven patching"],
      ),
    ]),
  ]);
}

function privilegeEscalation(): AttackNode {
  return orNode("Escalate from low-privilege to admin", [
    leaf(
      "Mass-assignment lets caller set `isAdmin` / `role`",
      "easy",
      ["CWE-915"],
      ["Allowlist updatable fields per endpoint", "Use schemas to deserialize"],
    ),
    leaf(
      "Missing authorization on an admin endpoint",
      "medium",
      ["CWE-862"],
      ["Centralize authorization; default-deny per route"],
    ),
    leaf(
      "Same-role privilege confusion (one tenant can access another's data)",
      "medium",
      ["CWE-639", "CWE-863"],
      ["Tie every record to a tenant; verify on every read/write"],
    ),
    leaf(
      "Container escape via overly-permissive runtime",
      "expert",
      ["CWE-693"],
      ["Use restricted Pod Security profile; drop CAP_SYS_ADMIN; readOnlyRootFilesystem"],
    ),
  ]);
}

function denialOfService(): AttackNode {
  return orNode("Make the application unavailable", [
    leaf(
      "Unbounded request body or recursion causes OOM",
      "easy",
      ["CWE-400", "CWE-770"],
      ["Set body-size and depth limits at the framework"],
    ),
    leaf(
      "Catastrophic regex backtracking (ReDoS)",
      "medium",
      ["CWE-1333"],
      ["Audit regexes; use linear-time engines (RE2) or apply length caps"],
    ),
    leaf(
      "Resource exhaustion on a downstream dependency (DB connection pool)",
      "easy",
      ["CWE-400"],
      ["Per-tenant quotas; circuit breakers; bounded worker pools"],
    ),
    leaf(
      "Algorithmic complexity attack (hash flooding, sort bomb)",
      "medium",
      ["CWE-407"],
      ["Use randomized hash keys; cap input sizes for expensive operations"],
    ),
  ]);
}

function supplyChain(): AttackNode {
  return orNode("Compromise the application via its supply chain", [
    leaf(
      "Typosquatted package published with a similar name",
      "medium",
      ["CWE-1357"],
      ["Pin by hash; mirror dependencies; use a typosquat detector at install time"],
    ),
    leaf(
      "Dependency confusion: internal package name resolves to public registry",
      "medium",
      ["CWE-1357"],
      ["Reserve internal names on the public registry; configure scoped registries"],
    ),
    leaf(
      "Build pipeline compromised; signed artifacts re-signed with attacker key",
      "expert",
      ["CWE-345"],
      ["Sigstore/cosign signatures; verify SLSA provenance before deploy"],
    ),
    leaf(
      "Compromised maintainer pushes a malicious release",
      "hard",
      ["CWE-1395"],
      ["2FA on registry accounts; review changelogs before bumps"],
    ),
  ]);
}

function genericTree(input: AttackTreeInput): AttackNode {
  const asset = input.asset ?? "the target";
  return orNode(`Achieve: ${input.goal}`, [
    leaf(
      `Identify an unauthenticated entry point exposing ${asset}`,
      "easy",
      ["CWE-306"],
      ["Enforce authentication globally; default-deny"],
    ),
    leaf(
      `Find an injection sink that influences how ${asset} is accessed`,
      "medium",
      ["CWE-74"],
      ["Parameterize every downstream interpreter"],
    ),
    leaf(
      `Bypass authorization on a privileged action against ${asset}`,
      "medium",
      ["CWE-862", "CWE-863"],
      ["Centralize authorization; object-level checks"],
    ),
    leaf(
      `Exfiltrate ${asset} through a side channel (errors, logs, timing)`,
      "medium",
      ["CWE-200"],
      ["Return generic error envelopes; redact logs; pad/constant-time critical operations"],
    ),
  ]);
}
