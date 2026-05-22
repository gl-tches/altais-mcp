// STRIDE analyzer.
//
// Given an architecture (components + data flows), emits a STRIDE
// breakdown per component using a knowledge base of typical threats
// for each component type. The output is a structured analysis the
// caller can fold into a threat-model document.

import {
  type Architecture,
  type Component,
  type ComponentType,
  type DataFlow,
  STRIDE_CATEGORIES,
  type StrideCategory,
  type ThreatTemplate,
} from "./types.js";

const T = (
  category: StrideCategory,
  description: string,
  mitigation: string,
  cwe: readonly string[] = [],
): ThreatTemplate => ({ category, description, mitigation, cwe });

const COMPONENT_THREATS: Readonly<Record<ComponentType, readonly ThreatTemplate[]>> = {
  user: [
    T(
      "spoofing",
      "Account takeover via password reuse or phishing",
      "Require MFA (preferably WebAuthn / passkeys) on all accounts; rate-limit logins; alert on impossible-travel sign-ins.",
      ["CWE-287", "CWE-1390"],
    ),
    T(
      "repudiation",
      "User actions are not bound to a user identity or are not durably logged",
      "Log security-relevant events with timestamp, user ID, source IP, and request ID; protect logs from user-side tampering.",
      ["CWE-778"],
    ),
    T(
      "information_disclosure",
      "Sensitive data transmitted on user-controlled channels (email, query string, screenshot tools)",
      "Avoid putting tokens or PII in URLs; redact when copying to clipboard or screenshots.",
      ["CWE-598"],
    ),
    T(
      "denial_of_service",
      "Login / password-reset endpoints abused to lock out users",
      "Apply per-account and per-IP throttling. Use exponential backoff and CAPTCHA after thresholds.",
      ["CWE-307"],
    ),
  ],

  browser: [
    T(
      "spoofing",
      "Cookie or session token stolen via XSS",
      "Set HttpOnly + Secure + SameSite on session cookies; enforce a strict CSP.",
      ["CWE-79", "CWE-1004"],
    ),
    T(
      "tampering",
      "Client-side state modified via DevTools or extensions",
      "Treat all client-supplied data as untrusted on the server. Re-validate every state transition.",
      ["CWE-602", "CWE-565"],
    ),
    T(
      "information_disclosure",
      "Secrets persisted in localStorage / sessionStorage / source",
      "Never store long-lived secrets in client storage. Use httpOnly cookies or short-lived tokens.",
      ["CWE-540", "CWE-798"],
    ),
    T(
      "elevation_of_privilege",
      "XSS escalates to session theft or arbitrary action-on-behalf",
      "Enforce CSP, sanitize all sinks, and use SameSite + CSRF tokens on state-changing endpoints.",
      ["CWE-79"],
    ),
  ],

  api: [
    T(
      "spoofing",
      "Missing or bypassable authentication on privileged endpoints",
      "Enforce auth in middleware (default-deny). Validate JWTs with pinned algorithm, issuer, and audience.",
      ["CWE-287", "CWE-306"],
    ),
    T(
      "tampering",
      "Injection via unparameterized queries or shell construction",
      "Use parameterized queries; pass argv arrays to subprocesses; validate input against schemas.",
      ["CWE-89", "CWE-78", "CWE-94"],
    ),
    T(
      "repudiation",
      "State-changing operations have no audit trail",
      "Log who/what/when for every mutation. Make logs append-only and ship off-host.",
      ["CWE-778"],
    ),
    T(
      "information_disclosure",
      "IDOR — caller can read records by guessing identifiers",
      "Enforce object-level authorization on every object access. Prefer indirect references where appropriate.",
      ["CWE-639", "CWE-285"],
    ),
    T(
      "denial_of_service",
      "Unbounded resource consumption (unbounded body, expensive query)",
      "Apply size and time limits per endpoint. Use bounded queues and worker pools.",
      ["CWE-400", "CWE-770"],
    ),
    T(
      "elevation_of_privilege",
      "Missing authorization check on a privileged action",
      "Centralize authorization. Default-deny and enumerate allowed roles per endpoint.",
      ["CWE-862", "CWE-863"],
    ),
  ],

  service: [
    T(
      "spoofing",
      "Internal services accept caller-supplied identity headers without verification",
      "Use mutual TLS or signed identity tokens between services. Strip and reset hop-by-hop headers at boundaries.",
      ["CWE-441", "CWE-287"],
    ),
    T(
      "tampering",
      "Message payloads modified in transit between services",
      "Require TLS for all internal traffic. Where intermediaries cannot be trusted, add an HMAC over the payload.",
      ["CWE-924", "CWE-319"],
    ),
    T(
      "denial_of_service",
      "Cascading failure from a slow or noisy dependency",
      "Add circuit breakers and bulkheads. Apply per-dependency timeouts and retry budgets.",
      ["CWE-400"],
    ),
  ],

  database: [
    T(
      "spoofing",
      "Shared or leaked database credentials grant direct access",
      "Use unique per-service credentials with IAM auth where available. Rotate on schedule and on compromise.",
      ["CWE-798"],
    ),
    T(
      "tampering",
      "SQL injection or direct writes bypassing application validation",
      "Restrict app DB user to least privilege. Require parameterized queries and review any raw-query escape hatches.",
      ["CWE-89"],
    ),
    T(
      "repudiation",
      "Database writes happen without an audit trail",
      "Enable transaction logging or write-ahead-log archival. Tag writes with the originating application user.",
      ["CWE-778"],
    ),
    T(
      "information_disclosure",
      "Backups or replicas accessible to broader audiences than production",
      "Apply the same access controls and encryption to backups. Encrypt at rest with a managed KMS.",
      ["CWE-311", "CWE-552"],
    ),
    T(
      "denial_of_service",
      "Long-running queries or connection exhaustion",
      "Set statement_timeout and connection caps. Index expensive queries; use read replicas for analytics.",
      ["CWE-400"],
    ),
    T(
      "elevation_of_privilege",
      "Application DB user has more rights than required (DROP, GRANT, etc.)",
      "Run the app under a least-privilege role. Reserve schema changes for migration jobs with separate credentials.",
      ["CWE-269", "CWE-272"],
    ),
  ],

  queue: [
    T(
      "spoofing",
      "Unauthenticated producers can publish arbitrary messages",
      "Require auth at the broker. Use per-publisher credentials so consumers can attribute messages.",
      ["CWE-306"],
    ),
    T(
      "tampering",
      "Replayed or reordered messages cause inconsistent state",
      "Use idempotency keys at the consumer. Sign messages with monotonically increasing sequence numbers.",
      ["CWE-294"],
    ),
    T(
      "denial_of_service",
      "Queue flooded with junk messages",
      "Apply per-producer quotas and dead-letter queues. Drop or quarantine messages that exceed schema size.",
      ["CWE-770"],
    ),
  ],

  cache: [
    T(
      "tampering",
      "Cache poisoning via Host / forwarding headers",
      "Normalize the cache key to a server-controlled origin. Strip unsafe headers from the key.",
      ["CWE-444"],
    ),
    T(
      "information_disclosure",
      "Cached responses leak to other users when keys ignore identity",
      "Include user / tenant identifiers in the cache key for any per-user response.",
      ["CWE-525"],
    ),
    T(
      "elevation_of_privilege",
      "Permission decisions cached and not invalidated when roles change",
      "Invalidate or shorten TTLs on revoked-role events. Re-check authorization on cache hit for high-impact actions.",
      ["CWE-285"],
    ),
  ],

  storage: [
    T(
      "information_disclosure",
      "Object storage misconfigured to allow public reads",
      "Default-deny. Use BlockPublicAccess settings; require signed URLs for shared objects.",
      ["CWE-552", "CWE-732"],
    ),
    T(
      "tampering",
      "Writes accepted without integrity checks",
      "Require checksums on PUT. Verify on read; consider object lock for tamper-evident workflows.",
      ["CWE-345"],
    ),
    T(
      "elevation_of_privilege",
      "Bucket / container policy grants more permissions than the service needs",
      "Scope IAM policies to specific prefixes and actions. Audit policies on a schedule.",
      ["CWE-269"],
    ),
  ],

  external: [
    T(
      "spoofing",
      "Vendor compromise or supply-chain attack",
      "Pin dependency versions by hash. Monitor vendor security advisories.",
      ["CWE-1395", "CWE-1357"],
    ),
    T(
      "tampering",
      "Man-in-the-middle on the link to the external service",
      "Require TLS with certificate validation. Pin CAs for high-value integrations.",
      ["CWE-295", "CWE-924"],
    ),
    T(
      "information_disclosure",
      "Data shared with the vendor is more than they need",
      "Apply data minimization. Pseudonymize where possible.",
      ["CWE-200"],
    ),
  ],

  auth: [
    T(
      "spoofing",
      "Token forgery via `alg: none` or weak signing key",
      "Pin the expected algorithm. Reject tokens that fail signature verification.",
      ["CWE-347"],
    ),
    T(
      "tampering",
      "OAuth redirect_uri / state manipulation",
      "Allowlist redirect URIs exactly. Bind state to the user's session.",
      ["CWE-601"],
    ),
    T(
      "information_disclosure",
      "Tokens leak via Referer or window.opener",
      "Use POST_RESPONSE or fragment delivery for tokens. Set Referrer-Policy: no-referrer on login pages.",
      ["CWE-200"],
    ),
    T(
      "denial_of_service",
      "Login endpoint abused by credential stuffing",
      "Rate-limit per account and per IP. Use a known-breach-password blocklist.",
      ["CWE-307"],
    ),
    T(
      "elevation_of_privilege",
      "Scope creep via consent flow re-prompts",
      "Re-prompt for sensitive scopes. Bind issued tokens to the minimum requested scope.",
      ["CWE-269"],
    ),
  ],

  function: [
    T(
      "spoofing",
      "Functions invoked from spoofed event sources",
      "Validate event source signatures (SNS sig, EventBridge ARN, API Gateway request context).",
      ["CWE-345"],
    ),
    T(
      "tampering",
      "Environment variables tampered at deploy time",
      "Sign deployment artifacts. Use a managed secrets store and reference at runtime, not at deploy.",
      ["CWE-15"],
    ),
    T(
      "denial_of_service",
      "Invocation budget exhaustion via fan-out",
      "Set concurrency limits and reserved capacity. Use throttling at the upstream queue.",
      ["CWE-770"],
    ),
    T(
      "elevation_of_privilege",
      "Function role grants more permissions than needed",
      "Scope the execution role to the specific actions used. Use temporary credentials.",
      ["CWE-269"],
    ),
  ],

  other: [
    T(
      "spoofing",
      "Component identity is unverified by upstream callers",
      "Mutually authenticate every external call. Use short-lived identity tokens.",
      ["CWE-287"],
    ),
    T(
      "tampering",
      "State changes occur without integrity protection",
      "Sign or HMAC sensitive state. Validate on read.",
      ["CWE-353"],
    ),
    T(
      "repudiation",
      "No audit trail for security-relevant operations",
      "Emit append-only audit logs to a separate ship.",
      ["CWE-778"],
    ),
    T(
      "information_disclosure",
      "Sensitive data exposed via verbose errors or logs",
      "Centralize logging with redaction. Return generic error envelopes.",
      ["CWE-209", "CWE-532"],
    ),
    T(
      "denial_of_service",
      "Unbounded resource consumption",
      "Cap concurrency, request sizes, and computation time.",
      ["CWE-400"],
    ),
    T(
      "elevation_of_privilege",
      "Privilege checks rely on client-supplied state",
      "Recompute authority server-side from a trusted identity.",
      ["CWE-285"],
    ),
  ],
};

export interface ComponentAnalysis {
  readonly component: string;
  readonly type: ComponentType;
  readonly threats: Readonly<Record<StrideCategory, readonly ThreatTemplate[]>>;
  readonly note?: string;
}

export interface CrossFlowThreat {
  readonly flow: string;
  readonly category: StrideCategory;
  readonly description: string;
  readonly mitigation: string;
  readonly cwe: readonly string[];
}

export interface StrideAnalysis {
  readonly components: readonly ComponentAnalysis[];
  readonly cross_component_threats: readonly CrossFlowThreat[];
  readonly summary: {
    readonly total_threats: number;
    readonly by_category: Readonly<Record<StrideCategory, number>>;
  };
}

function emptyByCategory(): Record<StrideCategory, ThreatTemplate[]> {
  return {
    spoofing: [],
    tampering: [],
    repudiation: [],
    information_disclosure: [],
    denial_of_service: [],
    elevation_of_privilege: [],
  };
}

function analyzeComponent(component: Component): ComponentAnalysis {
  const grouped = emptyByCategory();
  const templates = COMPONENT_THREATS[component.type];
  for (const t of templates) grouped[t.category].push(t);

  if (component.handles_pii === true) {
    grouped.information_disclosure.push(
      T(
        "information_disclosure",
        `${component.name} handles PII — exposure here triggers regulatory obligations (GDPR / state privacy laws).`,
        "Document the legal basis for collection. Apply field-level encryption and retention limits.",
        ["CWE-359", "CWE-311"],
      ),
    );
  }
  if (component.authenticates_clients === true) {
    grouped.spoofing.push(
      T(
        "spoofing",
        `${component.name} performs authentication — credential-stuffing and token-replay are concrete risks.`,
        "Enforce MFA for privileged accounts. Pin token algorithms and validate signatures.",
        ["CWE-287", "CWE-307"],
      ),
    );
  }

  return {
    component: component.name,
    type: component.type,
    threats: grouped,
  };
}

function analyzeFlows(flows: readonly DataFlow[]): readonly CrossFlowThreat[] {
  const out: CrossFlowThreat[] = [];
  for (const f of flows) {
    const flow = `${f.from} -> ${f.to}`;
    const isEncrypted = f.encrypted === true || /^https|^tls|^wss|^mtls/i.test(f.protocol ?? "");
    if (!isEncrypted) {
      out.push({
        flow,
        category: "information_disclosure",
        description: `Data flow \`${f.data}\` between ${f.from} and ${f.to} is not marked as encrypted.`,
        mitigation: "Require TLS (or mTLS for service-to-service) and reject plaintext fallbacks.",
        cwe: ["CWE-319"],
      });
    }
    if (!f.auth || f.auth.length === 0) {
      out.push({
        flow,
        category: "spoofing",
        description: `No authentication scheme declared for flow \`${f.data}\` (${flow}).`,
        mitigation:
          "Authenticate both endpoints (mTLS, signed tokens, or HMAC). Document the chosen scheme.",
        cwe: ["CWE-306"],
      });
    }
  }
  return out;
}

function summarize(
  components: readonly ComponentAnalysis[],
  cross: readonly CrossFlowThreat[],
): StrideAnalysis["summary"] {
  const byCategory: Record<StrideCategory, number> = {
    spoofing: 0,
    tampering: 0,
    repudiation: 0,
    information_disclosure: 0,
    denial_of_service: 0,
    elevation_of_privilege: 0,
  };
  let total = 0;
  for (const c of components) {
    for (const cat of STRIDE_CATEGORIES) {
      byCategory[cat] += c.threats[cat].length;
      total += c.threats[cat].length;
    }
  }
  for (const t of cross) {
    byCategory[t.category] += 1;
    total += 1;
  }
  return { total_threats: total, by_category: byCategory };
}

export function analyzeStride(architecture: Architecture): StrideAnalysis {
  const components = architecture.components.map(analyzeComponent);
  const cross = analyzeFlows(architecture.data_flows ?? []);
  return {
    components,
    cross_component_threats: cross,
    summary: summarize(components, cross),
  };
}
