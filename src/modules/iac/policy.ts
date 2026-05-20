// Policy-as-code auditor (altais_check_policy_as_code).
//
// Validates OPA / Rego and Kyverno policies for weaknesses that make a
// policy ineffective: an insecure default-allow, a policy with no deny
// rules, a network call inside a policy, an audit-only enforcement
// action, and a policy with no match selector. A line-oriented scan
// keeps the module dependency-free.

import type { Finding } from "../../core/types.js";
import { buildIacFinding, lineAt } from "./finding.js";

export type PolicyType = "rego" | "kyverno";

export interface PolicyAuditInput {
  readonly content: string;
  readonly policy_type: PolicyType;
  readonly filename?: string;
}

const REFS = [
  "https://www.openpolicyagent.org/docs/latest/policy-language/",
  "https://kyverno.io/docs/writing-policies/",
  "https://owasp.org/www-project-top-ten/",
];

export function auditPolicy(input: PolicyAuditInput): readonly Finding[] {
  return input.policy_type === "rego" ? auditRego(input) : auditKyverno(input);
}

// ─── Rego ──────────────────────────────────────────────────────────────────

const REGO_DEFAULT_ALLOW_RE = /^[ \t]*default[ \t]+allow[ \t]*(?::?=)[ \t]*true\b/gim;
const REGO_HTTP_SEND_RE = /\bhttp\.send[ \t]*\(/gi;
// A `deny` / `violation` rule head, in any of Rego's rule forms.
const REGO_DENY_RULE_RE = /^[ \t]*(?:deny|violation)\b[^=\n]*(?:\{|=|:=|contains|\[)/m;

function auditRego(input: PolicyAuditInput): readonly Finding[] {
  const file = input.filename ?? "policy.rego";
  const src = input.content;
  const findings: Finding[] = [];

  let allow: RegExpExecArray | null;
  const allowRe = new RegExp(REGO_DEFAULT_ALLOW_RE.source, "gim");
  while ((allow = allowRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "rego-default-allow",
          severity: "high",
          title: "Rego policy defaults `allow` to `true`",
          description:
            "`default allow = true` makes the policy fail open: if no rule explicitly denies a request the request is permitted. A gap in the rules — or a rule that never fires — silently grants access.",
          remediation:
            "Default decisions to deny (`default allow := false`) and write explicit rules that grant access only for verified-safe cases. A security policy must fail closed.",
          cwe: ["CWE-1188", "CWE-284"],
          references: REFS,
          evidence: allow[0].trim().slice(0, 200),
          tags: ["policy", "rego"],
          line: lineAt(src, allow.index),
        },
        file,
      ),
    );
  }

  let http: RegExpExecArray | null;
  const httpRe = new RegExp(REGO_HTTP_SEND_RE.source, "gi");
  while ((http = httpRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "rego-http-send",
          severity: "medium",
          title: "Rego policy makes a network call with `http.send`",
          description:
            "`http.send` performs an outbound HTTP request during policy evaluation. It makes decisions non-deterministic, slows admission, and creates a dependency whose failure or compromise can change the policy outcome.",
          remediation:
            "Remove `http.send` from the decision path. Push external data into OPA via bundles or the data API so evaluation stays local and deterministic.",
          cwe: ["CWE-829", "CWE-16"],
          references: REFS,
          evidence: http[0].trim().slice(0, 200),
          tags: ["policy", "rego"],
          line: lineAt(src, http.index),
        },
        file,
      ),
    );
  }

  if (REGO_DENY_RULE_RE.exec(src) === null) {
    findings.push(
      buildIacFinding(
        {
          rule: "rego-no-deny-rules",
          severity: "medium",
          title: "Rego policy defines no `deny` or `violation` rules",
          description:
            "A policy file with no `deny` or `violation` rule produces no enforcement decisions. If it is wired into an admission controller it permits everything, providing a false sense of coverage.",
          remediation:
            "Add explicit `deny` / `violation` rules that describe the conditions the policy must reject, or remove the unused file from the policy bundle.",
          cwe: ["CWE-1188", "CWE-284"],
          references: REFS,
          tags: ["policy", "rego"],
        },
        file,
      ),
    );
  }

  return findings;
}

// ─── Kyverno ───────────────────────────────────────────────────────────────

const KYVERNO_AUDIT_ACTION_RE = /^[ \t]*validationFailureAction[ \t]*:[ \t]*["']?Audit["']?/gim;
const KYVERNO_BACKGROUND_FALSE_RE = /^[ \t]*background[ \t]*:[ \t]*false\b/gim;
const KYVERNO_HAS_VALIDATE_RE = /^[ \t]*(?:validate|deny)[ \t]*:/m;
const KYVERNO_HAS_MATCH_RE = /^[ \t]*match[ \t]*:/m;
const KYVERNO_IS_POLICY_RE = /^[ \t]*kind[ \t]*:[ \t]*["']?(?:Cluster)?Policy["']?/m;

function auditKyverno(input: PolicyAuditInput): readonly Finding[] {
  const file = input.filename ?? "policy.yaml";
  const src = input.content;
  const findings: Finding[] = [];

  let audit: RegExpExecArray | null;
  const auditRe = new RegExp(KYVERNO_AUDIT_ACTION_RE.source, "gim");
  while ((audit = auditRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "kyverno-audit-action",
          severity: "medium",
          title: "Kyverno policy only audits violations instead of enforcing",
          description:
            "`validationFailureAction: Audit` records a policy report but still admits the non-compliant resource. A security policy left in `Audit` mode never actually blocks anything.",
          remediation:
            "Set `validationFailureAction: Enforce` once the policy has been validated, so violating resources are rejected at admission.",
          cwe: ["CWE-1188", "CWE-16"],
          references: REFS,
          evidence: audit[0].trim().slice(0, 200),
          tags: ["policy", "kyverno"],
          line: lineAt(src, audit.index),
        },
        file,
      ),
    );
  }

  let bg: RegExpExecArray | null;
  const bgRe = new RegExp(KYVERNO_BACKGROUND_FALSE_RE.source, "gim");
  while ((bg = bgRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "kyverno-background-disabled",
          severity: "low",
          title: "Kyverno background scanning is disabled",
          description:
            "`background: false` stops Kyverno from periodically re-evaluating resources that already exist in the cluster. Resources created before the policy — or that drift afterwards — are never re-checked.",
          remediation:
            "Set `background: true` (the default) unless the rule relies on admission-only context such as `AdmissionRequest` data that is unavailable to background scans.",
          cwe: ["CWE-778", "CWE-16"],
          references: REFS,
          evidence: bg[0].trim().slice(0, 200),
          tags: ["policy", "kyverno"],
          line: lineAt(src, bg.index),
        },
        file,
      ),
    );
  }

  const isPolicy = KYVERNO_IS_POLICY_RE.exec(src) !== null;
  if (isPolicy && KYVERNO_HAS_VALIDATE_RE.exec(src) === null) {
    findings.push(
      buildIacFinding(
        {
          rule: "kyverno-no-validate-rules",
          severity: "medium",
          title: "Kyverno policy defines no `validate` or `deny` rules",
          description:
            "A `ClusterPolicy` / `Policy` with no `validate` (or `deny`) block enforces nothing. It appears to provide coverage but admits every resource it matches.",
          remediation:
            "Add a `validate` rule with a `pattern` or `deny` condition that expresses what the policy must reject, or remove the empty policy.",
          cwe: ["CWE-1188", "CWE-284"],
          references: REFS,
          tags: ["policy", "kyverno"],
        },
        file,
      ),
    );
  }

  if (isPolicy && KYVERNO_HAS_MATCH_RE.exec(src) === null) {
    findings.push(
      buildIacFinding(
        {
          rule: "kyverno-missing-match",
          severity: "medium",
          title: "Kyverno policy rule has no `match` selector",
          description:
            "A rule with no `match` block has no scoping selector. Depending on the Kyverno version it either matches every resource — applying broadly and unpredictably — or never fires at all.",
          remediation:
            "Add an explicit `match` selector that scopes the rule to the specific resource kinds, namespaces, or labels it is meant to govern.",
          cwe: ["CWE-284", "CWE-16"],
          references: REFS,
          tags: ["policy", "kyverno"],
        },
        file,
      ),
    );
  }

  return findings;
}
