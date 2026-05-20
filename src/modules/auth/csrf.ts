// CSRF protections auditor.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface CsrfConfig {
  readonly auth_via?: "cookie" | "bearer" | "mixed";
  readonly samesite?: "Strict" | "Lax" | "None" | false;
  readonly csrf_token?: "synchronizer" | "double_submit" | "none";
  readonly checks_origin_header?: boolean;
  readonly state_changing_methods?: readonly ("POST" | "PUT" | "PATCH" | "DELETE")[];
}

export interface CsrfAuditInput {
  readonly source?: string;
  readonly config?: CsrfConfig;
  readonly filename?: string;
}

const REFS = ["https://owasp.org/www-community/attacks/csrf"];

export function auditCsrf(input: CsrfAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) findings.push(...scanSource(input.source, input.filename));
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

const PATTERNS: readonly {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}[] = [
  {
    rule: "csrf-token-disabled",
    regex:
      /\bcsrf\s*:\s*false\b|csrfProtection\s*:\s*false|csurf\(.*?ignoreMethods.*?(?:POST|PUT|PATCH|DELETE)/i,
    severity: "high",
    title: "CSRF protection appears to be disabled",
    description:
      "CSRF middleware is being turned off explicitly. State-changing endpoints become exploitable from any origin.",
    remediation: "Re-enable CSRF protection. Restrict ignoreMethods to read-only verbs.",
    cwe: ["CWE-352"],
  },
  {
    rule: "csrf-cors-credentials-with-wildcard",
    regex:
      /Access-Control-Allow-Origin[^\n]*\*[\s\S]{0,200}Access-Control-Allow-Credentials[^\n]*true/i,
    severity: "critical",
    title: "CORS combines `*` origin with credentials",
    description:
      "Browsers reject this combination, but the intent is dangerous and indicates a misunderstanding.",
    remediation: "Reflect a validated origin and add `Vary: Origin`.",
    cwe: ["CWE-352", "CWE-942"],
  },
];

function scanSource(source: string, filename: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  for (const pat of PATTERNS) {
    const regex = new RegExp(
      pat.regex.source,
      pat.regex.flags.includes("g") ? pat.regex.flags : `${pat.regex.flags}g`,
    );
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      findings.push(
        buildAuthFinding(
          {
            rule: pat.rule,
            severity: pat.severity,
            title: pat.title,
            description: pat.description,
            remediation: pat.remediation,
            cwe: pat.cwe,
            references: REFS,
            evidence: m[0].slice(0, 200),
            tags: ["csrf"],
            line: lineAt(source, m.index),
          },
          filename,
        ),
      );
      if (m[0].length === 0) regex.lastIndex += 1;
    }
  }
  return findings;
}

function auditConfig(c: CsrfConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const usesCookieAuth = c.auth_via === "cookie" || c.auth_via === "mixed";
  if (
    usesCookieAuth &&
    c.csrf_token === "none" &&
    c.samesite !== "Strict" &&
    c.checks_origin_header !== true
  ) {
    findings.push(
      buildAuthFinding(
        {
          rule: "csrf-no-mitigation",
          severity: "critical",
          title: "Cookie auth without CSRF mitigation",
          description:
            "When the API authenticates via cookies and has no CSRF tokens, no SameSite=Strict, and no Origin checks, state-changing requests can be triggered from any origin.",
          remediation:
            "Adopt at least one of: CSRF tokens (synchronizer or double-submit), SameSite=Strict cookies, or Origin / Referer validation on state-changing requests.",
          cwe: ["CWE-352"],
          references: REFS,
          evidence: `auth_via=${c.auth_via}, csrf_token=${c.csrf_token}, samesite=${String(c.samesite)}`,
          tags: ["csrf"],
        },
        source,
      ),
    );
  }
  if (
    usesCookieAuth &&
    c.samesite === "None" &&
    (c.csrf_token === "none" || c.csrf_token === undefined)
  ) {
    findings.push(
      buildAuthFinding(
        {
          rule: "csrf-samesite-none-no-token",
          severity: "high",
          title: "SameSite=None cookies without CSRF tokens",
          description:
            "SameSite=None cookies are sent on cross-site requests. With no CSRF token, the API is exposed to CSRF.",
          remediation: "Pair SameSite=None with CSRF tokens, or switch to SameSite=Lax / Strict.",
          cwe: ["CWE-352", "CWE-1275"],
          references: REFS,
          evidence: `samesite=None, csrf_token=${c.csrf_token ?? "none"}`,
          tags: ["csrf"],
        },
        source,
      ),
    );
  }
  if (
    usesCookieAuth &&
    (c.state_changing_methods ?? ["POST", "PUT", "PATCH", "DELETE"]).length === 0
  ) {
    findings.push(
      buildAuthFinding(
        {
          rule: "csrf-no-state-changing-methods",
          severity: "info",
          title: "No state-changing methods declared",
          description:
            "Confirm that read-only behavior is intentional and the API genuinely has no mutations.",
          remediation: "Declare which methods mutate state so CSRF protection can target them.",
          cwe: ["CWE-352"],
          references: REFS,
          tags: ["csrf"],
        },
        source,
      ),
    );
  }
  return findings;
}
