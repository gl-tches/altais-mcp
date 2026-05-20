// Session-management auditor.
//
// Source-level checks for cookie flags, session rotation, and fixation
// resistance. Also accepts a structured `SessionConfig` describing a
// session middleware setup.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface SessionConfig {
  readonly cookie?: {
    readonly secure?: boolean;
    readonly httpOnly?: boolean;
    readonly sameSite?: "Strict" | "Lax" | "None" | false;
    readonly maxAgeSeconds?: number;
    readonly domain?: string;
  };
  readonly regenerate_on_login?: boolean;
  readonly invalidate_on_logout?: boolean;
  readonly absolute_timeout_seconds?: number;
  readonly idle_timeout_seconds?: number;
  readonly id_entropy_bits?: number;
}

export interface SessionAuditInput {
  readonly source?: string;
  readonly config?: SessionConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
  "https://datatracker.ietf.org/doc/html/rfc6265",
];

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
    rule: "session-secure-false",
    regex: /\bsecure\s*:\s*false\b/i,
    severity: "high",
    title: "Session cookie configured with `secure: false`",
    description: "Cookies sent over plain HTTP leak to network attackers.",
    remediation: "Set `secure: true` in production. Use `secure: false` only for local dev.",
    cwe: ["CWE-614"],
  },
  {
    rule: "session-httponly-false",
    regex: /\bhttpOnly\s*:\s*false\b/i,
    severity: "high",
    title: "Session cookie configured with `httpOnly: false`",
    description:
      "Without `HttpOnly`, JS on the page can read the session cookie — any XSS escalates.",
    remediation: "Set `httpOnly: true`.",
    cwe: ["CWE-1004"],
  },
  {
    rule: "session-samesite-none",
    regex: /\bsameSite\s*:\s*["']?none["']?\b/i,
    severity: "medium",
    title: "Session cookie set to `SameSite=None`",
    description:
      "SameSite=None permits cross-site cookie transmission. Confirm this is intentional and combine with CSRF protections.",
    remediation:
      "Use `SameSite=Lax` (or `Strict`) unless cross-site flows are required. Pair with explicit CSRF tokens.",
    cwe: ["CWE-1275", "CWE-352"],
  },
  {
    rule: "session-fixation-no-regenerate",
    regex:
      /\b(req\.login|passport\.authenticate|req\.session\.user\s*=)\b[^\n]{0,200}(?![\s\S]{0,200}regenerate)/i,
    severity: "medium",
    title: "Login path does not regenerate session ID",
    description:
      "Without regenerating the session ID on authentication, a pre-set session ID survives login — enabling session fixation.",
    remediation:
      "Call `req.session.regenerate(cb)` on successful login. Re-assign user fields after regeneration.",
    cwe: ["CWE-384"],
  },
];

export function auditSession(input: SessionAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) findings.push(...scanSource(input.source, input.filename));
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

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
            tags: ["session"],
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

function auditConfig(c: SessionConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const cookie = c.cookie ?? {};
  if (cookie.secure === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-secure-false",
          severity: "high",
          title: "Session cookie `secure` is false",
          description: "Cookies sent over plain HTTP leak to network attackers.",
          remediation: "Set `secure: true`.",
          cwe: ["CWE-614"],
          references: REFS,
          evidence: "cookie.secure=false",
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if (cookie.httpOnly === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-httponly-false",
          severity: "high",
          title: "Session cookie `httpOnly` is false",
          description: "JavaScript can read the cookie — any XSS escalates to session theft.",
          remediation: "Set `httpOnly: true`.",
          cwe: ["CWE-1004"],
          references: REFS,
          evidence: "cookie.httpOnly=false",
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if (cookie.sameSite === false || cookie.sameSite === undefined) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-samesite-missing",
          severity: "medium",
          title: "Session cookie `SameSite` not set",
          description:
            "Without SameSite, the cookie is sent on cross-site requests — enabling CSRF.",
          remediation: "Set `sameSite: 'Lax'` (or `Strict`).",
          cwe: ["CWE-1275", "CWE-352"],
          references: REFS,
          evidence: `cookie.sameSite=${String(cookie.sameSite)}`,
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if (c.regenerate_on_login === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-fixation",
          severity: "high",
          title: "Session ID not regenerated on login",
          description: "A pre-set session ID survives login, allowing session fixation.",
          remediation: "Regenerate the session ID on successful authentication.",
          cwe: ["CWE-384"],
          references: REFS,
          evidence: "regenerate_on_login=false",
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if (c.invalidate_on_logout === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-no-logout-invalidation",
          severity: "high",
          title: "Sessions not invalidated on logout",
          description:
            "Server-side session must be destroyed on logout so the cookie is unusable even if it persists in a browser.",
          remediation:
            "Call `req.session.destroy()` (or equivalent) and clear the cookie on logout.",
          cwe: ["CWE-613"],
          references: REFS,
          evidence: "invalidate_on_logout=false",
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if ((c.absolute_timeout_seconds ?? 0) > 30 * 86_400) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-long-absolute-timeout",
          severity: "medium",
          title: `Absolute session timeout exceeds 30 days (${c.absolute_timeout_seconds}s)`,
          description: "Long absolute timeouts widen the impact of token theft.",
          remediation:
            "Set absolute timeout to days, not months. Require re-authentication for sensitive actions.",
          cwe: ["CWE-613"],
          references: REFS,
          tags: ["session"],
        },
        source,
      ),
    );
  }
  if ((c.id_entropy_bits ?? 128) < 128) {
    findings.push(
      buildAuthFinding(
        {
          rule: "session-low-entropy-id",
          severity: "high",
          title: `Session ID entropy below 128 bits (${c.id_entropy_bits} bits)`,
          description: "Insufficient entropy allows session-ID guessing.",
          remediation: "Generate session IDs with a CSPRNG of at least 128 bits.",
          cwe: ["CWE-330"],
          references: REFS,
          tags: ["session"],
        },
        source,
      ),
    );
  }
  return findings;
}
