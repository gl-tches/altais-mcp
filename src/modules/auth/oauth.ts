// OAuth 2.1 / OIDC implementation auditor.
//
// Accepts either:
// - source: code snippet for pattern-based checks
// - config: structured description of the OAuth client/server config
//
// Both produce Findings. OAuth 2.1 deprecates the implicit and password
// grants, mandates PKCE for every authorization-code flow, and forbids
// wildcard redirect URIs — checks below reflect that baseline.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface OAuthAuditConfig {
  readonly flow?:
    | "authorization_code"
    | "client_credentials"
    | "device_code"
    | "implicit"
    | "password";
  readonly pkce?: { readonly used: boolean; readonly method?: "S256" | "plain" };
  readonly redirect_uris?: readonly string[];
  readonly uses_state?: boolean;
  readonly uses_nonce_for_oidc?: boolean;
  readonly token_endpoint_auth?:
    | "client_secret_post"
    | "client_secret_basic"
    | "private_key_jwt"
    | "none";
  readonly token_storage?: "httponly_cookie" | "memory" | "localStorage" | "sessionStorage";
  readonly refresh_token_rotation?: boolean;
  readonly scope?: readonly string[];
}

export interface OAuthAuditInput {
  readonly source?: string;
  readonly config?: OAuthAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
  "https://www.rfc-editor.org/rfc/rfc9700.html",
  "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1",
];

interface Pattern {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

const SOURCE_PATTERNS: readonly Pattern[] = [
  {
    rule: "oauth-implicit-flow",
    regex: /\bresponse_type\s*=\s*["']?(?:token|id_token)\b/i,
    severity: "high",
    title: "Implicit flow in use (response_type=token / id_token)",
    description:
      "OAuth 2.1 deprecates the implicit grant. Access tokens are returned in the URL fragment and end up in browser history and Referer headers.",
    remediation: "Switch to authorization_code + PKCE. Set `response_type=code`.",
    cwe: ["CWE-287", "CWE-200"],
  },
  {
    rule: "oauth-password-grant",
    regex: /\bgrant_type\s*=\s*["']?password\b/i,
    severity: "high",
    title: "Resource Owner Password Credentials grant in use",
    description:
      "The password grant requires the client to handle the user's credentials, which OAuth 2.1 deprecates. Use authorization_code + PKCE so the user authenticates directly with the AS.",
    remediation: "Migrate to authorization_code + PKCE. Use device_code for non-browser clients.",
    cwe: ["CWE-287"],
  },
  {
    rule: "oauth-pkce-plain",
    regex: /code_challenge_method\s*[=:]\s*["']?plain\b/i,
    severity: "high",
    title: "PKCE configured with method=plain",
    description:
      "PKCE `plain` provides no protection against authorization-code interception. The verifier is sent in the clear after capture.",
    remediation:
      "Set `code_challenge_method=S256` and derive `code_challenge` as `BASE64URL(SHA256(code_verifier))`.",
    cwe: ["CWE-326"],
  },
  {
    rule: "oauth-wildcard-redirect",
    regex: /\bredirect_uri\s*[:=]\s*["'][^"']*\*[^"']*["']/i,
    severity: "critical",
    title: "Wildcard in redirect_uri",
    description:
      "Wildcards in redirect_uri are forbidden by OAuth 2.1. They enable open-redirect attacks that intercept authorization codes.",
    remediation: "Allowlist the exact redirect_uris. No wildcards, no path-prefix matching.",
    cwe: ["CWE-601", "CWE-942"],
  },
  {
    rule: "oauth-token-in-localstorage",
    regex: /localStorage\s*\.\s*setItem\s*\(\s*["'](?:access_token|id_token|refresh_token)/i,
    severity: "high",
    title: "OAuth token stored in localStorage",
    description:
      "Tokens in localStorage are reachable from any script on the page, so any XSS escalates to token theft.",
    remediation:
      "Use HttpOnly cookies (for browser clients) or in-memory storage with silent refresh.",
    cwe: ["CWE-540", "CWE-922"],
  },
  {
    rule: "oauth-token-endpoint-auth-none",
    regex: /token_endpoint_auth_method\s*[:=]\s*["']none["']/i,
    severity: "medium",
    title: "Public client with token_endpoint_auth_method=none",
    description:
      "Public clients (SPAs / native apps) cannot keep a secret, so `none` is correct. Confirm this is the intent and not a misconfiguration of a confidential client.",
    remediation:
      "For confidential clients, use `client_secret_basic` or — preferably — `private_key_jwt`.",
    cwe: ["CWE-287"],
  },
];

export function auditOAuth(input: OAuthAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const source = input.source ?? "";
  if (source.length > 0) {
    for (const pat of SOURCE_PATTERNS) {
      const regex = new RegExp(
        pat.regex.source,
        pat.regex.flags.includes("g") ? pat.regex.flags : `${pat.regex.flags}g`,
      );
      let m: RegExpExecArray | null;
      while ((m = regex.exec(source)) !== null) {
        const evidence = m[0].slice(0, 200);
        const line = lineAt(source, m.index);
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
              evidence,
              tags: ["oauth"],
              line,
            },
            input.filename,
          ),
        );
        if (m[0].length === 0) regex.lastIndex += 1;
      }
    }
  }
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

function auditConfig(c: OAuthAuditConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  if (c.flow === "implicit" || c.flow === "password") {
    findings.push(
      buildAuthFinding(
        {
          rule: c.flow === "implicit" ? "oauth-implicit-flow" : "oauth-password-grant",
          severity: "high",
          title: `OAuth flow \`${c.flow}\` is deprecated in OAuth 2.1`,
          description:
            c.flow === "implicit"
              ? "Implicit grants return tokens in the URL fragment. OAuth 2.1 removes the grant."
              : "Password grant exposes user credentials to the client. OAuth 2.1 removes the grant.",
          remediation: "Switch to authorization_code + PKCE; device_code for non-browser clients.",
          cwe: ["CWE-287"],
          references: REFS,
          evidence: `flow=${c.flow}`,
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  if (c.flow === "authorization_code" && !c.pkce?.used) {
    findings.push(
      buildAuthFinding(
        {
          rule: "oauth-no-pkce",
          severity: "high",
          title: "Authorization-code flow without PKCE",
          description:
            "OAuth 2.1 mandates PKCE for every authorization-code flow — including confidential clients.",
          remediation:
            "Generate a `code_verifier`, send `code_challenge=BASE64URL(SHA256(verifier))` and `code_challenge_method=S256`.",
          cwe: ["CWE-693"],
          references: REFS,
          evidence: "pkce.used=false",
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  if (c.pkce?.used === true && c.pkce.method === "plain") {
    findings.push(
      buildAuthFinding(
        {
          rule: "oauth-pkce-plain",
          severity: "high",
          title: "PKCE method=plain",
          description: "Plain PKCE offers no protection if the authorization code is intercepted.",
          remediation: "Use `code_challenge_method=S256`.",
          cwe: ["CWE-326"],
          references: REFS,
          evidence: "pkce.method=plain",
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  for (const uri of c.redirect_uris ?? []) {
    if (uri.includes("*")) {
      findings.push(
        buildAuthFinding(
          {
            rule: "oauth-wildcard-redirect",
            severity: "critical",
            title: `Wildcard redirect_uri: ${uri}`,
            description: "Wildcards in redirect_uri are forbidden by OAuth 2.1.",
            remediation: "Allowlist the exact redirect_uris.",
            cwe: ["CWE-601", "CWE-942"],
            references: REFS,
            evidence: uri,
            tags: ["oauth"],
          },
          source,
        ),
      );
    }
    if (
      uri.startsWith("http://") &&
      !uri.startsWith("http://localhost") &&
      !uri.startsWith("http://127.")
    ) {
      findings.push(
        buildAuthFinding(
          {
            rule: "oauth-http-redirect",
            severity: "high",
            title: `Non-localhost redirect_uri over HTTP: ${uri}`,
            description: "Authorization codes returned to an HTTP URL can be intercepted.",
            remediation:
              "Use HTTPS redirect URIs in production. Localhost over HTTP is acceptable for native dev only.",
            cwe: ["CWE-319"],
            references: REFS,
            evidence: uri,
            tags: ["oauth"],
          },
          source,
        ),
      );
    }
  }
  if (c.uses_state === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "oauth-no-state",
          severity: "medium",
          title: "Authorization request without `state` parameter",
          description:
            "Without `state`, the client cannot bind the callback to the initiating session, enabling CSRF on the OAuth callback.",
          remediation:
            "Generate a cryptographic random `state`, store it server-side bound to the session, and verify on callback.",
          cwe: ["CWE-352"],
          references: REFS,
          evidence: "uses_state=false",
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  if (c.flow === "authorization_code" && c.uses_nonce_for_oidc === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "oidc-no-nonce",
          severity: "medium",
          title: "OIDC authorization request without `nonce`",
          description:
            "The `nonce` claim binds the ID token to the session and prevents replay across logins.",
          remediation:
            "Send a CSPRNG `nonce` in the auth request and verify it matches the claim in the ID token.",
          cwe: ["CWE-294"],
          references: REFS,
          evidence: "uses_nonce_for_oidc=false",
          tags: ["oauth", "oidc"],
        },
        source,
      ),
    );
  }
  if (c.token_storage === "localStorage" || c.token_storage === "sessionStorage") {
    findings.push(
      buildAuthFinding(
        {
          rule: "oauth-token-in-storage",
          severity: "high",
          title: `Token storage is ${c.token_storage}`,
          description:
            "Web storage is reachable from any script on the page. Any XSS escalates to token theft.",
          remediation: "Use HttpOnly cookies or in-memory tokens with silent refresh.",
          cwe: ["CWE-540", "CWE-922"],
          references: REFS,
          evidence: `token_storage=${c.token_storage}`,
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  if (c.refresh_token_rotation === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "oauth-no-refresh-rotation",
          severity: "medium",
          title: "Refresh tokens are not rotated",
          description:
            "Without rotation, a single stolen refresh token grants long-lived access. Rotation lets the AS detect replay.",
          remediation: "Rotate refresh tokens on every use. Revoke the chain on detected reuse.",
          cwe: ["CWE-613"],
          references: REFS,
          evidence: "refresh_token_rotation=false",
          tags: ["oauth"],
        },
        source,
      ),
    );
  }
  return findings;
}
