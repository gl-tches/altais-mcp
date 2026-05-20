// JWT auditor.
//
// Accepts:
// - source: code that uses a JWT library (we check verify/decode call shape)
// - token: a JWT string (we decode header + payload and check claims)
// - config: structured description of the verifier's accepted claims

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface JwtVerifyConfig {
  readonly accepted_algorithms?: readonly string[];
  readonly required_iss?: readonly string[];
  readonly required_aud?: readonly string[];
  readonly clock_skew_seconds?: number;
  readonly verify_exp?: boolean;
  readonly verify_nbf?: boolean;
  readonly jwks_uri?: string;
}

export interface JwtAuditInput {
  readonly source?: string;
  readonly token?: string;
  readonly config?: JwtVerifyConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc7519",
  "https://datatracker.ietf.org/doc/html/rfc8725",
];

const SOURCE_PATTERNS: readonly {
  readonly rule: string;
  readonly regex: RegExp;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}[] = [
  {
    rule: "jwt-decode-without-verify",
    regex: /\bjwt\.decode\s*\(/i,
    severity: "high",
    title: "`jwt.decode()` used (no signature verification)",
    description:
      "`decode` parses the JWT but does not verify the signature. Any value returned should be treated as untrusted.",
    remediation: "Use `jwt.verify(token, key, options)` with a pinned algorithm.",
    cwe: ["CWE-347"],
  },
  {
    rule: "jwt-verify-no-algorithms",
    regex: /\bjwt\.verify\s*\([^)]*\)/,
    severity: "medium",
    title: "`jwt.verify()` call without an `algorithms` option",
    description:
      "Without `algorithms`, some libraries default-accept any algorithm in the token header, enabling algorithm-confusion attacks (alg: none, HS256 with public key).",
    remediation:
      "Pass `{ algorithms: ['RS256'] }` (or your specific list). Reject everything else.",
    cwe: ["CWE-347"],
  },
  {
    rule: "jwt-alg-none",
    regex: /["']alg["']\s*:\s*["']none["']/i,
    severity: "critical",
    title: "JWT verifier accepts `alg: none`",
    description: "Unsigned JWTs accepted by the verifier let attackers forge any token.",
    remediation: "Pin acceptable algorithms; reject `none` explicitly.",
    cwe: ["CWE-347"],
  },
  {
    rule: "jwt-hs256-with-public-key",
    regex: /jwt\.verify[^)]*algorithms\s*:\s*\[[^\]]*HS\d+[^\]]*\][^)]*publicKey/is,
    severity: "critical",
    title: "HS* algorithm allowed against a public key",
    description:
      "If the verifier accepts HS256 with a public key as the secret, an attacker can forge tokens by signing with the public key.",
    remediation:
      "Use one of HS* or RS*/ES*/PS*, never both. Separate signing keys per algorithm family.",
    cwe: ["CWE-347"],
  },
];

export function auditJwt(input: JwtAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source) findings.push(...scanSource(input.source, input.filename));
  if (input.token) findings.push(...auditToken(input.token, input.filename));
  if (input.config) findings.push(...auditConfig(input.config, input.filename));
  return findings;
}

function scanSource(source: string, filename: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  for (const pat of SOURCE_PATTERNS) {
    const regex = new RegExp(
      pat.regex.source,
      pat.regex.flags.includes("g") ? pat.regex.flags : `${pat.regex.flags}g`,
    );
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      if (pat.rule === "jwt-verify-no-algorithms" && /algorithms\s*:/i.test(m[0])) {
        if (m[0].length === 0) regex.lastIndex += 1;
        continue;
      }
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
            tags: ["jwt"],
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

function base64UrlDecode(s: string): string | null {
  try {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    return Buffer.from(padded + pad, "base64").toString("utf8");
  } catch {
    return null;
  }
}

function auditToken(token: string, filename: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const parts = token.split(".");
  if (parts.length !== 3) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-malformed",
          severity: "low",
          title: "Token does not look like a JWT (expected 3 base64url segments)",
          description: "Provided token has fewer or more than 3 dot-separated segments.",
          remediation: "Ensure the token is a JWS-encoded JWT, not a JWE or opaque token.",
          cwe: ["CWE-345"],
          references: REFS,
          evidence: `${parts.length} segment(s)`,
          tags: ["jwt"],
        },
        filename,
      ),
    );
    return findings;
  }
  const headerJson = parts[0] ? base64UrlDecode(parts[0]) : null;
  const payloadJson = parts[1] ? base64UrlDecode(parts[1]) : null;
  if (!headerJson || !payloadJson) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-malformed",
          severity: "low",
          title: "Could not base64url-decode the JWT header / payload",
          description: "One of the segments is not valid base64url.",
          remediation: "Pass a well-formed JWT.",
          cwe: ["CWE-345"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
    return findings;
  }
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(headerJson) as Record<string, unknown>;
    payload = JSON.parse(payloadJson) as Record<string, unknown>;
  } catch {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-malformed",
          severity: "low",
          title: "JWT header / payload is not valid JSON",
          description: "Decoded segments did not parse as JSON.",
          remediation: "Pass a well-formed JWT.",
          cwe: ["CWE-345"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
    return findings;
  }

  const alg = typeof header.alg === "string" ? header.alg : "";
  if (alg.toLowerCase() === "none") {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-alg-none",
          severity: "critical",
          title: "JWT header declares `alg: none`",
          description: "Unsigned JWTs are unverifiable; rejecting them is mandatory.",
          remediation: "Reject any token whose header `alg` is `none`.",
          cwe: ["CWE-347"],
          references: REFS,
          evidence: `alg=${alg}`,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  } else if (/^HS\d+$/i.test(alg)) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-symmetric-alg",
          severity: "medium",
          title: `JWT uses symmetric algorithm: ${alg}`,
          description:
            "Symmetric JWTs require sharing the signing secret with every verifier. Asymmetric algorithms scale better and resist verifier compromise.",
          remediation: "Prefer RS256 / ES256 / EdDSA where keys cross trust boundaries.",
          cwe: ["CWE-326"],
          references: REFS,
          evidence: `alg=${alg}`,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  }

  const exp = typeof payload.exp === "number" ? payload.exp : undefined;
  const now = Math.floor(Date.now() / 1000);
  if (exp === undefined) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-no-exp",
          severity: "high",
          title: "JWT has no `exp` claim",
          description: "Tokens with no expiry are valid forever once issued.",
          remediation: "Always set `exp`; the verifier should reject tokens without it.",
          cwe: ["CWE-613"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  } else if (exp - now > 30 * 86_400) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-long-lived",
          severity: "medium",
          title: `JWT lifetime exceeds 30 days (${Math.round((exp - now) / 86_400)}d)`,
          description: "Long-lived access tokens widen the impact of a token leak.",
          remediation:
            "Shorten access-token lifetime; use rotating refresh tokens for re-issuance.",
          cwe: ["CWE-613"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  }
  if (typeof payload.aud !== "string" && !Array.isArray(payload.aud)) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-no-aud",
          severity: "medium",
          title: "JWT has no `aud` claim",
          description: "Without `aud`, a token issued for one service can be replayed at another.",
          remediation: "Set `aud` to the resource server URI; require verifiers to validate it.",
          cwe: ["CWE-294"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  }
  if (typeof payload.iss !== "string") {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-no-iss",
          severity: "low",
          title: "JWT has no `iss` claim",
          description: "Without `iss`, the verifier cannot bind the token to a specific issuer.",
          remediation: "Set `iss` to the issuer URI and check it on the verifier.",
          cwe: ["CWE-345"],
          references: REFS,
          tags: ["jwt"],
        },
        filename,
      ),
    );
  }
  return findings;
}

function auditConfig(c: JwtVerifyConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const algs = (c.accepted_algorithms ?? []).map((a) => a.toLowerCase());
  if (algs.length === 0) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-verify-no-algorithms",
          severity: "high",
          title: "Verifier accepts any signing algorithm",
          description:
            "Without an `accepted_algorithms` allowlist, the verifier honors the token's own `alg` header.",
          remediation: "Pin acceptable algorithms (e.g. `['RS256']`).",
          cwe: ["CWE-347"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  if (algs.includes("none")) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-alg-none",
          severity: "critical",
          title: "Verifier explicitly accepts `alg: none`",
          description: "Unsigned JWTs are unverifiable.",
          remediation: "Remove `none` from the algorithm allowlist.",
          cwe: ["CWE-347"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  const hasSymmetric = algs.some((a) => a.startsWith("hs"));
  const hasAsymmetric = algs.some((a) => /^(rs|es|ps|ed)/.test(a));
  if (hasSymmetric && hasAsymmetric) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-mixed-algorithm-families",
          severity: "high",
          title: "Verifier accepts both symmetric and asymmetric algorithms",
          description:
            "Mixing HS* and RS*/ES* enables algorithm-confusion (token signed by attacker using the public key as HMAC secret).",
          remediation:
            "Choose one family. If migration is needed, route by `kid` and reject tokens whose algorithm does not match the resolved key.",
          cwe: ["CWE-347"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  if (c.verify_exp === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-verify-exp-disabled",
          severity: "high",
          title: "Verifier does not check `exp`",
          description: "Expired tokens accepted indefinitely.",
          remediation: "Enable `exp` verification with a small clock skew (60s).",
          cwe: ["CWE-613"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  if ((c.required_aud ?? []).length === 0) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-no-required-aud",
          severity: "medium",
          title: "Verifier has no required `aud`",
          description: "Tokens for another service may be replayed here.",
          remediation: "Set the verifier's required audience to this resource server.",
          cwe: ["CWE-294"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  if ((c.clock_skew_seconds ?? 0) > 300) {
    findings.push(
      buildAuthFinding(
        {
          rule: "jwt-clock-skew-too-large",
          severity: "low",
          title: `Verifier clock skew is ${c.clock_skew_seconds}s`,
          description: "Large clock-skew windows extend the lifetime of expired tokens.",
          remediation: "Cap clock skew at 60s; sync hosts via NTP.",
          cwe: ["CWE-693"],
          references: REFS,
          tags: ["jwt"],
        },
        source,
      ),
    );
  }
  return findings;
}
