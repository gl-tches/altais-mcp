// FIDO2 / Passkey (WebAuthn) auditor.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding, lineAt } from "./finding.js";

export interface PasskeyConfig {
  readonly rp_id?: string;
  readonly user_verification?: "required" | "preferred" | "discouraged";
  readonly resident_key?: "required" | "preferred" | "discouraged";
  readonly attestation?: "none" | "indirect" | "direct" | "enterprise";
  readonly origins?: readonly string[];
  readonly challenge_entropy_bits?: number;
  readonly stores_credential_id?: boolean;
  readonly stores_aaguid?: boolean;
  readonly stores_sign_count?: boolean;
}

export interface PasskeyAuditInput {
  readonly source?: string;
  readonly config?: PasskeyConfig;
  readonly filename?: string;
}

const REFS = ["https://www.w3.org/TR/webauthn-3/", "https://www.rfc-editor.org/rfc/rfc9709.html"];

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
    rule: "passkey-user-verification-discouraged",
    regex: /userVerification\s*:\s*["']discouraged["']/i,
    severity: "medium",
    title: "WebAuthn userVerification set to `discouraged`",
    description:
      "Without user verification, a passkey behaves like an unlocked credential — proximity to the device is the only factor.",
    remediation:
      "Set `userVerification: 'required'` (or `'preferred'`) so authenticators that support PIN/biometric prompt for it.",
    cwe: ["CWE-1390"],
  },
  {
    rule: "passkey-attestation-direct-default",
    regex: /attestation\s*:\s*["']direct["']/i,
    severity: "info",
    title: "WebAuthn `attestation: direct` requested",
    description:
      "Direct attestation may reveal authenticator make/model. Only use it if you actually need that information (enterprise fleets, regulated environments).",
    remediation:
      "Use `attestation: 'none'` unless your threat model requires attested authenticators.",
    cwe: ["CWE-200"],
  },
  {
    rule: "passkey-no-challenge-binding",
    regex: /credentials\.create\s*\(\s*\{[^}]{0,200}\}\s*\)/i,
    severity: "medium",
    title: "WebAuthn create() call may not include a server-issued challenge",
    description:
      "If the challenge is generated client-side or hard-coded, replay attacks are trivial.",
    remediation:
      "Fetch a CSPRNG-generated challenge from the server immediately before the call; bind it to the user session.",
    cwe: ["CWE-294"],
  },
];

export function auditPasskey(input: PasskeyAuditInput): readonly Finding[] {
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
      if (pat.rule === "passkey-no-challenge-binding" && /challenge/i.test(m[0])) {
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
            tags: ["passkey", "webauthn"],
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

function auditConfig(c: PasskeyConfig, source: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  if (c.user_verification === "discouraged") {
    findings.push(
      buildAuthFinding(
        {
          rule: "passkey-user-verification-discouraged",
          severity: "medium",
          title: "userVerification=discouraged",
          description:
            "Passkeys without user verification rely on proximity alone for the second factor.",
          remediation: "Set `user_verification: 'required'`.",
          cwe: ["CWE-1390"],
          references: REFS,
          evidence: "user_verification=discouraged",
          tags: ["passkey"],
        },
        source,
      ),
    );
  }
  if (c.rp_id !== undefined && c.origins) {
    const rp = c.rp_id;
    const mismatched = c.origins.filter((o) => {
      try {
        const host = new URL(o).host;
        return !host.endsWith(rp);
      } catch {
        return true;
      }
    });
    if (mismatched.length > 0) {
      findings.push(
        buildAuthFinding(
          {
            rule: "passkey-origin-rp-mismatch",
            severity: "high",
            title: "Origin host does not align with rp_id",
            description:
              "WebAuthn requires that the relying-party ID be a registrable suffix of the origin host. Mismatch will be rejected by the browser, or worse, point at the wrong RP if accepted.",
            remediation: `Align origins with rp_id=${rp}.`,
            cwe: ["CWE-346"],
            references: REFS,
            evidence: `rp_id=${rp}, mismatched=${mismatched.join(",")}`,
            tags: ["passkey"],
          },
          source,
        ),
      );
    }
  }
  if ((c.challenge_entropy_bits ?? 128) < 128) {
    findings.push(
      buildAuthFinding(
        {
          rule: "passkey-low-challenge-entropy",
          severity: "high",
          title: `WebAuthn challenge entropy below 128 bits (${c.challenge_entropy_bits} bits)`,
          description: "Insufficient challenge entropy enables replay attacks.",
          remediation: "Generate at least 128 bits (16 bytes) of CSPRNG output per challenge.",
          cwe: ["CWE-330"],
          references: REFS,
          tags: ["passkey"],
        },
        source,
      ),
    );
  }
  if (c.stores_sign_count === false) {
    findings.push(
      buildAuthFinding(
        {
          rule: "passkey-no-sign-count-tracking",
          severity: "low",
          title: "Sign-count not tracked",
          description:
            "Many authenticators expose a monotonic sign counter; tracking it detects cloned credentials.",
          remediation: "Persist the sign-count per credential and reject decreasing values.",
          cwe: ["CWE-294"],
          references: REFS,
          tags: ["passkey"],
        },
        source,
      ),
    );
  }
  return findings;
}
