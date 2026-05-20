// Zero-trust architecture assessor (altais_check_zero_trust).
//
// Scores an architecture description against the tenets of NIST SP
// 800-207 (Zero Trust Architecture). Each principle is a boolean in the
// input; any principle that is `false` or absent produces a Finding with
// 800-207-aligned remediation. The analyzer also returns a maturity
// summary finding describing how many tenets are satisfied.

import type { Finding, Severity } from "../../core/types.js";
import { buildInfraFinding } from "./finding.js";

export interface ZeroTrustConfig {
  readonly verify_explicitly?: boolean;
  readonly least_privilege_access?: boolean;
  readonly assume_breach?: boolean;
  readonly mfa_enforced?: boolean;
  readonly microsegmentation?: boolean;
  readonly device_trust_verification?: boolean;
  readonly continuous_verification?: boolean;
  readonly no_implicit_network_trust?: boolean;
  readonly encrypted_internal_traffic?: boolean;
  readonly per_request_authorization?: boolean;
  readonly centralized_policy_engine?: boolean;
}

export interface ZeroTrustInput {
  readonly config: ZeroTrustConfig;
  readonly filename?: string;
}

const REFS = [
  "https://csrc.nist.gov/pubs/sp/800/207/final",
  "https://cwe.mitre.org/data/definitions/284.html",
  "https://owasp.org/www-project-top-ten/",
];

interface Principle {
  readonly key: keyof ZeroTrustConfig;
  readonly rule: string;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
}

// The eleven tenets checked, derived from NIST SP 800-207 §2.1.
const PRINCIPLES: readonly Principle[] = [
  {
    key: "verify_explicitly",
    rule: "zt-verify-explicitly-missing",
    severity: "medium",
    title: "Access is not verified explicitly on every request",
    description:
      "NIST SP 800-207 requires every access decision to be made dynamically from all available signals — identity, device, location, workload. Granting access without explicit verification reintroduces implicit trust.",
    remediation:
      "Route every resource request through a policy decision point that evaluates identity, device posture, and context before granting access. Do not trust requests based on network position alone.",
    cwe: ["CWE-284", "CWE-285"],
  },
  {
    key: "least_privilege_access",
    rule: "zt-least-privilege-missing",
    severity: "medium",
    title: "Least-privilege access is not enforced",
    description:
      "SP 800-207 calls for access scoped to the minimum needed for the task, ideally just-in-time and just-enough. Broad standing privileges enlarge what a single compromised identity can reach.",
    remediation:
      "Scope every grant to the minimum resources and duration required. Use just-in-time elevation, time-bound roles, and regular access reviews to remove standing privilege.",
    cwe: ["CWE-272", "CWE-269"],
  },
  {
    key: "assume_breach",
    rule: "zt-assume-breach-missing",
    severity: "medium",
    title: "Architecture does not assume breach",
    description:
      "Zero trust assumes the environment is already hostile and designs to limit blast radius. Without this posture, controls focus on perimeter prevention and an internal foothold spreads unchecked.",
    remediation:
      "Design for containment: segment workloads, minimize blast radius, encrypt everything, and instrument for detection. Run breach-assumption exercises to validate that lateral movement is constrained.",
    cwe: ["CWE-284"],
  },
  {
    key: "mfa_enforced",
    rule: "zt-mfa-not-enforced",
    severity: "high",
    title: "Multi-factor authentication is not enforced",
    description:
      "Single-factor authentication leaves every account one phished or reused password away from takeover. SP 800-207 treats strong, phishing-resistant authentication as foundational to verifying identity.",
    remediation:
      "Enforce MFA for all users and administrative access, preferring phishing-resistant factors (FIDO2 / WebAuthn passkeys, hardware tokens) over SMS or one-time codes.",
    cwe: ["CWE-308", "CWE-287"],
  },
  {
    key: "microsegmentation",
    rule: "zt-microsegmentation-missing",
    severity: "medium",
    title: "Network is not microsegmented",
    description:
      "SP 800-207 expects fine-grained segmentation so each workload only reaches what it needs. Without microsegmentation a compromised host can move laterally across a large flat trust domain.",
    remediation:
      "Apply identity- or workload-aware microsegmentation with a default-deny policy between segments, so each workload communicates only with its explicitly permitted peers.",
    cwe: ["CWE-1008", "CWE-668"],
  },
  {
    key: "device_trust_verification",
    rule: "zt-device-trust-missing",
    severity: "medium",
    title: "Device trust is not verified before access",
    description:
      "Zero trust evaluates the requesting asset's security posture as an input to every access decision. Ignoring device state lets a compromised or unmanaged endpoint reach protected resources with valid credentials.",
    remediation:
      "Require device enrollment and posture checks (patch level, disk encryption, EDR health) as a condition of access, and re-evaluate posture continuously rather than only at login.",
    cwe: ["CWE-287"],
  },
  {
    key: "continuous_verification",
    rule: "zt-continuous-verification-missing",
    severity: "medium",
    title: "Sessions are not continuously verified",
    description:
      "SP 800-207 treats trust as never permanent: sessions must be re-evaluated as context changes. A session validated only at login stays valid even after the device or identity is compromised.",
    remediation:
      "Continuously re-evaluate active sessions against current risk signals, with adaptive step-up authentication and short-lived tokens that force periodic re-verification.",
    cwe: ["CWE-613", "CWE-287"],
  },
  {
    key: "no_implicit_network_trust",
    rule: "zt-implicit-network-trust",
    severity: "high",
    title: "Network location still confers implicit trust",
    description:
      "The defining tenet of zero trust is that being on the internal network grants nothing. Treating the internal network as trusted lets any attacker with a foothold reach resources without further checks.",
    remediation:
      "Remove network-location-based trust entirely. Authenticate and authorize every request regardless of origin, and treat the internal network as no more trusted than the public internet.",
    cwe: ["CWE-284", "CWE-668"],
  },
  {
    key: "encrypted_internal_traffic",
    rule: "zt-internal-traffic-unencrypted",
    severity: "high",
    title: "Internal (east-west) traffic is not encrypted",
    description:
      "SP 800-207 requires all communication to be secured regardless of network location. Unencrypted internal traffic can be sniffed or tampered with by anything sharing the network segment.",
    remediation:
      "Encrypt all east-west traffic with mutually authenticated TLS, for example via a service mesh that issues and rotates per-workload identities automatically.",
    cwe: ["CWE-319"],
  },
  {
    key: "per_request_authorization",
    rule: "zt-per-request-authz-missing",
    severity: "medium",
    title: "Authorization is not evaluated per request",
    description:
      "SP 800-207 makes access a per-session, per-request decision rather than a one-time grant. Authorizing only at session start lets revoked or changed permissions linger until the session ends.",
    remediation:
      "Evaluate authorization on every request at the policy enforcement point, so permission changes and revocations take effect immediately instead of at next login.",
    cwe: ["CWE-285", "CWE-284"],
  },
  {
    key: "centralized_policy_engine",
    rule: "zt-policy-engine-missing",
    severity: "medium",
    title: "No centralized policy engine governs access decisions",
    description:
      "SP 800-207's architecture centers on a policy decision point that consistently evaluates all access. Scattered, per-service authorization logic drifts, leaves gaps, and cannot be audited as a whole.",
    remediation:
      "Centralize access decisions in a policy engine (policy decision point) that all enforcement points consult, giving consistent, auditable, and uniformly updatable policy.",
    cwe: ["CWE-284"],
  },
];

export function checkZeroTrust(input: ZeroTrustInput): readonly Finding[] {
  const file = input.filename;
  const cfg = input.config;
  const findings: Finding[] = [];

  let satisfied = 0;
  for (const p of PRINCIPLES) {
    const value = cfg[p.key];
    if (value === true) {
      satisfied++;
      continue;
    }
    findings.push(
      mk(
        file,
        p.rule,
        p.severity,
        p.title,
        p.description,
        p.remediation,
        p.cwe,
        `${p.key}=${value === false ? "false" : "missing"}`,
      ),
    );
  }

  // ── Maturity summary ────────────────────────────────────────────────────
  const total = PRINCIPLES.length;
  const gaps = total - satisfied;
  const maturity: string =
    satisfied === total
      ? "advanced"
      : satisfied >= 8
        ? "intermediate"
        : satisfied >= 4
          ? "traditional"
          : "ad-hoc";
  if (gaps > 0) {
    findings.push(
      mk(
        file,
        "zt-maturity-summary",
        gaps >= total / 2 ? "medium" : "low",
        `Zero-trust maturity: ${maturity} — ${String(satisfied)} of ${String(total)} NIST SP 800-207 tenets satisfied`,
        `The architecture satisfies ${String(satisfied)} of ${String(total)} zero-trust tenets, leaving ${String(gaps)} gap(s). NIST SP 800-207 describes zero trust as a journey across tenets rather than a single product; the current posture is best characterized as "${maturity}".`,
        "Treat the individual tenet findings as a prioritized backlog. Close the high-severity gaps (MFA, encrypted east-west traffic, no implicit network trust) first, then iterate on the remaining tenets toward an advanced posture.",
        ["CWE-284"],
        `satisfied=${String(satisfied)}/${String(total)} maturity=${maturity}`,
      ),
    );
  }

  return findings;
}

function mk(
  file: string | undefined,
  rule: string,
  severity: Severity,
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
): Finding {
  return buildInfraFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["zero-trust", "nist-800-207"],
    },
    file,
  );
}
