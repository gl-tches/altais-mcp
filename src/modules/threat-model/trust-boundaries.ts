// Trust boundary analyzer.
//
// Walks the data flows in an architecture, identifies flows whose
// endpoints sit in different trust zones, and emits Finding objects
// for missing controls at the crossing (encryption, authentication,
// input validation).

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import type { Architecture, Component, DataFlow } from "./types.js";

const TRUSTED_ZONE = /^(?:internal|trusted|core|prod|production|backend|private)$/i;
const UNTRUSTED_ZONE = /^(?:internet|public|untrusted|external|user)$/i;
const ADMIN_ZONE = /^(?:admin|management|control[- ]?plane)$/i;

const REFS = ["https://cwe.mitre.org/data/definitions/501.html"];

function zoneRank(zone: string | undefined): number {
  if (!zone) return 1;
  if (UNTRUSTED_ZONE.test(zone)) return 0;
  if (ADMIN_ZONE.test(zone)) return 3;
  if (TRUSTED_ZONE.test(zone)) return 2;
  return 1;
}

function isEncrypted(flow: DataFlow): boolean {
  if (flow.encrypted === true) return true;
  return /^(?:https|tls|wss|mtls|grpcs|sftp|ssh|quic)/i.test(flow.protocol ?? "");
}

function hasAuth(flow: DataFlow): boolean {
  return (
    typeof flow.auth === "string" && flow.auth.length > 0 && flow.auth.toLowerCase() !== "none"
  );
}

interface BoundaryCrossing {
  readonly flow: DataFlow;
  readonly from_zone: string;
  readonly to_zone: string;
  readonly direction: "ingress" | "egress" | "lateral";
}

export interface BoundaryReport {
  readonly crossings: readonly BoundaryCrossing[];
  readonly findings: readonly Finding[];
  readonly summary: {
    readonly total_crossings: number;
    readonly ingress: number;
    readonly egress: number;
    readonly lateral: number;
  };
}

export function analyzeTrustBoundaries(architecture: Architecture): BoundaryReport {
  const components = new Map<string, Component>();
  for (const c of architecture.components) components.set(c.name, c);

  const crossings: BoundaryCrossing[] = [];
  const findings: Finding[] = [];

  for (const flow of architecture.data_flows ?? []) {
    const from = components.get(flow.from);
    const to = components.get(flow.to);
    const fromZone = from?.trust_zone ?? inferZone(flow.from);
    const toZone = to?.trust_zone ?? inferZone(flow.to);
    if (fromZone === toZone) continue;

    const fromRank = zoneRank(fromZone);
    const toRank = zoneRank(toZone);
    const direction: BoundaryCrossing["direction"] =
      fromRank < toRank ? "ingress" : fromRank > toRank ? "egress" : "lateral";

    crossings.push({ flow, from_zone: fromZone, to_zone: toZone, direction });
    findings.push(...crossingFindings(flow, fromZone, toZone, direction));
  }

  const summary = {
    total_crossings: crossings.length,
    ingress: crossings.filter((c) => c.direction === "ingress").length,
    egress: crossings.filter((c) => c.direction === "egress").length,
    lateral: crossings.filter((c) => c.direction === "lateral").length,
  };

  return { crossings, findings, summary };
}

function inferZone(componentName: string): string {
  if (/internet|public|external|user/i.test(componentName)) return "untrusted";
  if (/admin|management/i.test(componentName)) return "admin";
  return "internal";
}

function crossingFindings(
  flow: DataFlow,
  fromZone: string,
  toZone: string,
  direction: BoundaryCrossing["direction"],
): readonly Finding[] {
  const findings: Finding[] = [];
  const flowLabel = `${flow.from} -> ${flow.to}`;
  const baseTags = ["threat-model", "trust-boundary", `direction:${direction}`];

  if (!isEncrypted(flow)) {
    findings.push(
      buildFinding({
        rule: "boundary-cleartext",
        severity: direction === "ingress" ? "high" : "medium",
        title: `Cleartext crossing of trust boundary (${fromZone} → ${toZone})`,
        description: `Flow \`${flow.data}\` (${flowLabel}) crosses from \`${fromZone}\` to \`${toZone}\` without a declared encryption layer. A network attacker on the path between zones can read or tamper with traffic.`,
        remediation:
          "Require TLS (or mTLS for service-to-service) for every cross-zone flow. Set `encrypted: true` or a TLS-implying protocol on the flow description.",
        cwe: ["CWE-319", "CWE-501"],
        references: REFS,
        evidence: `${flowLabel} protocol=${flow.protocol ?? "(unspecified)"} data=${flow.data}`,
        tags: baseTags,
      }),
    );
  }
  if (!hasAuth(flow) && direction !== "egress") {
    findings.push(
      buildFinding({
        rule: "boundary-unauthenticated",
        severity: direction === "ingress" ? "high" : "medium",
        title: `Unauthenticated crossing of trust boundary (${fromZone} → ${toZone})`,
        description: `Flow \`${flow.data}\` (${flowLabel}) crosses zones without a declared authentication scheme. The receiver cannot verify that the caller is who it claims to be.`,
        remediation:
          "Authenticate both endpoints (mTLS, signed identity tokens, HMAC). Document the chosen scheme in the flow's `auth` field.",
        cwe: ["CWE-306", "CWE-287", "CWE-501"],
        references: REFS,
        evidence: `${flowLabel} auth=${flow.auth ?? "(unspecified)"}`,
        tags: baseTags,
      }),
    );
  }
  if (direction === "ingress") {
    findings.push(
      buildFinding({
        rule: "boundary-ingress-validation",
        severity: "medium",
        title: `Ingress from untrusted zone requires explicit input validation`,
        description: `Flow \`${flow.data}\` (${flowLabel}) crosses from \`${fromZone}\` (less trusted) into \`${toZone}\` (more trusted). Every field in the request must be validated against a schema before use.`,
        remediation:
          "Validate inputs at the boundary against an allowlist schema (types, ranges, formats). Reject unknown fields.",
        cwe: ["CWE-20", "CWE-501"],
        references: REFS,
        evidence: `${flowLabel} data=${flow.data}`,
        tags: baseTags,
      }),
    );
  }
  return findings;
}

interface FindingDraft {
  readonly rule: string;
  readonly severity: Finding["severity"];
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly evidence?: string;
  readonly tags: readonly string[];
}

function buildFinding(draft: FindingDraft): Finding {
  const location: FindingLocation | undefined = undefined;
  return {
    id: findingId("threat_model", draft.rule, location, draft.evidence ?? ""),
    module: "threat_model",
    rule: draft.rule,
    severity: draft.severity,
    cwe: draft.cwe,
    title: draft.title,
    description: draft.description,
    ...(draft.evidence !== undefined ? { evidence: draft.evidence } : {}),
    remediation: draft.remediation,
    references: draft.references,
    tags: draft.tags,
    status: "open",
  };
}
