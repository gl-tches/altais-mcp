// gRPC security auditor (altais_audit_grpc).
//
// Accepts gRPC server/client source code and/or a structured description
// of the gRPC posture. Checks for the failures specific to gRPC services:
// insecure (plaintext) channels, no authentication interceptor, missing
// deadline / timeout propagation, server reflection left on in
// production, and unbounded message sizes.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface GrpcAuditConfig {
  readonly tls_enabled?: boolean;
  readonly insecure_channel?: boolean;
  readonly auth_interceptor?: boolean;
  readonly deadline_propagation?: boolean;
  readonly reflection_enabled?: boolean;
  readonly max_message_size?: boolean;
  readonly production?: boolean;
}

export interface GrpcAuditInput {
  readonly source?: string;
  readonly config?: GrpcAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://grpc.io/docs/guides/auth/",
  "https://datatracker.ietf.org/doc/html/rfc9113",
  "https://cwe.mitre.org/data/definitions/319.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "grpc-insecure-channel",
    regex:
      /\b(?:credentials\.createInsecure\s*\(|grpc\.insecure_channel\s*\(|InsecureChannelCredentials\s*\(|WithInsecure\s*\()/,
    severity: "high",
    title: "gRPC channel created without TLS",
    description:
      "An insecure gRPC channel (`createInsecure`, `insecure_channel`, `WithInsecure`, `InsecureChannelCredentials`) carries all RPC traffic — including metadata and bearer tokens — in cleartext.",
    remediation:
      "Use channel credentials backed by TLS (`createSsl`, `secure_channel`, `grpc.WithTransportCredentials`).",
    cwe: ["CWE-319"],
    tags: ["grpc", "transport"],
  },
  {
    rule: "grpc-reflection-enabled",
    regex: /\b(?:reflection\.register|enableReflection|reflection\.Register|ReflectionService)\b/,
    severity: "medium",
    title: "gRPC server reflection registered",
    description:
      "Server reflection lets any client enumerate the service's full set of methods and message types at runtime. Exposed in production it maps the entire API surface for an attacker.",
    remediation:
      "Register reflection only in non-production builds, or restrict it behind authentication.",
    cwe: ["CWE-200"],
    tags: ["grpc", "reflection"],
  },
];

function mk(
  filename: string | undefined,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
  tags: readonly string[],
): Finding {
  return buildProtocolFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["grpc", ...tags],
    },
    filename,
  );
}

function auditConfig(c: GrpcAuditConfig, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const inProd = c.production !== false;

  if (c.insecure_channel === true || c.tls_enabled === false) {
    findings.push(
      mk(
        file,
        "grpc-insecure-channel",
        "high",
        "gRPC channel does not use TLS",
        "An insecure gRPC channel transmits all RPC payloads and metadata — including authentication tokens — in cleartext, exposing them to any network attacker.",
        "Configure the channel with TLS credentials and disable insecure channels in all environments.",
        ["CWE-319"],
        c.insecure_channel === true ? "insecure_channel=true" : "tls_enabled=false",
        ["transport"],
      ),
    );
  }

  if (c.auth_interceptor === false) {
    findings.push(
      mk(
        file,
        "grpc-no-auth-interceptor",
        "high",
        "gRPC server has no authentication interceptor",
        "Without an auth interceptor (server interceptor / middleware), RPC methods are reachable without credentials. Any client that can connect can invoke any method.",
        "Add a server interceptor that validates per-call credentials (token in metadata, mTLS client certificate) and rejects unauthenticated calls.",
        ["CWE-306"],
        "auth_interceptor=false",
        ["auth"],
      ),
    );
  }

  if (c.deadline_propagation === false) {
    findings.push(
      mk(
        file,
        "grpc-no-deadline-propagation",
        "medium",
        "gRPC calls do not set or propagate a deadline",
        "Without a deadline, a slow or stuck downstream call holds a connection and resources indefinitely. Under load, missing deadlines let backpressure cascade into resource exhaustion.",
        "Set a deadline on every gRPC call and propagate the inbound deadline to downstream calls.",
        ["CWE-400"],
        "deadline_propagation=false",
        ["dos"],
      ),
    );
  }

  if (c.reflection_enabled === true && inProd) {
    findings.push(
      mk(
        file,
        "grpc-reflection-enabled",
        "medium",
        "gRPC server reflection is enabled in production",
        "Server reflection lets any connecting client list every service, method, and message type. In production this hands an attacker a full map of the API surface.",
        "Disable server reflection in production, or gate it behind authentication.",
        ["CWE-200"],
        "reflection_enabled=true, production=true",
        ["reflection"],
      ),
    );
  }

  if (c.max_message_size === false) {
    findings.push(
      mk(
        file,
        "grpc-unbounded-message-size",
        "medium",
        "gRPC accepts messages of unbounded size",
        "Raising or removing the max receive message size lets a client send a huge message that exhausts server memory — a denial-of-service vector.",
        "Keep a conservative `grpc.max_receive_message_length` and reject oversized messages.",
        ["CWE-400"],
        "max_message_size=false",
        ["dos"],
      ),
    );
  }

  return findings;
}

export function auditGrpc(input: GrpcAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config !== undefined) {
    findings.push(...auditConfig(input.config, input.filename));
  }
  return findings;
}
