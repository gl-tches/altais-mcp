// WebSocket security auditor (altais_audit_websocket).
//
// Accepts WebSocket server/client source code and/or a structured
// description of the WebSocket posture. Checks for the failures that
// expose a WebSocket endpoint: plaintext `ws://`, a missing Origin check
// on the upgrade handshake (Cross-Site WebSocket Hijacking), no
// authentication, unbounded message size, and no rate limiting.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface WebSocketAuditConfig {
  readonly tls?: boolean;
  readonly origin_validation?: boolean;
  readonly authentication?: boolean;
  readonly message_size_limit?: boolean;
  readonly rate_limiting?: boolean;
  readonly csrf_protection?: boolean;
}

export interface WebSocketAuditInput {
  readonly source?: string;
  readonly config?: WebSocketAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://datatracker.ietf.org/doc/html/rfc6455",
  "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking",
  "https://cwe.mitre.org/data/definitions/1385.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "websocket-plaintext-ws",
    regex: /\bnew\s+WebSocket\s*\(\s*["'`]ws:\/\/[^"'`]+["'`]/i,
    severity: "high",
    title: "WebSocket connection uses plaintext `ws://`",
    description:
      "A `ws://` URL carries the WebSocket frames in cleartext. A network attacker can read and tamper with every message, including any session token sent during the handshake.",
    remediation: "Use the TLS-protected `wss://` scheme for all WebSocket connections.",
    cwe: ["CWE-319"],
    tags: ["websocket", "transport"],
  },
  {
    rule: "websocket-no-origin-check",
    regex: /verifyClient\s*:\s*(?:true|function\s*\(\s*\)\s*\{\s*return\s+true)/i,
    severity: "high",
    title: "WebSocket upgrade accepts any Origin",
    description:
      "A `verifyClient` that always returns true (or `verifyClient: true`) skips Origin validation on the upgrade handshake. A malicious page in the victim's browser can open an authenticated WebSocket — Cross-Site WebSocket Hijacking (CSWSH).",
    remediation:
      "Implement `verifyClient` to allowlist the expected `Origin` header, and reject upgrades from any other origin.",
    cwe: ["CWE-346", "CWE-1385"],
    tags: ["websocket", "origin"],
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
      tags: ["websocket", ...tags],
    },
    filename,
  );
}

function auditConfig(c: WebSocketAuditConfig, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  if (c.tls === false) {
    findings.push(
      mk(
        file,
        "websocket-plaintext-ws",
        "high",
        "WebSocket endpoint does not use TLS",
        "An unencrypted WebSocket (`ws://`) transmits all frames in cleartext, exposing message content and any handshake-time credentials to a network attacker.",
        "Terminate the WebSocket over TLS and use the `wss://` scheme exclusively.",
        ["CWE-319"],
        "tls=false",
        ["transport"],
      ),
    );
  }

  if (c.origin_validation === false) {
    findings.push(
      mk(
        file,
        "websocket-no-origin-check",
        "high",
        "WebSocket upgrade handshake does not validate the Origin header",
        "WebSocket handshakes are not protected by the same-origin policy. Without an Origin allowlist on the upgrade, a malicious site loaded in the victim's browser can open an authenticated socket and act as the user — Cross-Site WebSocket Hijacking.",
        "Validate the `Origin` header against an allowlist during the upgrade and reject mismatches; pair it with a per-connection CSRF token.",
        ["CWE-346", "CWE-1385"],
        "origin_validation=false",
        ["origin"],
      ),
    );
  }

  if (c.authentication === false) {
    findings.push(
      mk(
        file,
        "websocket-no-authentication",
        "high",
        "WebSocket endpoint has no authentication",
        "An unauthenticated WebSocket endpoint lets any client establish a connection and exchange messages, exposing whatever data and actions the channel carries.",
        "Authenticate the connection during the handshake (a token in the URL or a subprotocol/cookie) and reject unauthenticated upgrades.",
        ["CWE-306"],
        "authentication=false",
        ["auth"],
      ),
    );
  }

  if (c.message_size_limit === false) {
    findings.push(
      mk(
        file,
        "websocket-unbounded-message-size",
        "medium",
        "WebSocket accepts messages of unbounded size",
        "Without a maximum frame/message size, a single client can send an enormous payload and exhaust server memory — a denial-of-service vector.",
        "Set a `maxPayload` (or equivalent) limit and close connections that exceed it.",
        ["CWE-400"],
        "message_size_limit=false",
        ["dos"],
      ),
    );
  }

  if (c.rate_limiting === false) {
    findings.push(
      mk(
        file,
        "websocket-no-rate-limiting",
        "medium",
        "WebSocket endpoint has no rate limiting",
        "Without per-connection message rate limiting, a client can flood the server with messages or open many connections, exhausting CPU and connection slots.",
        "Apply a per-connection message rate limit and a per-IP connection cap.",
        ["CWE-400", "CWE-770"],
        "rate_limiting=false",
        ["dos"],
      ),
    );
  }

  if (c.csrf_protection === false && c.origin_validation !== false) {
    findings.push(
      mk(
        file,
        "websocket-no-csrf-token",
        "low",
        "WebSocket handshake has no CSRF token",
        "Origin checks can be bypassed by non-browser clients or a relaxed allowlist. Without a per-session CSRF token in the handshake, a forged cross-site connection may still authenticate via ambient cookies.",
        "Require a per-session CSRF token (or a non-cookie bearer credential) in the upgrade request in addition to the Origin check.",
        ["CWE-352"],
        "csrf_protection=false",
        ["csrf"],
      ),
    );
  }

  return findings;
}

export function auditWebSocket(input: WebSocketAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config !== undefined) {
    findings.push(...auditConfig(input.config, input.filename));
  }
  return findings;
}
