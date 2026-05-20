// Server-Sent Events security auditor (altais_audit_sse).
//
// Accepts source code that serves or consumes an SSE (`text/event-stream`)
// endpoint and/or a structured description of the SSE posture. Checks for
// the failures specific to long-lived event streams: a missing Origin
// check, missing authentication, plaintext `http://`, no reconnection
// backoff, unrestricted CORS, and no per-client connection cap.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface SseAuditConfig {
  readonly origin_validation?: boolean;
  readonly authentication?: boolean;
  readonly tls?: boolean;
  readonly reconnection_backoff?: boolean;
  readonly cors_restricted?: boolean;
  readonly per_connection_limit?: boolean;
}

export interface SseAuditInput {
  readonly source?: string;
  readonly config?: SseAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://html.spec.whatwg.org/multipage/server-sent-events.html",
  "https://owasp.org/www-community/attacks/CSRF",
  "https://cwe.mitre.org/data/definitions/346.html",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "sse-plaintext-http",
    regex: /\bnew\s+EventSource\s*\(\s*["'`]http:\/\/[^"'`]+["'`]/i,
    severity: "high",
    title: "EventSource connects over plaintext `http://`",
    description:
      "An `EventSource` opened over `http://` streams all server-sent events in cleartext and sends any session cookie unprotected. A network attacker can read and inject events.",
    remediation: "Connect the EventSource to an `https://` URL.",
    cwe: ["CWE-319"],
    tags: ["sse", "transport"],
  },
  {
    rule: "sse-wildcard-cors",
    regex:
      /["'`]Access-Control-Allow-Origin["'`]\s*[,:]\s*["'`]\*["'`]|setHeader\(\s*["'`]Access-Control-Allow-Origin["'`]\s*,\s*["'`]\*["'`]/i,
    severity: "medium",
    title: "SSE endpoint sends `Access-Control-Allow-Origin: *`",
    description:
      "A wildcard CORS header on a `text/event-stream` endpoint lets any website read the event stream from the victim's browser. Combined with cookie auth this leaks the stream cross-origin.",
    remediation:
      "Echo back only an allowlisted Origin on the SSE endpoint and never combine `*` with credentialed requests.",
    cwe: ["CWE-942", "CWE-346"],
    tags: ["sse", "cors"],
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
      tags: ["sse", ...tags],
    },
    filename,
  );
}

function auditConfig(c: SseAuditConfig, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];

  if (c.tls === false) {
    findings.push(
      mk(
        file,
        "sse-plaintext-http",
        "high",
        "SSE endpoint is served over plaintext HTTP",
        "Serving `text/event-stream` over `http://` exposes the entire event stream and any session cookie to a network attacker, who can both read and inject events.",
        "Serve the SSE endpoint over HTTPS only.",
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
        "sse-no-origin-check",
        "high",
        "SSE endpoint does not validate the Origin header",
        "An `EventSource` request carries the browser's cookies automatically and is not constrained by the same-origin policy for the request itself. Without an Origin check, a malicious page can subscribe to the stream as the victim.",
        "Validate the `Origin` header against an allowlist on the SSE endpoint and reject mismatches.",
        ["CWE-346"],
        "origin_validation=false",
        ["origin"],
      ),
    );
  }

  if (c.authentication === false) {
    findings.push(
      mk(
        file,
        "sse-no-authentication",
        "high",
        "SSE endpoint has no authentication",
        "An unauthenticated `text/event-stream` endpoint lets any client subscribe and receive whatever data the stream pushes.",
        "Require authentication on the SSE endpoint and reject unauthenticated subscriptions.",
        ["CWE-306"],
        "authentication=false",
        ["auth"],
      ),
    );
  }

  if (c.reconnection_backoff === false) {
    findings.push(
      mk(
        file,
        "sse-no-reconnection-backoff",
        "medium",
        "SSE has no reconnection backoff",
        "`EventSource` reconnects automatically. Without a server-controlled `retry:` interval or exponential backoff, a transient outage produces a reconnection storm that can keep the server from recovering — a self-inflicted denial of service.",
        "Send a `retry:` field and apply exponential backoff with jitter so clients do not all reconnect at once.",
        ["CWE-400"],
        "reconnection_backoff=false",
        ["dos"],
      ),
    );
  }

  if (c.cors_restricted === false) {
    findings.push(
      mk(
        file,
        "sse-unrestricted-cors",
        "medium",
        "SSE endpoint has unrestricted CORS",
        "An unrestricted (`*`) `Access-Control-Allow-Origin` on the `text/event-stream` endpoint lets any origin read the stream from a victim's browser.",
        "Restrict CORS on the SSE endpoint to an explicit allowlist of trusted origins.",
        ["CWE-942"],
        "cors_restricted=false",
        ["cors"],
      ),
    );
  }

  if (c.per_connection_limit === false) {
    findings.push(
      mk(
        file,
        "sse-no-connection-limit",
        "low",
        "SSE endpoint has no per-client connection cap",
        "Each SSE subscription holds an open connection. Without a per-client cap, one client can open many streams and exhaust the server's connection pool.",
        "Cap the number of concurrent SSE connections per client / IP and reject excess subscriptions.",
        ["CWE-400"],
        "per_connection_limit=false",
        ["dos"],
      ),
    );
  }

  return findings;
}

export function auditSse(input: SseAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config !== undefined) {
    findings.push(...auditConfig(input.config, input.filename));
  }
  return findings;
}
