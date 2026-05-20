// API gateway configuration auditor (altais_audit_api_gateway).
//
// Reviews an API gateway's declared security posture for the
// misconfigurations that turn the gateway from a control point into an
// open door: authentication or authorization off, TLS disabled or pinned
// to an obsolete version, no WAF, no edge request validation, no request
// size limit or timeout, rate limiting off, logging off, a permissive
// CORS policy combined with credentials, and cleartext traffic to the
// backend.

import type { Finding, Severity } from "../../core/types.js";
import { buildApiFinding } from "./finding.js";

export interface GatewayCorsConfig {
  readonly allow_all_origins?: boolean;
  readonly allow_credentials?: boolean;
}

export interface GatewayConfig {
  readonly authentication_enabled?: boolean;
  readonly authorization_enabled?: boolean;
  readonly tls_enabled?: boolean;
  readonly min_tls_version?: string;
  readonly waf_enabled?: boolean;
  readonly request_validation?: boolean;
  readonly request_size_limit_bytes?: number;
  readonly timeout_seconds?: number;
  readonly rate_limiting_enabled?: boolean;
  readonly logging_enabled?: boolean;
  readonly cors?: GatewayCorsConfig;
  readonly ip_allowlist_enabled?: boolean;
  readonly mtls_enabled?: boolean;
  readonly api_keys_rotated?: boolean;
  readonly backend_tls?: boolean;
}

export interface GatewayAuditInput {
  readonly config: GatewayConfig;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
  "https://cwe.mitre.org/",
];

// A timeout above this many seconds is treated as effectively unbounded
// for slow-client / slowloris purposes.
const LONG_TIMEOUT_SECONDS = 60;

/** Parse a TLS version string ("1.2", "TLSv1.3", "1.0") into a number. */
function parseTlsVersion(raw: string): number | undefined {
  const m = /([0-9]+(?:\.[0-9]+)?)/.exec(raw);
  if (m === null) return undefined;
  const value = m[1];
  if (value === undefined) return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}

export function auditApiGateway(input: GatewayAuditInput): readonly Finding[] {
  const file = input.filename;
  const cfg = input.config;
  const findings: Finding[] = [];

  // ── Authentication disabled ───────────────────────────────────────────
  if (cfg.authentication_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-authentication-disabled",
        "critical",
        "API gateway does not enforce authentication",
        "The gateway is configured with authentication disabled. Every request reaches the backend without an identity check, exposing all routed APIs to anonymous access.",
        "Enable authentication at the gateway (OAuth2 / OIDC token validation or signed API keys) and reject unauthenticated requests before they reach any backend.",
        ["CWE-306"],
        "authentication_enabled: false",
        ["gateway", "authentication", "API2:2023"],
      ),
    );
  }

  // ── Authorization disabled ────────────────────────────────────────────
  if (cfg.authorization_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-authorization-disabled",
        "high",
        "API gateway does not enforce authorization",
        "Authorization is disabled, so any authenticated caller can reach any route the gateway exposes. Object-level and function-level access control is left entirely to backends, where it is easy to miss.",
        "Enforce authorization at the gateway (scope, role, or policy checks per route) in addition to backend checks.",
        ["CWE-285", "CWE-862"],
        "authorization_enabled: false",
        ["gateway", "authorization", "API5:2023"],
      ),
    );
  }

  // ── TLS disabled / obsolete ───────────────────────────────────────────
  if (cfg.tls_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-tls-disabled",
        "high",
        "API gateway terminates traffic without TLS",
        "TLS is disabled at the gateway, so client traffic — including credentials, tokens, and request bodies — crosses the network in cleartext and can be intercepted or modified.",
        "Enable TLS at the gateway and require at least TLS 1.2 (prefer 1.3). Redirect or reject plaintext HTTP.",
        ["CWE-319"],
        "tls_enabled: false",
        ["gateway", "transport", "API8:2023"],
      ),
    );
  } else if (cfg.min_tls_version !== undefined) {
    const version = parseTlsVersion(cfg.min_tls_version);
    if (version !== undefined && version < 1.2) {
      findings.push(
        mk(
          file,
          "gateway-weak-tls-version",
          "high",
          `API gateway allows obsolete TLS version ${cfg.min_tls_version}`,
          "The gateway permits a minimum TLS version below 1.2. TLS 1.0 and 1.1 are deprecated and vulnerable to known downgrade and cipher attacks (BEAST, POODLE).",
          "Set the minimum TLS version to 1.2 or, preferably, 1.3 and disable all earlier protocol versions.",
          ["CWE-326", "CWE-319"],
          `min_tls_version: ${cfg.min_tls_version}`,
          ["gateway", "transport", "API8:2023"],
        ),
      );
    }
  }

  // ── WAF disabled ──────────────────────────────────────────────────────
  if (cfg.waf_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-waf-disabled",
        "high",
        "No web application firewall in front of the API",
        "The gateway has no WAF enabled. Common injection, traffic-flood, and known-exploit patterns reach the backend unfiltered, removing a useful defence-in-depth layer.",
        "Enable a WAF at the gateway with managed rule sets for injection and bot/abuse protection, tuned to the API's traffic.",
        ["CWE-16"],
        "waf_enabled: false",
        ["gateway", "waf", "API8:2023"],
      ),
    );
  }

  // ── No edge request validation ────────────────────────────────────────
  if (cfg.request_validation === false) {
    findings.push(
      mk(
        file,
        "gateway-no-request-validation",
        "high",
        "API gateway does not validate requests against a schema",
        "Schema validation at the edge is disabled. Malformed or oversized payloads, unexpected fields, and bad parameters pass straight to the backend, widening the input-validation attack surface.",
        "Enable request validation at the gateway against the OpenAPI/JSON Schema contract so non-conforming requests are rejected before reaching backends.",
        ["CWE-20"],
        "request_validation: false",
        ["gateway", "input-validation", "API6:2023"],
      ),
    );
  }

  // ── No request size limit ─────────────────────────────────────────────
  if (cfg.request_size_limit_bytes === undefined || cfg.request_size_limit_bytes <= 0) {
    findings.push(
      mk(
        file,
        "gateway-no-request-size-limit",
        "medium",
        "API gateway enforces no request size limit",
        "No maximum request body size is configured. A client can submit very large payloads to exhaust gateway and backend memory, a straightforward denial-of-service vector.",
        "Set an explicit `request_size_limit_bytes` sized to the largest legitimate request and reject anything larger.",
        ["CWE-770", "CWE-400"],
        "request_size_limit_bytes: unset",
        ["gateway", "availability", "API4:2023"],
      ),
    );
  }

  // ── No / long timeout ─────────────────────────────────────────────────
  if (cfg.timeout_seconds === undefined || cfg.timeout_seconds <= 0) {
    findings.push(
      mk(
        file,
        "gateway-no-timeout",
        "medium",
        "API gateway enforces no request timeout",
        "No request timeout is configured. Slow or stalled clients can hold connections and worker threads open indefinitely, exhausting the gateway's connection pool (a slowloris-style attack).",
        "Configure a request timeout (typically a few seconds to tens of seconds) appropriate to the API's workload.",
        ["CWE-770", "CWE-400"],
        "timeout_seconds: unset",
        ["gateway", "availability", "API4:2023"],
      ),
    );
  } else if (cfg.timeout_seconds > LONG_TIMEOUT_SECONDS) {
    findings.push(
      mk(
        file,
        "gateway-long-timeout",
        "low",
        `API gateway request timeout is very long (${cfg.timeout_seconds}s)`,
        `A timeout of ${cfg.timeout_seconds}s lets each slow client hold a connection for an extended period, making it cheaper to exhaust the gateway's connection pool.`,
        "Shorten the request timeout to the minimum that supports legitimate long-running calls, and move genuinely long operations to an async pattern.",
        ["CWE-400"],
        `timeout_seconds: ${cfg.timeout_seconds}`,
        ["gateway", "availability", "API4:2023"],
      ),
    );
  }

  // ── Rate limiting disabled ────────────────────────────────────────────
  if (cfg.rate_limiting_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-rate-limiting-disabled",
        "high",
        "API gateway does not enforce rate limiting",
        "Rate limiting is disabled at the gateway. Clients can flood the API with requests, exhausting backend resources and enabling brute-force attacks against authentication.",
        "Enable per-client rate limiting at the gateway and return `429` with a `Retry-After` header when limits are exceeded.",
        ["CWE-770"],
        "rate_limiting_enabled: false",
        ["gateway", "rate-limiting", "API4:2023"],
      ),
    );
  }

  // ── Logging disabled ──────────────────────────────────────────────────
  if (cfg.logging_enabled === false) {
    findings.push(
      mk(
        file,
        "gateway-logging-disabled",
        "medium",
        "API gateway access logging is disabled",
        "The gateway does not log requests. Without access logs there is no audit trail for abuse, no data for rate-limit tuning, and incident response loses its primary evidence source.",
        "Enable structured access logging at the gateway (excluding secrets and request bodies) and ship logs to a central, tamper-resistant store.",
        ["CWE-778"],
        "logging_enabled: false",
        ["gateway", "observability", "API9:2023"],
      ),
    );
  }

  // ── Permissive CORS with credentials ──────────────────────────────────
  if (cfg.cors !== undefined) {
    if (cfg.cors.allow_all_origins === true && cfg.cors.allow_credentials === true) {
      findings.push(
        mk(
          file,
          "gateway-cors-wildcard-with-credentials",
          "high",
          "CORS allows all origins together with credentials",
          "The gateway reflects/allows any origin (`allow_all_origins`) while also allowing credentials. Any website a victim visits can then make authenticated cross-origin requests to the API using the victim's cookies or tokens.",
          "Never combine a wildcard origin with credentialed CORS. Allow credentials only for an explicit allowlist of trusted origins.",
          ["CWE-942", "CWE-346"],
          "cors: allow_all_origins + allow_credentials",
          ["gateway", "cors", "API8:2023"],
        ),
      );
    } else if (cfg.cors.allow_all_origins === true) {
      findings.push(
        mk(
          file,
          "gateway-cors-wildcard-origin",
          "low",
          "CORS allows requests from any origin",
          "The gateway allows any origin to make cross-origin requests. Without credentials the immediate risk is lower, but a wildcard origin still widens exposure and is rarely intended.",
          "Restrict CORS to an explicit allowlist of origins the API is meant to serve.",
          ["CWE-942"],
          "cors: allow_all_origins",
          ["gateway", "cors", "API8:2023"],
        ),
      );
    }
  }

  // ── Cleartext backend traffic ─────────────────────────────────────────
  if (cfg.backend_tls === false) {
    findings.push(
      mk(
        file,
        "gateway-cleartext-backend",
        "high",
        "Gateway-to-backend traffic is sent in cleartext",
        "Traffic from the gateway to backend services is not encrypted. An attacker with a foothold inside the network can read or tamper with requests and responses, including credentials and tokens, between the gateway and the backend.",
        "Encrypt gateway-to-backend traffic with TLS, and prefer mutual TLS so the backend also authenticates the gateway.",
        ["CWE-319"],
        "backend_tls: false",
        ["gateway", "transport", "API8:2023"],
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
  tags: readonly string[],
): Finding {
  return buildApiFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags,
    },
    file,
  );
}
