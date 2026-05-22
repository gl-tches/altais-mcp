// altais_audit_elasticsearch — Elasticsearch configuration audit.
//
// Reviews the security plugin, anonymous access, transport and HTTP TLS,
// dynamic scripting, network binding, audit logging, and the built-in
// elastic superuser password.

import { z } from "zod";
import type { Finding } from "../../core/types.js";
import { type ConfigCheck, runConfigChecks } from "./finding.js";

const REFS = [
  "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html",
  "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
];

export const elasticsearchSchema = z.object({
  config: z.object({
    xpack_security_enabled: z
      .boolean()
      .optional()
      .describe("Whether the security feature (xpack.security.enabled) is enabled."),
    anonymous_access_enabled: z
      .boolean()
      .optional()
      .describe("Whether anonymous access is permitted."),
    tls_transport_enabled: z
      .boolean()
      .optional()
      .describe("Whether TLS is enabled on the inter-node transport layer."),
    tls_http_enabled: z
      .boolean()
      .optional()
      .describe("Whether TLS is enabled on the HTTP / REST layer."),
    dynamic_scripting_enabled: z
      .boolean()
      .optional()
      .describe("Whether dynamic / inline scripting is enabled."),
    network_host: z
      .string()
      .max(256)
      .optional()
      .describe("The network.host value (e.g. `_local_`, `0.0.0.0`)."),
    audit_logging_enabled: z
      .boolean()
      .optional()
      .describe("Whether security audit logging is enabled."),
    default_elastic_password_changed: z
      .boolean()
      .optional()
      .describe("Whether the built-in `elastic` superuser password has been changed."),
  }),
  filename: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe("Optional filename used for the finding location."),
});

export type ElasticsearchInput = z.infer<typeof elasticsearchSchema>;
type ElasticsearchConfig = ElasticsearchInput["config"];

const CHECKS: readonly ConfigCheck<ElasticsearchConfig>[] = [
  {
    rule: "es-security-disabled",
    when: (c) => c.xpack_security_enabled === false,
    severity: "critical",
    title: "Elasticsearch security is disabled",
    description:
      "With `xpack.security.enabled: false`, the cluster has no authentication, authorization, or TLS. Any client that reaches the HTTP port can read, modify, or delete every index — the cause of widespread Elasticsearch data breaches.",
    remediation:
      "Set `xpack.security.enabled: true`, create roles and users, and configure TLS. Restart the cluster so security is enforced.",
    cwe: ["CWE-306"],
  },
  {
    rule: "es-anonymous-access",
    when: (c) => c.anonymous_access_enabled === true,
    severity: "high",
    title: "Elasticsearch anonymous access is enabled",
    description:
      "Anonymous access lets unauthenticated clients act with whatever role is assigned to the anonymous user, undermining authentication and accountability.",
    remediation:
      "Disable anonymous access, or restrict the anonymous role to nothing. Require every client to authenticate with a named user or API key.",
    cwe: ["CWE-306"],
  },
  {
    rule: "es-transport-tls-disabled",
    when: (c) => c.tls_transport_enabled === false,
    severity: "high",
    title: "Elasticsearch transport-layer TLS is disabled",
    description:
      "The inter-node transport carries cluster data and the security configuration. Without TLS it can be intercepted, and a rogue node can join the cluster.",
    remediation:
      "Enable `xpack.security.transport.ssl` with certificates, and require certificate verification between nodes.",
    cwe: ["CWE-319"],
  },
  {
    rule: "es-http-tls-disabled",
    when: (c) => c.tls_http_enabled === false,
    severity: "high",
    title: "Elasticsearch HTTP-layer TLS is disabled",
    description:
      "Without HTTP TLS, client requests — credentials, queries, and documents — travel to the cluster in cleartext.",
    remediation:
      "Enable `xpack.security.http.ssl` with a trusted certificate and have clients connect over `https://` with verification.",
    cwe: ["CWE-319"],
  },
  {
    rule: "es-dynamic-scripting-enabled",
    when: (c) => c.dynamic_scripting_enabled === true,
    severity: "high",
    title: "Elasticsearch dynamic scripting is enabled",
    description:
      "Inline / dynamic scripting executes caller-supplied script code in the cluster. Historically this has been a remote-code-execution vector, and it remains a code-injection and denial-of-service risk.",
    remediation:
      "Disable inline scripting; use stored scripts vetted by operators, or Painless with the default sandbox and `script.allowed_types: stored`.",
    cwe: ["CWE-94"],
  },
  {
    rule: "es-network-host-all-interfaces",
    when: (c) => c.network_host === "0.0.0.0" || c.network_host === "*",
    severity: "medium",
    title: "Elasticsearch binds to all network interfaces",
    description:
      "`network.host: 0.0.0.0` exposes the cluster on every interface. Combined with disabled security this makes the data internet-reachable.",
    remediation:
      "Bind to a specific private address, place the cluster behind a firewall, and never expose the HTTP port directly to untrusted networks.",
    cwe: ["CWE-1327"],
  },
  {
    rule: "es-audit-logging-disabled",
    when: (c) => c.audit_logging_enabled === false,
    severity: "low",
    title: "Elasticsearch audit logging is disabled",
    description:
      "Without audit logging there is no record of authentication, authorization, or data-access events, leaving no trail for incident investigation.",
    remediation:
      "Enable `xpack.security.audit.enabled: true` and ship the audit events to a central, access-controlled destination.",
    cwe: ["CWE-778"],
  },
  {
    rule: "es-default-password-unchanged",
    when: (c) => c.default_elastic_password_changed === false,
    severity: "high",
    title: "Elasticsearch built-in elastic password is unchanged",
    description:
      "The built-in `elastic` superuser starts with a setup-time password. Leaving a default or unrotated password on a superuser account is a trivial path to full cluster control.",
    remediation:
      "Reset the `elastic`, `kibana_system`, and other built-in user passwords to strong, unique values via `elasticsearch-reset-password`, and store them in a secret manager.",
    cwe: ["CWE-1392"],
  },
];

/** Audit an Elasticsearch configuration. */
export function auditElasticsearch(input: ElasticsearchInput): readonly Finding[] {
  return runConfigChecks(input.config, CHECKS, REFS, input.filename);
}
