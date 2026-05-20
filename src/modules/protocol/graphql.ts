// GraphQL security auditor (altais_audit_graphql).
//
// Accepts GraphQL server source code and/or a structured description of
// the GraphQL posture. Checks for the failures specific to GraphQL APIs:
// introspection left enabled in production, missing query-depth and
// complexity limits, query batching enabled, field suggestions leaking
// the schema, and no rate limiting.

import type { Finding } from "../../core/types.js";
import { buildProtocolFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface GraphQlAuditConfig {
  readonly introspection_enabled?: boolean;
  readonly query_depth_limit?: boolean;
  readonly query_complexity_limit?: boolean;
  readonly batching_enabled?: boolean;
  readonly field_suggestions?: boolean;
  readonly rate_limiting?: boolean;
  readonly production?: boolean;
}

export interface GraphQlAuditInput {
  readonly source?: string;
  readonly config?: GraphQlAuditConfig;
  readonly filename?: string;
}

const REFS = [
  "https://graphql.org/learn/security/",
  "https://owasp.org/www-project-web-security-testing-guide/",
  "https://portswigger.net/web-security/graphql",
];

const SOURCE_PATTERNS: readonly SourcePattern[] = [
  {
    rule: "graphql-introspection-enabled",
    regex: /\bintrospection\s*:\s*true\b/i,
    severity: "medium",
    title: "GraphQL introspection explicitly enabled",
    description:
      "`introspection: true` exposes the full schema — every type, field, and argument. In production this hands an attacker a complete map of the API's attack surface.",
    remediation:
      "Disable introspection in production builds (`introspection: process.env.NODE_ENV !== 'production'`).",
    cwe: ["CWE-200"],
    tags: ["graphql", "introspection"],
  },
  {
    rule: "graphql-debug-playground",
    regex: /\b(?:playground|graphiql)\s*:\s*true\b/i,
    severity: "medium",
    title: "GraphQL Playground / GraphiQL enabled",
    description:
      "An interactive GraphQL IDE served alongside the API exposes the schema and an explorer UI to anyone who reaches the endpoint.",
    remediation: "Disable the Playground / GraphiQL IDE in production.",
    cwe: ["CWE-200"],
    tags: ["graphql", "introspection"],
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
      tags: ["graphql", ...tags],
    },
    filename,
  );
}

function auditConfig(c: GraphQlAuditConfig, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const inProd = c.production !== false;

  if (c.introspection_enabled === true && inProd) {
    findings.push(
      mk(
        file,
        "graphql-introspection-enabled",
        "medium",
        "GraphQL introspection is enabled in production",
        "Introspection exposes the entire schema — types, fields, arguments, deprecations. In production it gives an attacker a complete blueprint of the API, including fields not used by the official client.",
        "Disable introspection for production deployments; allow it only in development.",
        ["CWE-200"],
        "introspection_enabled=true, production=true",
        ["introspection"],
      ),
    );
  }

  if (c.query_depth_limit === false) {
    findings.push(
      mk(
        file,
        "graphql-no-depth-limit",
        "high",
        "GraphQL has no query-depth limit",
        "Cyclic relationships in the schema let a client nest a query arbitrarily deep. A single deeply nested query can trigger an explosion of resolver calls and exhaust server resources.",
        "Enforce a maximum query depth (e.g. `graphql-depth-limit`) and reject queries that exceed it.",
        ["CWE-770"],
        "query_depth_limit=false",
        ["dos"],
      ),
    );
  }

  if (c.query_complexity_limit === false) {
    findings.push(
      mk(
        file,
        "graphql-no-complexity-limit",
        "high",
        "GraphQL has no query complexity / cost limit",
        "Without a cost analysis, a shallow but wide query (many fields, large list arguments) can still be extremely expensive to resolve, enabling a denial-of-service.",
        "Assign per-field costs and reject queries above a complexity budget (e.g. `graphql-cost-analysis`, `graphql-query-complexity`).",
        ["CWE-770"],
        "query_complexity_limit=false",
        ["dos"],
      ),
    );
  }

  if (c.batching_enabled === true) {
    findings.push(
      mk(
        file,
        "graphql-batching-enabled",
        "medium",
        "GraphQL query batching is enabled",
        "Array-form batched requests let a client send many operations in one HTTP request. This multiplies cost behind a single request and is commonly used to bypass per-request rate limits — a batching attack (e.g. brute-forcing logins).",
        "Disable array batching, or apply rate limiting and complexity analysis across the whole batch rather than per HTTP request.",
        ["CWE-799"],
        "batching_enabled=true",
        ["batching"],
      ),
    );
  }

  if (c.field_suggestions === true) {
    findings.push(
      mk(
        file,
        "graphql-field-suggestions-enabled",
        "low",
        "GraphQL field suggestions are enabled",
        "When a query names an unknown field, the server replies with a 'Did you mean ...?' suggestion. An attacker can use these hints to reconstruct the schema even with introspection disabled.",
        "Disable 'did you mean' field suggestions in production (e.g. mask validation errors or strip suggestions).",
        ["CWE-200"],
        "field_suggestions=true",
        ["introspection"],
      ),
    );
  }

  if (c.rate_limiting === false) {
    findings.push(
      mk(
        file,
        "graphql-no-rate-limiting",
        "medium",
        "GraphQL endpoint has no rate limiting",
        "A single GraphQL endpoint serves every operation. Without rate limiting, an attacker can hammer expensive queries or brute-force mutations through the one URL.",
        "Apply rate limiting to the GraphQL endpoint, ideally weighted by query cost.",
        ["CWE-770"],
        "rate_limiting=false",
        ["dos"],
      ),
    );
  }

  return findings;
}

export function auditGraphQl(input: GraphQlAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  if (input.source !== undefined) {
    findings.push(...scanWithPatterns(input.source, SOURCE_PATTERNS, REFS, input.filename));
  }
  if (input.config !== undefined) {
    findings.push(...auditConfig(input.config, input.filename));
  }
  return findings;
}
