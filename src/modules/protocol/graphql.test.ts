import { describe, expect, it } from "vitest";
import { auditGraphQl, type GraphQlAuditInput } from "./graphql.js";

const has = (input: GraphQlAuditInput, rule: string): boolean =>
  auditGraphQl(input).some((f) => f.rule === rule);

describe("auditGraphQl — config posture", () => {
  it("flags introspection enabled in production", () => {
    expect(
      has(
        { config: { introspection_enabled: true, production: true } },
        "graphql-introspection-enabled",
      ),
    ).toBe(true);
  });

  it("does not flag introspection enabled outside production", () => {
    expect(
      has(
        { config: { introspection_enabled: true, production: false } },
        "graphql-introspection-enabled",
      ),
    ).toBe(false);
  });

  it("flags a missing depth limit", () => {
    expect(has({ config: { query_depth_limit: false } }, "graphql-no-depth-limit")).toBe(true);
  });

  it("flags a missing complexity limit", () => {
    expect(has({ config: { query_complexity_limit: false } }, "graphql-no-complexity-limit")).toBe(
      true,
    );
  });

  it("flags query batching enabled", () => {
    expect(has({ config: { batching_enabled: true } }, "graphql-batching-enabled")).toBe(true);
  });

  it("flags field suggestions enabled", () => {
    expect(has({ config: { field_suggestions: true } }, "graphql-field-suggestions-enabled")).toBe(
      true,
    );
  });

  it("flags missing rate limiting", () => {
    expect(has({ config: { rate_limiting: false } }, "graphql-no-rate-limiting")).toBe(true);
  });

  it("returns no findings for a hardened production config", () => {
    const findings = auditGraphQl({
      config: {
        introspection_enabled: false,
        query_depth_limit: true,
        query_complexity_limit: true,
        batching_enabled: false,
        field_suggestions: false,
        rate_limiting: true,
        production: true,
      },
    });
    expect(findings).toHaveLength(0);
  });
});

describe("auditGraphQl — source scanning", () => {
  it("flags introspection: true in source", () => {
    const src = "const server = new ApolloServer({ schema, introspection: true });";
    expect(has({ source: src }, "graphql-introspection-enabled")).toBe(true);
  });

  it("flags an enabled GraphQL Playground", () => {
    const src = "new ApolloServer({ schema, playground: true });";
    expect(has({ source: src }, "graphql-debug-playground")).toBe(true);
  });

  it("does not flag introspection: false", () => {
    const src = "new ApolloServer({ schema, introspection: false });";
    expect(has({ source: src }, "graphql-introspection-enabled")).toBe(false);
  });
});

describe("auditGraphQl — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const input: GraphQlAuditInput = {
      config: { introspection_enabled: true, query_depth_limit: false },
      filename: "schema.ts",
    };
    const a = auditGraphQl(input);
    const b = auditGraphQl(input);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the protocol module and a CWE", () => {
    const findings = auditGraphQl({ config: { query_depth_limit: false, batching_enabled: true } });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("protocol");
      expect(f.tags).toContain("protocol");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
