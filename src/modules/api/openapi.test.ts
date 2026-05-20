import { describe, expect, it } from "vitest";
import { auditOpenApi } from "./openapi.js";
import type { Finding } from "../../core/types.js";

function run(spec: unknown): readonly Finding[] {
  const result = auditOpenApi({ spec: JSON.stringify(spec), filename: "openapi.json" });
  if (!result.ok) throw new Error(`expected ok, got error: ${result.error}`);
  return result.findings;
}

function has(spec: unknown, rule: string): boolean {
  return run(spec).some((f) => f.rule === rule);
}

// A minimal, reasonably-hardened spec used as the negative baseline.
const SECURE_SPEC = {
  openapi: "3.1.0",
  info: { title: "Demo", version: "1.0.0" },
  servers: [{ url: "https://api.example.com" }],
  security: [{ bearerAuth: [] }],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
  },
  paths: {
    "/items": {
      get: {
        responses: {
          "200": { description: "ok" },
          "429": { description: "too many requests" },
          "500": { description: "error" },
        },
      },
      post: {
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                additionalProperties: false,
                properties: { name: { type: "string" } },
              },
            },
          },
        },
        responses: {
          "201": { description: "created" },
          "400": { description: "bad request" },
          "429": { description: "too many requests" },
        },
      },
    },
  },
};

describe("auditOpenApi — malformed input", () => {
  it("returns an actionable error on malformed JSON", () => {
    const result = auditOpenApi({ spec: "{ not json" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("JSON");
  });

  it("returns an error when the root is not an object", () => {
    const result = auditOpenApi({ spec: "[]" });
    expect(result.ok).toBe(false);
  });
});

describe("auditOpenApi — security", () => {
  it("flags a spec with no security and no schemes", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      paths: { "/a": { get: { responses: { "200": { description: "ok" } } } } },
    };
    expect(has(spec, "openapi-no-security")).toBe(true);
  });

  it("flags an HTTP Basic auth scheme", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      components: { securitySchemes: { basic: { type: "http", scheme: "basic" } } },
      security: [{ basic: [] }],
      paths: {},
    };
    expect(has(spec, "openapi-basic-auth-scheme")).toBe(true);
  });

  it("flags an API key carried in the query string", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      components: {
        securitySchemes: { apiKey: { type: "apiKey", in: "query", name: "key" } },
      },
      security: [{ apiKey: [] }],
      paths: {},
    };
    expect(has(spec, "openapi-apikey-in-query")).toBe(true);
  });

  it("does not flag an API key carried in a header", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      components: {
        securitySchemes: { apiKey: { type: "apiKey", in: "header", name: "X-Key" } },
      },
      security: [{ apiKey: [] }],
      paths: {},
    };
    expect(has(spec, "openapi-apikey-in-query")).toBe(false);
  });

  it("flags an operation with no security when there is no global default", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: { "/a": { get: { responses: { "200": { description: "ok" } } } } },
    };
    expect(has(spec, "openapi-operation-no-security")).toBe(true);
  });
});

describe("auditOpenApi — transport and responses", () => {
  it("flags a cleartext http:// server URL", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      servers: [{ url: "http://api.example.com" }],
      security: [{ bearerAuth: [] }],
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: {},
    };
    expect(has(spec, "openapi-cleartext-server-url")).toBe(true);
  });

  it("flags an operation missing 4xx/5xx error responses", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      security: [{ bearerAuth: [] }],
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: { "/a": { get: { responses: { "200": { description: "ok" } } } } },
    };
    expect(has(spec, "openapi-operation-no-error-response")).toBe(true);
  });

  it("flags a request schema that allows arbitrary extra properties", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      security: [{ bearerAuth: [] }],
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: {
        "/a": {
          post: {
            requestBody: {
              content: {
                "application/json": {
                  schema: { type: "object", properties: { name: { type: "string" } } },
                },
              },
            },
            responses: { "200": { description: "ok" }, "400": { description: "bad" } },
          },
        },
      },
    };
    expect(has(spec, "openapi-additional-properties-open")).toBe(true);
  });

  it("flags a request body with no schema", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      security: [{ bearerAuth: [] }],
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: {
        "/a": {
          post: {
            requestBody: {},
            responses: { "200": { description: "ok" }, "400": { description: "bad" } },
          },
        },
      },
    };
    expect(has(spec, "openapi-request-body-no-schema")).toBe(true);
  });

  it("flags a spec where no operation documents a 429 response", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      security: [{ bearerAuth: [] }],
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
      paths: {
        "/a": {
          get: { responses: { "200": { description: "ok" }, "500": { description: "err" } } },
        },
      },
    };
    expect(has(spec, "openapi-no-rate-limit-documented")).toBe(true);
  });
});

describe("auditOpenApi — clean baseline and shape", () => {
  it("produces no findings for a reasonably hardened spec", () => {
    expect(run(SECURE_SPEC)).toHaveLength(0);
  });

  it("produces deterministic finding IDs across runs", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      paths: { "/a": { get: { responses: { "200": { description: "ok" } } } } },
    };
    const a = run(spec);
    const b = run(spec);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the api module, a CWE, and the api tag", () => {
    const spec = {
      openapi: "3.1.0",
      info: { title: "x", version: "1" },
      servers: [{ url: "http://api.example.com" }],
      paths: { "/a": { get: { responses: { "200": { description: "ok" } } } } },
    };
    const findings = run(spec);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("api");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
      expect(f.tags).toContain("api");
    }
  });
});
