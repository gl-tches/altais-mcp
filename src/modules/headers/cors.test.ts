import { describe, expect, it } from "vitest";
import { checkCors } from "./cors.js";

function rulesFromHeaders(headers: Record<string, string>): string[] {
  return checkCors({ headers }).map((f) => f.rule);
}

function rulesFromConfig(config: Parameters<typeof checkCors>[0]["config"]): string[] {
  return checkCors({ config: config ?? {} }).map((f) => f.rule);
}

describe("checkCors - wildcard with credentials", () => {
  it("flags via headers", () => {
    expect(
      rulesFromHeaders({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
      }),
    ).toContain("cors-wildcard-with-credentials");
  });

  it("flags via config", () => {
    expect(rulesFromConfig({ allowed_origins: ["*"], allow_credentials: true })).toContain(
      "cors-wildcard-with-credentials",
    );
  });

  it("allows wildcard without credentials but flags wildcard", () => {
    const r = rulesFromConfig({ allowed_origins: ["*"], allow_credentials: false });
    expect(r).toContain("cors-wildcard-origin");
    expect(r).not.toContain("cors-wildcard-with-credentials");
  });
});

describe("checkCors - origin reflection + null origin", () => {
  it("flags reflection without an allowlist", () => {
    expect(rulesFromConfig({ reflect_origin: true, allowed_origins: [] })).toContain(
      "cors-origin-reflection",
    );
  });

  it("does not flag reflection when an allowlist is present", () => {
    expect(
      rulesFromConfig({ reflect_origin: true, allowed_origins: ["https://app.example.com"] }),
    ).not.toContain("cors-origin-reflection");
  });

  it("flags `null` origin", () => {
    expect(rulesFromConfig({ allowed_origins: ["null", "https://app.example.com"] })).toContain(
      "cors-null-origin",
    );
  });
});

describe("checkCors - methods + headers + max-age", () => {
  it("flags wildcard methods", () => {
    expect(rulesFromConfig({ allowed_methods: ["*"] })).toContain("cors-wildcard-methods");
  });

  it("flags wildcard headers", () => {
    expect(rulesFromConfig({ allowed_headers: ["*"] })).toContain("cors-wildcard-headers");
  });

  it("flags state-changing methods with credentials", () => {
    expect(
      rulesFromConfig({
        allowed_methods: ["GET", "DELETE"],
        allowed_origins: ["https://app.example.com"],
        allow_credentials: true,
      }),
    ).toContain("cors-state-changing-with-credentials");
  });

  it("flags excessive max-age", () => {
    expect(rulesFromConfig({ max_age_seconds: 31_536_000 })).toContain("cors-max-age-excessive");
  });

  it("accepts a reasonable max-age", () => {
    expect(rulesFromConfig({ max_age_seconds: 86_400 })).not.toContain("cors-max-age-excessive");
  });
});

describe("checkCors - Vary: Origin", () => {
  it("flags missing Vary when origin is reflected", () => {
    expect(
      checkCors({
        headers: {
          "access-control-allow-origin": "https://app.example.com",
        },
        config: { reflect_origin: true },
      }).map((f) => f.rule),
    ).toContain("cors-missing-vary-origin");
  });

  it("does not flag Vary when policy is static", () => {
    expect(
      checkCors({
        config: { allowed_origins: ["https://app.example.com"] },
      }).map((f) => f.rule),
    ).not.toContain("cors-missing-vary-origin");
  });
});
