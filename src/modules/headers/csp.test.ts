import { describe, expect, it } from "vitest";
import { generateCsp } from "./csp.js";

describe("generateCsp - strict mode", () => {
  it("uses default-src 'none' by default", () => {
    const r = generateCsp({});
    expect(r.header).toMatch(/default-src 'none'/);
  });

  it("always includes object-src 'none' and frame-ancestors 'none'", () => {
    const r = generateCsp({});
    expect(r.header).toMatch(/object-src 'none'/);
    expect(r.header).toMatch(/frame-ancestors 'none'/);
  });

  it("includes base-uri 'self'", () => {
    expect(generateCsp({}).header).toMatch(/base-uri 'self'/);
  });

  it("emits upgrade-insecure-requests", () => {
    expect(generateCsp({}).header).toMatch(/upgrade-insecure-requests/);
  });

  it("never emits 'unsafe-inline'", () => {
    const r = generateCsp({
      requires_inline_scripts: true,
      requires_inline_styles: true,
    });
    expect(r.header).not.toMatch(/unsafe-inline/);
    expect(r.recommendations.some((x) => /nonce/i.test(x))).toBe(true);
  });

  it("includes external scripts in script-src", () => {
    const r = generateCsp({ external_scripts: ["https://cdn.example.com"] });
    expect(r.header).toMatch(/script-src 'self' https:\/\/cdn\.example\.com/);
  });

  it("warns on HTTP external sources", () => {
    const r = generateCsp({ external_scripts: ["http://insecure.example.com"] });
    expect(r.recommendations.some((x) => x.includes("HTTPS"))).toBe(true);
  });
});

describe("generateCsp - compatible mode", () => {
  it("uses default-src 'self'", () => {
    const r = generateCsp({ mode: "compatible" });
    expect(r.header).toMatch(/default-src 'self'/);
  });

  it("notes the relaxation in `notes`", () => {
    const r = generateCsp({ mode: "compatible" });
    expect(r.notes.some((n) => /compatible mode/i.test(n))).toBe(true);
  });
});

describe("generateCsp - reporting + workers", () => {
  it("adds worker-src when use_workers is true", () => {
    const r = generateCsp({ use_workers: true });
    expect(r.header).toMatch(/worker-src 'self'/);
  });

  it("adds report-uri when provided", () => {
    const r = generateCsp({ report_uri: "/csp-report" });
    expect(r.header).toMatch(/report-uri \/csp-report/);
  });

  it("rejects malformed source values", () => {
    const r = generateCsp({ external_scripts: ["javascript:alert(1)"] });
    expect(r.notes.some((n) => /unrecognized/i.test(n) || /javascript:/i.test(n))).toBe(true);
  });
});

describe("generateCsp - frames + form-action", () => {
  it("defaults frame-src to 'none' when no frames are required", () => {
    expect(generateCsp({}).header).toMatch(/frame-src 'none'/);
  });

  it("emits an explicit frame-src when frames are required", () => {
    const r = generateCsp({ external_frames: ["https://embed.example.com"] });
    expect(r.header).toMatch(/frame-src https:\/\/embed\.example\.com/);
  });

  it("includes form-action 'self' by default", () => {
    expect(generateCsp({}).header).toMatch(/form-action 'self'/);
  });
});
