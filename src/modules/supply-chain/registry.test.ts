import { describe, expect, it } from "vitest";
import { auditRegistryConfig } from "./registry.js";

describe("auditRegistryConfig", () => {
  it("flags an HTTP npm registry", () => {
    const r = auditRegistryConfig("registry=http://npm.internal.example/\n", "npmrc", ".npmrc");
    expect(r.findings.some((f) => f.rule === "registry-http")).toBe(true);
  });

  it("flags a plaintext _authToken", () => {
    const r = auditRegistryConfig(
      "//registry.npmjs.org/:_authToken=npm_aaaaaaaaaaaa\n",
      "npmrc",
      undefined,
    );
    expect(r.findings.some((f) => f.rule === "registry-plaintext-authtoken")).toBe(true);
  });

  it("does not flag an env-referenced auth token", () => {
    const r = auditRegistryConfig(
      "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
      "npmrc",
      undefined,
    );
    expect(r.findings.filter((f) => f.rule === "registry-plaintext-authtoken")).toEqual([]);
  });

  it("flags strict-ssl=false on npmrc", () => {
    const r = auditRegistryConfig("strict-ssl=false\n", "npmrc", undefined);
    expect(r.findings.some((f) => f.rule === "registry-strict-ssl-disabled")).toBe(true);
  });

  it("flags pip trusted-host pointing at pypi.org", () => {
    const r = auditRegistryConfig(
      "[global]\ntrusted-host = pypi.org\nindex-url = https://pypi.org/simple\n",
      "pip",
      undefined,
    );
    expect(r.findings.some((f) => f.rule === "registry-pip-trusted-host-public")).toBe(true);
  });
});
