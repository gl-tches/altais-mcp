import { describe, expect, it } from "vitest";
import { verifySlsa } from "./slsa.js";

function dsseEnvelope(statement: unknown, signatures: unknown[] = [{ sig: "..." }]): string {
  const payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  return JSON.stringify({
    payload,
    payloadType: "application/vnd.in-toto+json",
    signatures,
  });
}

describe("verifySlsa", () => {
  it("accepts a well-formed v1 provenance and reports level 3", () => {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "app.tar", digest: { sha256: "abc" } }],
      predicate: {
        builder: { id: "https://github.com/actions/runner/v2" },
        buildDefinition: { buildType: "https://example.com/build/v1" },
      },
    };
    const r = verifySlsa(dsseEnvelope(statement));
    expect(r.findings).toEqual([]);
    expect(r.summary.slsa_level_estimate).toBe(3);
    expect(r.summary.builder_id).toMatch(/runner/);
  });

  it("flags missing signatures", () => {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "x" }],
      predicate: { builder: { id: "x" }, buildDefinition: { buildType: "y" } },
    };
    const env = dsseEnvelope(statement, []);
    const r = verifySlsa(env);
    expect(r.findings.some((f) => f.rule === "slsa-no-signatures")).toBe(true);
  });

  it("flags missing builder", () => {
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "x" }],
      predicate: { buildDefinition: { buildType: "x" } },
    };
    const r = verifySlsa(dsseEnvelope(statement));
    expect(r.findings.some((f) => f.rule === "slsa-no-builder")).toBe(true);
  });

  it("rejects malformed JSON", () => {
    const r = verifySlsa("not json");
    expect(r.findings.some((f) => f.rule === "slsa-malformed")).toBe(true);
  });
});
