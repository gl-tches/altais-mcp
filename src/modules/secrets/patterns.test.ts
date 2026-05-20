import { describe, expect, it } from "vitest";
import { SecretPatternRegistry, redact } from "./patterns.js";

let cached: SecretPatternRegistry | null = null;
async function getRegistry(): Promise<SecretPatternRegistry> {
  cached ??= await SecretPatternRegistry.load();
  return cached;
}

describe("SecretPatternRegistry", () => {
  it("loads at least the Phase 1 patterns", async () => {
    const r = await getRegistry();
    expect(r.size()).toBeGreaterThanOrEqual(28);
  });

  it("matches an AWS access key id", async () => {
    const r = await getRegistry();
    const findings = r.scan({ source: "const k = AKIAIOSFODNN7EXAMPLE;" });
    expect(findings.map((f) => f.rule)).toContain("aws-access-key-id");
  });

  it("matches a GitHub classic PAT", async () => {
    const r = await getRegistry();
    const fake = `ghp_${"a".repeat(36)}`;
    const findings = r.scan({ source: `const t = "${fake}";` });
    expect(findings.map((f) => f.rule)).toContain("github-pat-classic");
  });

  it("matches a Slack webhook URL", async () => {
    const r = await getRegistry();
    const findings = r.scan({
      source:
        "const hook = 'https://hooks.slack.com/services/T01ABCDEF/B01XYZ12/abcdef1234567890';",
    });
    expect(findings.map((f) => f.rule)).toContain("slack-webhook");
  });

  it("matches a PEM private key header", async () => {
    const r = await getRegistry();
    const findings = r.scan({
      source: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n",
    });
    expect(findings.map((f) => f.rule)).toContain("private-key-pem");
  });

  it("matches a Stripe live key", async () => {
    const r = await getRegistry();
    const fake = `sk_live_${"a".repeat(24)}`;
    const findings = r.scan({ source: `stripe.setKey("${fake}");` });
    expect(findings.map((f) => f.rule)).toContain("stripe-secret-key");
  });

  it("matches a database connection string with credentials", async () => {
    const r = await getRegistry();
    const findings = r.scan({
      source: 'DATABASE_URL="postgres://user:secret123@db.example.com:5432/app"',
    });
    expect(findings.map((f) => f.rule)).toContain("db-connection-string");
  });

  it("matches a password-in-config", async () => {
    const r = await getRegistry();
    const findings = r.scan({ source: 'password = "supersecret123"' });
    expect(findings.map((f) => f.rule)).toContain("password-assignment");
  });

  it("does not match obvious non-secrets", async () => {
    const r = await getRegistry();
    const findings = r.scan({ source: 'const greeting = "hello, world";\nconst n = 42;\n' });
    expect(findings).toEqual([]);
  });

  it("attaches the `secret` tag to every finding", async () => {
    const r = await getRegistry();
    const findings = r.scan({ source: "AKIAIOSFODNN7EXAMPLE" });
    expect(findings[0]?.tags).toContain("secret");
  });

  it("respects the `rules` filter", async () => {
    const r = await getRegistry();
    const source = `AKIAIOSFODNN7EXAMPLE and ghp_${"a".repeat(36)}`;
    const filtered = r.scan({ source }, { rules: ["github-pat-classic"] });
    expect(filtered.map((f) => f.rule)).toEqual(["github-pat-classic"]);
  });

  it("uses evidenceGroup for the password-assignment pattern", async () => {
    const r = await getRegistry();
    const findings = r.scan({ source: 'password = "supersecret"' });
    const f = findings.find((x) => x.rule === "password-assignment");
    expect(f?.evidence).toBeDefined();
    expect(f?.evidence).not.toContain("password =");
  });
});

describe("redact", () => {
  it("keeps short strings as-is", () => {
    expect(redact("abc", 200)).toBe("abc");
  });

  it("masks the middle of longer strings", () => {
    const out = redact("AKIAIOSFODNN7EXAMPLE", 200);
    expect(out).toMatch(/^AKIA…MPLE \(len=20\)$/);
  });

  it("truncates extremely long values", () => {
    const long = "a".repeat(300);
    const out = redact(long, 100);
    expect(out.endsWith(")")).toBe(true);
    expect(out.length).toBeLessThan(120);
  });
});
