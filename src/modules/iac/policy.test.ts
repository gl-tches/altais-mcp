import { describe, expect, it } from "vitest";
import { auditPolicy, type PolicyType } from "./policy.js";

const has = (content: string, type: PolicyType, rule: string): boolean =>
  auditPolicy({ content, policy_type: type }).some((f) => f.rule === rule);

describe("auditPolicy — Rego", () => {
  it("flags default allow = true", () => {
    const c = "package authz\n\ndefault allow = true\n";
    expect(has(c, "rego", "rego-default-allow")).toBe(true);
  });

  it("flags default allow := true (assignment form)", () => {
    const c = "package authz\n\ndefault allow := true\n";
    expect(has(c, "rego", "rego-default-allow")).toBe(true);
  });

  it("does not flag default allow = false", () => {
    const c =
      'package authz\n\ndefault allow = false\n\ndeny[msg] {\n  input.bad\n  msg := "no"\n}\n';
    expect(has(c, "rego", "rego-default-allow")).toBe(false);
  });

  it("flags an http.send network call", () => {
    const c =
      'package authz\n\ndeny[msg] {\n  resp := http.send({"url": "http://x"})\n  msg := "x"\n}\n';
    expect(has(c, "rego", "rego-http-send")).toBe(true);
  });

  it("flags a policy with no deny or violation rules", () => {
    const c = "package authz\n\ndefault allow = false\n\nhelper := 1\n";
    expect(has(c, "rego", "rego-no-deny-rules")).toBe(true);
  });

  it("does not flag a policy that has a deny rule", () => {
    const c = 'package authz\n\ndeny[msg] {\n  input.bad\n  msg := "no"\n}\n';
    expect(has(c, "rego", "rego-no-deny-rules")).toBe(false);
  });

  it("does not flag a policy that has a violation rule", () => {
    const c = 'package authz\n\nviolation[{"msg": msg}] {\n  input.bad\n  msg := "no"\n}\n';
    expect(has(c, "rego", "rego-no-deny-rules")).toBe(false);
  });
});

describe("auditPolicy — Kyverno", () => {
  it("flags validationFailureAction: Audit", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: p",
      "spec:",
      "  validationFailureAction: Audit",
      "  rules:",
      "    - name: r",
      "      match:",
      "        resources:",
      "          kinds: [Pod]",
      "      validate:",
      "        message: no",
      "        pattern:",
      "          spec:",
      "            x: y",
    ].join("\n");
    expect(has(c, "kyverno", "kyverno-audit-action")).toBe(true);
  });

  it("does not flag validationFailureAction: Enforce", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: p",
      "spec:",
      "  validationFailureAction: Enforce",
      "  rules:",
      "    - name: r",
      "      match:",
      "        resources:",
      "          kinds: [Pod]",
      "      validate:",
      "        message: no",
      "        pattern: {}",
    ].join("\n");
    expect(has(c, "kyverno", "kyverno-audit-action")).toBe(false);
  });

  it("flags background: false", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: p",
      "spec:",
      "  background: false",
      "  rules:",
      "    - name: r",
      "      match:",
      "        resources:",
      "          kinds: [Pod]",
      "      validate:",
      "        message: no",
      "        pattern: {}",
    ].join("\n");
    expect(has(c, "kyverno", "kyverno-background-disabled")).toBe(true);
  });

  it("flags a policy with no validate or deny rules", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: empty",
      "spec:",
      "  rules:",
      "    - name: r",
      "      match:",
      "        resources:",
      "          kinds: [Pod]",
    ].join("\n");
    expect(has(c, "kyverno", "kyverno-no-validate-rules")).toBe(true);
  });

  it("flags a policy rule with no match selector", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: nomatch",
      "spec:",
      "  rules:",
      "    - name: r",
      "      validate:",
      "        message: no",
      "        pattern: {}",
    ].join("\n");
    expect(has(c, "kyverno", "kyverno-missing-match")).toBe(true);
  });

  it("does not flag a well-formed enforcing policy", () => {
    const c = [
      "apiVersion: kyverno.io/v1",
      "kind: ClusterPolicy",
      "metadata:",
      "  name: good",
      "spec:",
      "  validationFailureAction: Enforce",
      "  background: true",
      "  rules:",
      "    - name: r",
      "      match:",
      "        resources:",
      "          kinds: [Pod]",
      "      validate:",
      "        message: required",
      "        pattern:",
      "          spec:",
      "            x: y",
    ].join("\n");
    expect(auditPolicy({ content: c, policy_type: "kyverno" })).toHaveLength(0);
  });
});

describe("auditPolicy — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const c = "package authz\n\ndefault allow = true\n";
    const a = auditPolicy({ content: c, policy_type: "rego", filename: "p.rego" });
    const b = auditPolicy({ content: c, policy_type: "rego", filename: "p.rego" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("emits findings tagged iac with a real CWE", () => {
    const c = "package authz\n\ndefault allow = true\n";
    const f = auditPolicy({ content: c, policy_type: "rego" }).find(
      (x) => x.rule === "rego-default-allow",
    );
    expect(f?.module).toBe("iac");
    expect(f?.tags).toContain("iac");
    expect((f?.cwe ?? []).some((id) => id.startsWith("CWE-"))).toBe(true);
  });
});
