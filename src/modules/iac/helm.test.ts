import { describe, expect, it } from "vitest";
import { auditHelmChart } from "./helm.js";

const has = (content: string, rule: string): boolean =>
  auditHelmChart({ content }).some((f) => f.rule === rule);

describe("auditHelmChart — insecure defaults", () => {
  it("flags privileged: true in values", () => {
    const c = "securityContext:\n  privileged: true\n";
    expect(has(c, "helm-privileged-default")).toBe(true);
  });

  it("flags a LoadBalancer service type", () => {
    const c = "service:\n  type: LoadBalancer\n  port: 80\n";
    expect(has(c, "helm-loadbalancer-service")).toBe(true);
  });

  it("flags a NodePort service type", () => {
    const c = "service:\n  type: NodePort\n";
    expect(has(c, "helm-loadbalancer-service")).toBe(true);
  });

  it("does not flag a ClusterIP service type", () => {
    const c = "service:\n  type: ClusterIP\n  port: 80\n";
    expect(has(c, "helm-loadbalancer-service")).toBe(false);
  });

  it("flags rbac.create: false", () => {
    const c = "rbac:\n  create: false\n";
    expect(has(c, "helm-rbac-disabled")).toBe(true);
  });

  it("flags a disabled security context", () => {
    const c = "podSecurityContext: {}\n";
    expect(has(c, "helm-security-context-disabled")).toBe(true);
  });
});

describe("auditHelmChart — images and secrets", () => {
  it("flags a latest image tag", () => {
    const c = "image:\n  repository: nginx\n  tag: latest\n";
    expect(has(c, "helm-mutable-image-tag")).toBe(true);
  });

  it("flags an empty image tag", () => {
    const c = "image:\n  repository: nginx\n  tag:\n";
    expect(has(c, "helm-mutable-image-tag")).toBe(true);
  });

  it("does not flag a pinned image tag", () => {
    const c = "image:\n  repository: nginx\n  tag: 1.27.3\n";
    expect(has(c, "helm-mutable-image-tag")).toBe(false);
  });

  it("flags a well-known default password", () => {
    const c = "auth:\n  password: changeme\n";
    expect(has(c, "helm-default-password")).toBe(true);
  });

  it("flags an arbitrary hardcoded secret value", () => {
    const c = "auth:\n  apiToken: aB3xQz9KmP2L\n";
    expect(has(c, "helm-hardcoded-secret")).toBe(true);
  });

  it("does not flag a templated secret value", () => {
    const c = "auth:\n  password: {{ .Values.global.password }}\n";
    expect(has(c, "helm-hardcoded-secret")).toBe(false);
    expect(has(c, "helm-default-password")).toBe(false);
  });

  it("does not flag an empty secret value", () => {
    const c = "auth:\n  password:\n";
    expect(has(c, "helm-hardcoded-secret")).toBe(false);
  });

  it("flags a secret passed via --set in chart notes", () => {
    const c = "# Install with:\n#   helm install app . --set auth.password=topsecret\n";
    expect(has(c, "helm-set-secret")).toBe(true);
  });

  it("flags a secret rendered into a ConfigMap template", () => {
    const c = [
      "apiVersion: v1",
      "kind: ConfigMap",
      "data:",
      "  db-password: {{ .Values.dbPassword }}",
    ].join("\n");
    expect(has(c, "helm-secret-in-configmap")).toBe(true);
  });

  it("masks the secret value in finding evidence", () => {
    const c = "auth:\n  apiToken: aB3xQz9KmP2L\n";
    const f = auditHelmChart({ content: c }).find((x) => x.rule === "helm-hardcoded-secret");
    expect(f?.evidence ?? "").not.toContain("aB3xQz9KmP2L");
  });
});

describe("auditHelmChart — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const c = "securityContext:\n  privileged: true\nservice:\n  type: LoadBalancer\n";
    const a = auditHelmChart({ content: c, filename: "values.yaml" });
    const b = auditHelmChart({ content: c, filename: "values.yaml" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("emits findings tagged iac with a real CWE", () => {
    const c = "securityContext:\n  privileged: true\n";
    const f = auditHelmChart({ content: c }).find((x) => x.rule === "helm-privileged-default");
    expect(f?.module).toBe("iac");
    expect(f?.tags).toContain("iac");
    expect((f?.cwe ?? []).some((id) => id.startsWith("CWE-"))).toBe(true);
  });

  it("returns no findings for a clean values file", () => {
    const c = "image:\n  repository: nginx\n  tag: 1.27.3\nservice:\n  type: ClusterIP\n";
    expect(auditHelmChart({ content: c })).toHaveLength(0);
  });
});
