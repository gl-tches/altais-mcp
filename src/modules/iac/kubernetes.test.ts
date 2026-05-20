import { describe, expect, it } from "vitest";
import { auditK8sManifest } from "./kubernetes.js";

const has = (content: string, rule: string): boolean =>
  auditK8sManifest({ content }).some((f) => f.rule === rule);

// A reasonably hardened Pod manifest used as the negative baseline.
const HARDENED = [
  "apiVersion: v1",
  "kind: Pod",
  "metadata:",
  "  name: app",
  "spec:",
  "  automountServiceAccountToken: false",
  "  containers:",
  "    - name: app",
  "      image: app:1.2.3",
  "      securityContext:",
  "        privileged: false",
  "        runAsNonRoot: true",
  "        runAsUser: 1000",
  "        allowPrivilegeEscalation: false",
  "        readOnlyRootFilesystem: true",
  "        capabilities:",
  "          drop:",
  "            - ALL",
  "      resources:",
  "        limits:",
  "          cpu: 500m",
  "          memory: 256Mi",
].join("\n");

describe("auditK8sManifest — pod security", () => {
  it("flags a privileged container", () => {
    const c = HARDENED.replace("privileged: false", "privileged: true");
    expect(has(c, "k8s-privileged-container")).toBe(true);
  });

  it("flags allowPrivilegeEscalation: true", () => {
    const c = HARDENED.replace("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true");
    expect(has(c, "k8s-allow-privilege-escalation")).toBe(true);
  });

  it("flags runAsUser: 0", () => {
    const c = HARDENED.replace("runAsUser: 1000", "runAsUser: 0");
    expect(has(c, "k8s-run-as-root-explicit")).toBe(true);
  });

  it("flags runAsNonRoot: false", () => {
    const c = HARDENED.replace("runAsNonRoot: true", "runAsNonRoot: false");
    expect(has(c, "k8s-run-as-non-root-false")).toBe(true);
  });

  it("flags hostNetwork, hostPID, and hostIPC", () => {
    const c = HARDENED.replace(
      "spec:",
      "spec:\n  hostNetwork: true\n  hostPID: true\n  hostIPC: true",
    );
    expect(has(c, "k8s-host-network")).toBe(true);
    expect(has(c, "k8s-host-pid")).toBe(true);
    expect(has(c, "k8s-host-ipc")).toBe(true);
  });

  it("does not flag the hardened baseline", () => {
    const findings = auditK8sManifest({ content: HARDENED });
    expect(findings).toHaveLength(0);
  });
});

describe("auditK8sManifest — capabilities and structure", () => {
  it("flags a dangerous added capability in block form", () => {
    const c = HARDENED.replace(
      "        capabilities:\n          drop:\n            - ALL",
      "        capabilities:\n          add:\n            - SYS_ADMIN",
    );
    expect(has(c, "k8s-dangerous-capability")).toBe(true);
  });

  it("flags a dangerous added capability in inline-list form", () => {
    const c = HARDENED.replace(
      "        capabilities:\n          drop:\n            - ALL",
      '        capabilities:\n          add: ["NET_ADMIN"]',
    );
    expect(has(c, "k8s-dangerous-capability")).toBe(true);
  });

  it("flags a missing securityContext", () => {
    const c = [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "spec:",
      "  template:",
      "    spec:",
      "      containers:",
      "        - name: app",
      "          image: app:1.0.0",
      "          resources:",
      "            limits:",
      "              cpu: 100m",
      "              memory: 64Mi",
    ].join("\n");
    expect(has(c, "k8s-missing-security-context")).toBe(true);
  });

  it("flags missing resource limits", () => {
    const c = HARDENED.replace(
      "      resources:\n        limits:\n          cpu: 500m\n          memory: 256Mi",
      "",
    );
    expect(has(c, "k8s-missing-resource-limits")).toBe(true);
  });

  it("flags a hostPath volume", () => {
    const c = HARDENED + "\n  volumes:\n    - name: host\n      hostPath:\n        path: /";
    expect(has(c, "k8s-hostpath-volume")).toBe(true);
  });
});

describe("auditK8sManifest — images and RBAC", () => {
  it("flags a :latest container image", () => {
    const c = HARDENED.replace("image: app:1.2.3", "image: app:latest");
    expect(has(c, "k8s-mutable-image-tag")).toBe(true);
  });

  it("flags an untagged container image", () => {
    const c = HARDENED.replace("image: app:1.2.3", "image: nginx");
    expect(has(c, "k8s-mutable-image-tag")).toBe(true);
  });

  it("does not flag a version-pinned image", () => {
    expect(has(HARDENED, "k8s-mutable-image-tag")).toBe(false);
  });

  it("flags wildcard verbs in an RBAC role", () => {
    const c = [
      "apiVersion: rbac.authorization.k8s.io/v1",
      "kind: ClusterRole",
      "metadata:",
      "  name: too-broad",
      "rules:",
      '  - apiGroups: ["*"]',
      '    resources: ["*"]',
      '    verbs: ["*"]',
    ].join("\n");
    expect(has(c, "k8s-wildcard-rbac")).toBe(true);
  });

  it("does not flag a narrowly scoped RBAC role", () => {
    const c = [
      "apiVersion: rbac.authorization.k8s.io/v1",
      "kind: Role",
      "metadata:",
      "  name: scoped",
      "rules:",
      '  - apiGroups: [""]',
      '    resources: ["pods"]',
      '    verbs: ["get", "list"]',
    ].join("\n");
    expect(has(c, "k8s-wildcard-rbac")).toBe(false);
  });

  it("flags an automatically mounted service-account token", () => {
    const c = HARDENED.replace(
      "automountServiceAccountToken: false",
      "automountServiceAccountToken: true",
    );
    expect(has(c, "k8s-automount-sa-token")).toBe(true);
  });
});

describe("auditK8sManifest — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const c = HARDENED.replace("privileged: false", "privileged: true");
    const a = auditK8sManifest({ content: c, filename: "pod.yaml" });
    const b = auditK8sManifest({ content: c, filename: "pod.yaml" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("emits findings tagged iac with a real CWE", () => {
    const c = HARDENED.replace("privileged: false", "privileged: true");
    const f = auditK8sManifest({ content: c }).find((x) => x.rule === "k8s-privileged-container");
    expect(f?.module).toBe("iac");
    expect(f?.tags).toContain("iac");
    expect((f?.cwe ?? []).some((id) => id.startsWith("CWE-"))).toBe(true);
  });
});
