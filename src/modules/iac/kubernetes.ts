// Kubernetes manifest auditor (altais_audit_k8s_manifest).
//
// Checks a Kubernetes manifest's text against the Pod Security
// Standards and least-privilege RBAC guidance: privileged containers,
// privilege escalation, root execution, shared host namespaces,
// dangerous added capabilities, missing security context, missing
// resource limits, mounted service-account tokens, hostPath volumes,
// a writable root filesystem, mutable image tags, and wildcard RBAC.
// Manifests are YAML, but a line-oriented scan keeps the module
// dependency-free while covering the keys that matter.

import type { Finding } from "../../core/types.js";
import { buildIacFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface K8sAuditInput {
  readonly content: string;
  readonly filename?: string;
}

const REFS = [
  "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
  "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
  "https://owasp.org/www-project-kubernetes-top-ten/",
];

const PATTERNS: readonly SourcePattern[] = [
  {
    rule: "k8s-privileged-container",
    regex: /^[ \t]*privileged:[ \t]*true\b/im,
    severity: "critical",
    title: "Container runs in privileged mode",
    description:
      "`privileged: true` gives the container all capabilities and direct access to host devices. It removes nearly every isolation boundary, so a container escape leads straight to host compromise.",
    remediation:
      "Remove `privileged: true`. Grant only the specific capabilities the workload needs via `securityContext.capabilities.add` and mount only the devices it requires.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-allow-privilege-escalation",
    regex: /^[ \t]*allowPrivilegeEscalation:[ \t]*true\b/im,
    severity: "high",
    title: "Container allows privilege escalation",
    description:
      "`allowPrivilegeEscalation: true` lets a process gain more privileges than its parent (for example via setuid binaries), undermining a non-root container's protection.",
    remediation:
      "Set `allowPrivilegeEscalation: false` in the container `securityContext`. This is required by the `restricted` Pod Security Standard.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-run-as-root-explicit",
    regex: /^[ \t]*runAsUser:[ \t]*0\b/im,
    severity: "high",
    title: "Container is explicitly configured to run as UID 0 (root)",
    description:
      "`runAsUser: 0` runs the container process as root. A process escape then begins with root in the host user namespace, dramatically raising the impact of a compromise.",
    remediation:
      "Set `runAsUser` to a non-zero UID and `runAsNonRoot: true`. Build the image so its files are owned by that unprivileged user.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-run-as-non-root-false",
    regex: /^[ \t]*runAsNonRoot:[ \t]*false\b/im,
    severity: "high",
    title: "Container is allowed to run as root (`runAsNonRoot: false`)",
    description:
      "`runAsNonRoot: false` disables the guard that rejects an image whose default user is root, so the workload can silently run with root privileges.",
    remediation:
      "Set `runAsNonRoot: true` and provide a non-zero `runAsUser`. This is required by the `restricted` Pod Security Standard.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-host-network",
    regex: /^[ \t]*hostNetwork:[ \t]*true\b/im,
    severity: "high",
    title: "Pod shares the host network namespace",
    description:
      "`hostNetwork: true` places the pod directly on the node's network stack. It can bind host ports, reach node-local services, and bypass NetworkPolicy isolation.",
    remediation:
      "Remove `hostNetwork: true` unless the workload is a trusted node-level agent. Expose the pod through a Service instead.",
    cwe: ["CWE-668"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-host-pid",
    regex: /^[ \t]*hostPID:[ \t]*true\b/im,
    severity: "high",
    title: "Pod shares the host PID namespace",
    description:
      "`hostPID: true` lets the pod see and signal every process on the node, enabling reconnaissance and interference with host and other-container processes.",
    remediation: "Remove `hostPID: true` unless the workload is a dedicated, trusted host monitor.",
    cwe: ["CWE-668"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-host-ipc",
    regex: /^[ \t]*hostIPC:[ \t]*true\b/im,
    severity: "medium",
    title: "Pod shares the host IPC namespace",
    description:
      "`hostIPC: true` shares System V IPC and POSIX shared memory with the node, allowing the pod to read or tamper with shared-memory segments of host processes.",
    remediation: "Remove `hostIPC: true`; use a private IPC namespace (the default).",
    cwe: ["CWE-668"],
    tags: ["kubernetes", "pod-security"],
  },
  {
    rule: "k8s-automount-sa-token",
    regex: /^[ \t]*automountServiceAccountToken:[ \t]*true\b/im,
    severity: "medium",
    title: "Service-account token is automatically mounted",
    description:
      "`automountServiceAccountToken: true` mounts a Kubernetes API token into the pod. If the workload does not call the API the token is needless attack surface — a compromised pod uses it to talk to the cluster.",
    remediation:
      "Set `automountServiceAccountToken: false` on the pod (or its ServiceAccount) unless the workload genuinely needs the Kubernetes API.",
    cwe: ["CWE-250", "CWE-668"],
    tags: ["kubernetes", "rbac"],
  },
];

const SECURITY_CONTEXT_RE = /^[ \t]*securityContext[ \t]*:/m;
const RESOURCE_LIMITS_RE = /^[ \t]*limits[ \t]*:/m;
const READONLY_ROOT_TRUE_RE = /^[ \t]*readOnlyRootFilesystem:[ \t]*true\b/m;
const KIND_RE = /^[ \t]*kind[ \t]*:[ \t]*["']?([A-Za-z]+)["']?/m;
const RUN_AS_NON_ROOT_RE = /^[ \t]*runAsNonRoot[ \t]*:/m;

// Dangerous Linux capabilities that materially widen the host attack surface.
const DANGEROUS_CAPS = new Set([
  "ALL",
  "SYS_ADMIN",
  "NET_ADMIN",
  "SYS_PTRACE",
  "SYS_MODULE",
  "SYS_RAWIO",
  "DAC_READ_SEARCH",
  "DAC_OVERRIDE",
  "NET_RAW",
  "BPF",
]);

export function auditK8sManifest(input: K8sAuditInput): readonly Finding[] {
  const file = input.filename ?? "manifest.yaml";
  const src = input.content;
  const findings: Finding[] = [...scanWithPatterns(src, PATTERNS, REFS, file)];

  const lines = src.split(/\r?\n/);
  const kind = KIND_RE.exec(src)?.[1] ?? "";
  const isWorkload = /Deployment|Pod|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob/i.test(kind);

  // ── Added Linux capabilities ──────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    findings.push(...scanCapabilities(lines, i, file));
    findings.push(...scanImageLine(lines, i, file));
  }

  // ── Workload-level structural checks ──────────────────────────────────
  if (isWorkload) {
    if (SECURITY_CONTEXT_RE.exec(src) === null) {
      findings.push(
        structural(
          file,
          "k8s-missing-security-context",
          "high",
          "Workload defines no `securityContext`",
          "With no `securityContext`, the workload inherits permissive defaults: it may run as root, allow privilege escalation, and keep a writable root filesystem.",
          "Add a `securityContext` that sets `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and drops all capabilities.",
          ["CWE-250", "CWE-16"],
        ),
      );
    }
    if (RESOURCE_LIMITS_RE.exec(src) === null) {
      findings.push(
        structural(
          file,
          "k8s-missing-resource-limits",
          "medium",
          "Workload defines no CPU / memory `resources.limits`",
          "Without `resources.limits`, a runaway or compromised container can consume all node CPU and memory, starving other pods — a denial-of-service condition.",
          "Set `resources.limits` (and `resources.requests`) for CPU and memory on every container.",
          ["CWE-770", "CWE-400"],
        ),
      );
    }
    if (READONLY_ROOT_TRUE_RE.exec(src) === null) {
      findings.push(
        structural(
          file,
          "k8s-writable-root-filesystem",
          "low",
          "Container root filesystem is not read-only",
          "Without `readOnlyRootFilesystem: true`, a compromised process can drop tools, modify binaries, or persist within the container image layer at runtime.",
          "Set `readOnlyRootFilesystem: true` and mount a writable `emptyDir` only for the specific paths the application must write to.",
          ["CWE-732", "CWE-16"],
        ),
      );
    }
    if (RUN_AS_NON_ROOT_RE.exec(src) === null) {
      findings.push(
        structural(
          file,
          "k8s-missing-run-as-non-root",
          "medium",
          "Workload does not set `runAsNonRoot`",
          "When `runAsNonRoot` is unset the kubelet does not reject an image whose default user is root, so the container can silently run with root privileges.",
          "Set `runAsNonRoot: true` (and a non-zero `runAsUser`) in the pod or container `securityContext`.",
          ["CWE-250"],
        ),
      );
    }
  }

  // ── hostPath volumes ──────────────────────────────────────────────────
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (/^[ \t]*hostPath[ \t]*:/.test(line)) {
      findings.push(
        buildIacFinding(
          {
            rule: "k8s-hostpath-volume",
            severity: "high",
            title: "Pod mounts a `hostPath` volume from the node filesystem",
            description:
              "A `hostPath` volume mounts a directory from the node into the pod. A compromised container can then read or write node files — and a path such as `/` or `/var/run/docker.sock` is a direct route to node takeover.",
            remediation:
              "Avoid `hostPath`. Use a `persistentVolumeClaim`, `emptyDir`, `configMap`, or `secret` volume instead. If a host mount is unavoidable, scope it to the narrowest possible read-only path.",
            cwe: ["CWE-668", "CWE-250"],
            references: REFS,
            evidence: "hostPath",
            tags: ["kubernetes", "pod-security"],
            line: i + 1,
          },
          file,
        ),
      );
    }
  }

  // ── Overly broad RBAC ─────────────────────────────────────────────────
  if (/Role|ClusterRole/i.test(kind)) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      const m = /^[ \t]*(verbs|resources|apiGroups)[ \t]*:[ \t]*\[([^\]]*)\]/.exec(line);
      if (m === null) continue;
      const list = m[2] ?? "";
      if (/["']\*["']/.test(list) || /(?:^|,)[ \t]*\*[ \t]*(?:,|$)/.test(list)) {
        findings.push(
          buildIacFinding(
            {
              rule: "k8s-wildcard-rbac",
              severity: "high",
              title: `RBAC rule grants a wildcard \`${m[1] ?? ""}\``,
              description:
                "A wildcard (`*`) in an RBAC rule's `verbs`, `resources`, or `apiGroups` grants sweeping cluster access. A subject bound to this role can perform far more than any single workload needs, and a compromised credential becomes cluster-wide.",
              remediation:
                "Replace `*` with the explicit verbs and resource types the subject actually requires. Prefer a narrowly scoped namespaced `Role` over a `ClusterRole` whenever possible.",
              cwe: ["CWE-284", "CWE-732"],
              references: REFS,
              evidence: line.trim().slice(0, 200),
              tags: ["kubernetes", "rbac"],
              line: i + 1,
            },
            file,
          ),
        );
      }
    }
  }

  return findings;
}

/** Scan a block / inline `add:` capabilities list starting at line `idx`. */
function scanCapabilities(lines: readonly string[], idx: number, file: string): readonly Finding[] {
  const line = lines[idx] ?? "";
  const head = /^([ \t]*)add[ \t]*:[ \t]*(.*)$/.exec(line);
  if (head === null) return [];
  const indent = (head[1] ?? "").length;
  const inline = (head[2] ?? "").trim();
  const caps: string[] = [];

  if (inline.startsWith("[")) {
    for (const tok of inline.replace(/[[\]]/g, "").split(",")) {
      const c = tok.trim().replace(/^["']|["']$/g, "");
      if (c !== "") caps.push(c);
    }
  } else if (inline === "") {
    for (let j = idx + 1; j < lines.length; j++) {
      const next = lines[j] ?? "";
      if (next.trim() === "") continue;
      const itemIndent = next.length - next.trimStart().length;
      if (itemIndent <= indent || !next.trimStart().startsWith("-")) break;
      const c = next
        .trim()
        .replace(/^-[ \t]*/, "")
        .replace(/[ \t]+#.*$/, "")
        .replace(/^["']|["']$/g, "");
      if (c !== "") caps.push(c);
    }
  }

  const findings: Finding[] = [];
  for (const cap of caps) {
    const upper = cap.toUpperCase();
    if (DANGEROUS_CAPS.has(upper)) {
      findings.push(
        buildIacFinding(
          {
            rule: "k8s-dangerous-capability",
            severity: upper === "ALL" || upper === "SYS_ADMIN" ? "high" : "medium",
            title: `Dangerous Linux capability added: ${upper}`,
            description: `The container's \`securityContext.capabilities.add\` grants ${upper}, which substantially widens what the container can do to the kernel and node. SYS_ADMIN and ALL in particular are routinely used for container escapes.`,
            remediation:
              "Drop all capabilities (`capabilities.drop: [ALL]`) and add back only the individually verified capabilities the workload proves it needs.",
            cwe: ["CWE-250", "CWE-269"],
            references: REFS,
            evidence: `add: ${upper}`,
            tags: ["kubernetes", "pod-security"],
            line: idx + 1,
          },
          file,
        ),
      );
    }
  }
  return findings;
}

/** Flag an `image:` line that uses `:latest` or carries no tag at all. */
function scanImageLine(lines: readonly string[], idx: number, file: string): readonly Finding[] {
  const line = lines[idx] ?? "";
  const m = /^[ \t]*-?[ \t]*image[ \t]*:[ \t]*["']?([^\s"'#]+)["']?/.exec(line);
  if (m === null) return [];
  const ref = m[1] ?? "";
  if (ref === "" || ref.includes("@sha256:") || ref.includes("$") || ref.includes("{{")) return [];
  const tag = imageTag(ref);
  if (tag !== undefined && tag.toLowerCase() !== "latest") return [];
  return [
    buildIacFinding(
      {
        rule: "k8s-mutable-image-tag",
        severity: "low",
        title: `Container image \`${ref}\` is not pinned to a fixed version`,
        description:
          "An untagged image or the `latest` tag is mutable: a pod restart can pull a different image, so the deployment is not reproducible and a poisoned tag is hard to detect.",
        remediation:
          "Pin the image to an explicit version tag, ideally with an immutable digest (`image:1.2.3@sha256:...`), and set `imagePullPolicy: IfNotPresent`.",
        cwe: ["CWE-1357", "CWE-829"],
        references: REFS,
        evidence: `image: ${ref}`,
        tags: ["kubernetes", "supply-chain"],
        line: idx + 1,
      },
      file,
    ),
  ];
}

function structural(
  file: string,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
): Finding {
  return buildIacFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      tags: ["kubernetes", "pod-security"],
    },
    file,
  );
}

/** Extract the tag from an image reference, ignoring any registry port. */
function imageTag(ref: string): string | undefined {
  const withoutDigest = ref.split("@")[0] ?? ref;
  const lastSlash = withoutDigest.lastIndexOf("/");
  const namePart = withoutDigest.slice(lastSlash + 1);
  const colon = namePart.lastIndexOf(":");
  return colon >= 0 ? namePart.slice(colon + 1) : undefined;
}
