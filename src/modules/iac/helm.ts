// Helm chart auditor (altais_audit_helm_chart).
//
// Reviews a Helm chart — typically a `values.yaml`, optionally with
// concatenated templates — for insecure defaults: privileged pods,
// mutable image tags, publicly exposing service types, disabled RBAC,
// disabled security context, default / hardcoded passwords, and secrets
// rendered into ConfigMaps. A line-oriented scan keeps the module
// dependency-free while covering the keys that matter.

import type { Finding } from "../../core/types.js";
import { buildIacFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface HelmAuditInput {
  readonly content: string;
  readonly filename?: string;
}

const REFS = [
  "https://helm.sh/docs/topics/security/",
  "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
  "https://owasp.org/www-project-kubernetes-top-ten/",
];

const PATTERNS: readonly SourcePattern[] = [
  {
    rule: "helm-privileged-default",
    regex: /^[ \t]*privileged:[ \t]*true\b/im,
    severity: "critical",
    title: "Chart values enable privileged mode by default",
    description:
      "`privileged: true` in a chart's values renders a privileged container by default. Every install of the chart then ships a pod with no isolation from the node unless the operator overrides it.",
    remediation:
      "Default `privileged` to `false` in `values.yaml`. If a workload genuinely needs elevated access, gate it behind an explicit, well-documented opt-in value.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["helm", "pod-security"],
  },
  {
    rule: "helm-rbac-disabled",
    regex: /^[ \t]*create:[ \t]*false\b[ \t]*(?:#.*)?$/im,
    severity: "medium",
    title: "Chart may disable RBAC resource creation",
    description:
      "A `create: false` value under an `rbac` block means the chart installs no Role / RoleBinding. The workload then either fails closed or, worse, falls back to an over-permissioned existing service account.",
    remediation:
      "Default `rbac.create` to `true` so each install ships a least-privilege Role scoped to exactly what the workload needs.",
    cwe: ["CWE-284", "CWE-16"],
    tags: ["helm", "rbac"],
  },
  {
    rule: "helm-loadbalancer-service",
    regex: /^[ \t]*type:[ \t]*["']?(?:LoadBalancer|NodePort)["']?[ \t]*(?:#.*)?$/im,
    severity: "medium",
    title: "Chart exposes a Service publicly by default",
    description:
      "A default `service.type` of `LoadBalancer` or `NodePort` publishes the workload outside the cluster on install. Many charts ship this for convenience, exposing internal services to the network unintentionally.",
    remediation:
      "Default `service.type` to `ClusterIP`. Require an explicit value change, and pair external exposure with an Ingress that has authentication and TLS.",
    cwe: ["CWE-668", "CWE-284"],
    tags: ["helm", "network"],
  },
];

// Default / weak passwords frequently shipped in chart values.
const WEAK_PASSWORDS = new Set([
  "changeme",
  "change-me",
  "admin",
  "password",
  "secret",
  "root",
  "test",
  "default",
  "123456",
  "postgres",
]);

const SECRET_KEY_RE =
  /^[ \t]*([A-Za-z0-9_]*(?:password|passwd|secret|token|api_?key|access_?key|private_?key|credential)[A-Za-z0-9_]*)[ \t]*:[ \t]*(.+?)[ \t]*$/i;

const IMAGE_TAG_RE = /^[ \t]*tag[ \t]*:[ \t]*(.*?)[ \t]*(?:#.*)?$/i;
const SECURITY_CONTEXT_DISABLED_RE =
  /^[ \t]*(?:securityContext|podSecurityContext|podSecurityPolicy)[ \t]*:[ \t]*(?:false|\{\})[ \t]*(?:#.*)?$/im;
const SET_SECRET_RE =
  /--set[ \t]+([A-Za-z0-9_.]*(?:password|secret|token|api_?key|access_?key)[A-Za-z0-9_.]*)=(\S+)/i;

export function auditHelmChart(input: HelmAuditInput): readonly Finding[] {
  const file = input.filename ?? "values.yaml";
  const src = input.content;
  const findings: Finding[] = [...scanWithPatterns(src, PATTERNS, REFS, file)];

  // ── securityContext / podSecurityPolicy disabled ──────────────────────
  let sc: RegExpExecArray | null;
  const scRe = new RegExp(SECURITY_CONTEXT_DISABLED_RE.source, "gim");
  while ((sc = scRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "helm-security-context-disabled",
          severity: "medium",
          title: "Chart values disable the pod security context",
          description:
            "A `securityContext` / `podSecurityContext` set to `false` or `{}` means the chart renders pods with no hardening — they may run as root with a writable root filesystem and full capabilities.",
          remediation:
            "Default the security context to a hardened block: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and `capabilities.drop: [ALL]`.",
          cwe: ["CWE-250", "CWE-16"],
          references: REFS,
          evidence: lineFor(src, sc.index),
          tags: ["helm", "pod-security"],
          line: countLines(src, sc.index),
        },
        file,
      ),
    );
  }

  // ── `--set`-style secrets embedded in chart notes / docs ──────────────
  let setSecret: RegExpExecArray | null;
  const setRe = new RegExp(SET_SECRET_RE.source, "gi");
  while ((setSecret = setRe.exec(src)) !== null) {
    findings.push(
      buildIacFinding(
        {
          rule: "helm-set-secret",
          severity: "high",
          title: `Secret passed via \`--set\` (\`${setSecret[1] ?? ""}\`)`,
          description:
            "A secret supplied with `helm install --set` is recorded in shell history, in CI logs, and inside the Helm release object stored in the cluster. It is broadly readable.",
          remediation:
            "Pass secrets with `--set-file` from a protected file, or reference a pre-created Kubernetes Secret. Never inline a credential in a `--set` argument.",
          cwe: ["CWE-798", "CWE-532"],
          references: REFS,
          evidence: `--set ${setSecret[1] ?? ""}=********`,
          tags: ["helm", "secrets"],
          line: countLines(src, setSecret.index),
        },
        file,
      ),
    );
  }

  // ── Per-line value checks ─────────────────────────────────────────────
  const lines = src.split(/\r?\n/);
  let inConfigMap = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    // Empty / `latest` image tag.
    const tag = IMAGE_TAG_RE.exec(line);
    if (tag !== null) {
      const value = (tag[1] ?? "").replace(/^["']|["']$/g, "");
      if (value === "" || value.toLowerCase() === "latest") {
        findings.push(
          mk(
            file,
            i + 1,
            "helm-mutable-image-tag",
            "low",
            `Chart image \`tag\` is ${value === "" ? "empty" : "`latest`"}`,
            "An empty or `latest` image tag in `values.yaml` is mutable: each install (or pod restart) can pull a different image, so deployments are not reproducible.",
            "Default `image.tag` to an explicit version, ideally pinned with a digest. Avoid an empty tag, which falls back to `latest`.",
            ["CWE-1357", "CWE-829"],
            line.trim().slice(0, 120),
          ),
        );
      }
    }

    // Default / hardcoded passwords in values.
    const secret = SECRET_KEY_RE.exec(line);
    if (secret !== null) {
      const raw = (secret[2] ?? "").replace(/[ \t]+#.*$/, "").trim();
      const value = raw.replace(/^["']|["']$/g, "");
      const isTemplate =
        value === "" ||
        value.includes("{{") ||
        value.startsWith("$") ||
        value === "~" ||
        value.toLowerCase() === "null";
      if (!isTemplate) {
        const weak = WEAK_PASSWORDS.has(value.toLowerCase());
        findings.push(
          mk(
            file,
            i + 1,
            weak ? "helm-default-password" : "helm-hardcoded-secret",
            weak ? "high" : "high",
            weak
              ? `Weak default password in chart values (\`${secret[1] ?? ""}\`)`
              : `Hardcoded secret in chart values (\`${secret[1] ?? ""}\`)`,
            weak
              ? "A well-known default password such as `changeme` or `admin` in `values.yaml` means every install that does not override it ships an account with publicly known credentials."
              : "A literal credential in `values.yaml` is committed to version control and embedded in the rendered manifests of every install of the chart.",
            weak
              ? "Default the password to an empty value and require the operator to supply one, or generate a random secret at install time with a Helm `randAlphaNum` template."
              : "Remove the literal value. Reference a pre-created Kubernetes Secret, or generate the credential at install time with a Helm template function.",
            ["CWE-798", "CWE-1392"],
            `${secret[1] ?? ""}: ********`,
          ),
        );
      }
    }

    // Templates rendering secrets into a ConfigMap.
    if (/^[ \t]*kind[ \t]*:[ \t]*["']?ConfigMap["']?/.test(line)) inConfigMap = true;
    else if (/^[ \t]*kind[ \t]*:/.test(line)) inConfigMap = false;
    if (
      inConfigMap &&
      /\{\{[^}]*\.(?:Values|Secret)[^}]*(?:password|secret|token|apikey|api_key|key)[^}]*\}\}/i.test(
        line,
      )
    ) {
      findings.push(
        mk(
          file,
          i + 1,
          "helm-secret-in-configmap",
          "high",
          "Template renders a secret value into a ConfigMap",
          "A ConfigMap stores data in plaintext and is not treated as sensitive by Kubernetes RBAC defaults. Rendering a password or token into a ConfigMap exposes it to any subject that can read ConfigMaps.",
          "Render the value into a `Secret` resource instead of a `ConfigMap`, and consume it via `secretKeyRef` or a mounted secret volume.",
          ["CWE-312", "CWE-538"],
          line.trim().slice(0, 120),
        ),
      );
    }
  }

  return findings;
}

function mk(
  file: string,
  line: number,
  rule: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  cwe: readonly string[],
  evidence: string,
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
      evidence,
      tags: ["helm"],
      line,
    },
    file,
  );
}

/** 1-based line number of the offset `idx` within `src`. */
function countLines(src: string, idx: number): number {
  let n = 1;
  for (let i = 0; i < idx; i++) if (src.charCodeAt(i) === 0x0a) n++;
  return n;
}

/** The trimmed text of the line containing offset `idx`. */
function lineFor(src: string, idx: number): string {
  const start = src.lastIndexOf("\n", idx - 1) + 1;
  let end = src.indexOf("\n", idx);
  if (end < 0) end = src.length;
  return src.slice(start, end).trim().slice(0, 120);
}
