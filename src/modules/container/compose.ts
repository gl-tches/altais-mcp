// Docker Compose auditor (altais_audit_compose).
//
// Scans a Compose file's text for the misconfigurations that hand a
// container control of the host: privileged mode, shared host
// namespaces, a mounted Docker socket, dangerous Linux capabilities, a
// disabled seccomp/AppArmor sandbox, hardcoded credentials, and mutable
// image tags. Compose is YAML, but a line-oriented scan keeps the module
// dependency-free while covering the keys that matter.

import type { Finding } from "../../core/types.js";
import { buildContainerFinding, scanWithPatterns, type SourcePattern } from "./finding.js";

export interface ComposeAuditInput {
  readonly content: string;
  readonly filename?: string;
}

const REFS = [
  "https://docs.docker.com/compose/compose-file/",
  "https://docs.docker.com/engine/security/",
  "https://owasp.org/www-project-docker-top-10/",
];

const PATTERNS: readonly SourcePattern[] = [
  {
    rule: "compose-privileged-container",
    regex: /^[ \t]*privileged:[ \t]*(?:true|yes)\b/im,
    severity: "critical",
    title: "Service runs in privileged mode",
    description:
      "`privileged: true` disables almost all container isolation: the container gets every capability and direct access to host devices. A process escape is then trivial and full host compromise follows.",
    remediation:
      "Remove `privileged: true`. Grant only the specific capabilities the service needs via `cap_add`, and mount only the specific devices it requires.",
    cwe: ["CWE-250", "CWE-269"],
    tags: ["compose"],
  },
  {
    rule: "compose-host-network",
    regex: /^[ \t]*network_mode:[ \t]*["']?host["']?/im,
    severity: "high",
    title: "Service shares the host network namespace",
    description:
      "`network_mode: host` removes network isolation: the container binds directly to host interfaces, can reach loopback-only host services, and bypasses Compose network segmentation.",
    remediation:
      "Use a dedicated Compose network and publish only the ports the service needs with `ports:`.",
    cwe: ["CWE-668"],
    tags: ["compose"],
  },
  {
    rule: "compose-host-pid",
    regex: /^[ \t]*pid:[ \t]*["']?host["']?/im,
    severity: "high",
    title: "Service shares the host PID namespace",
    description:
      "`pid: host` lets the container see and signal every process on the host, enabling reconnaissance and interference with host or other-container processes.",
    remediation: "Remove `pid: host` unless the service is a dedicated, trusted host monitor.",
    cwe: ["CWE-668"],
    tags: ["compose"],
  },
  {
    rule: "compose-host-ipc",
    regex: /^[ \t]*ipc:[ \t]*["']?host["']?/im,
    severity: "medium",
    title: "Service shares the host IPC namespace",
    description:
      "`ipc: host` shares System V IPC and POSIX shared memory with the host, allowing a container to read or tamper with shared-memory segments of host processes.",
    remediation: "Remove `ipc: host`; use a private IPC namespace (the default).",
    cwe: ["CWE-668"],
    tags: ["compose"],
  },
  {
    rule: "compose-docker-socket-mount",
    regex: /(?:\/var)?\/run\/docker\.sock(?::[^\s"']*)?/i,
    severity: "critical",
    title: "Docker socket mounted into a container",
    description:
      "Mounting `/var/run/docker.sock` gives the container full control of the Docker daemon. It can start a privileged container, mount the host filesystem, and take over the host — this is root-equivalent.",
    remediation:
      "Do not mount the Docker socket. If the service must manage containers, use a hardened socket proxy that allows only the minimum required API calls.",
    cwe: ["CWE-250", "CWE-668"],
    tags: ["compose"],
  },
  {
    rule: "compose-sandbox-disabled",
    regex: /(?:seccomp|apparmor)[ \t]*[:=][ \t]*["']?unconfined\b/i,
    severity: "high",
    title: "seccomp or AppArmor sandbox disabled",
    description:
      "`seccomp:unconfined` / `apparmor:unconfined` turns off the syscall and mandatory-access-control filters that block container-escape and kernel-attack syscalls.",
    remediation:
      "Remove the `unconfined` `security_opt`; keep the default seccomp and AppArmor profiles, or supply a tailored profile.",
    cwe: ["CWE-693"],
    tags: ["compose"],
  },
];

// Capabilities that materially expand the host attack surface.
const DANGEROUS_CAPS = new Set([
  "ALL",
  "SYS_ADMIN",
  "SYS_PTRACE",
  "SYS_MODULE",
  "SYS_RAWIO",
  "NET_ADMIN",
  "DAC_READ_SEARCH",
  "DAC_OVERRIDE",
  "BPF",
  "NET_RAW",
]);

const SECRET_KEY_RE =
  /^[ \t]*-?[ \t]*["']?([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*)["']?[ \t]*[:=][ \t]*(.+?)[ \t]*$/i;

const IMAGE_RE = /^[ \t]*image:[ \t]*["']?([^\s"'#]+)["']?/i;

export function auditCompose(input: ComposeAuditInput): readonly Finding[] {
  const file = input.filename ?? "docker-compose.yml";
  const findings: Finding[] = [...scanWithPatterns(input.content, PATTERNS, REFS, file)];

  const lines = input.content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    findings.push(...scanCapabilities(lines, i, file));

    const secret = SECRET_KEY_RE.exec(line);
    if (secret !== null) {
      const value = (secret[2] ?? "").replace(/^["']|["']$/g, "").replace(/[ \t]+#.*$/, "");
      if (value !== "" && !value.startsWith("$") && !/^["']?\$\{/.test(secret[2] ?? "")) {
        findings.push(
          mk(
            file,
            i + 1,
            "compose-hardcoded-secret",
            "high",
            `Hardcoded credential in Compose (\`${secret[1] ?? ""}\`)`,
            "A literal password, token, or key in the Compose file is committed to version control and visible to anyone with repository access.",
            "Reference secrets via environment interpolation (`${DB_PASSWORD}`) sourced from an untracked `.env`, or use the Compose `secrets:` mechanism backed by a secrets manager.",
            ["CWE-798", "CWE-540"],
            `${secret[1] ?? ""}=********`,
          ),
        );
      }
    }

    const image = IMAGE_RE.exec(line);
    if (image !== null) {
      const ref = image[1] ?? "";
      if (ref !== "" && !ref.includes("@sha256:") && !ref.includes("$")) {
        const tag = imageTag(ref);
        if (tag === undefined || tag.toLowerCase() === "latest") {
          findings.push(
            mk(
              file,
              i + 1,
              "compose-unpinned-image",
              "medium",
              `Service image \`${ref}\` is not pinned to a fixed version`,
              "An untagged image or the `latest` tag is mutable — `docker compose pull` can resolve to a different image over time, so the deployment is not reproducible.",
              "Pin the image to an explicit version tag, ideally with an immutable digest (`image:1.2.3@sha256:...`).",
              ["CWE-1357", "CWE-829"],
              `image: ${ref}`,
            ),
          );
        }
      }
    }
  }

  return findings;
}

/** If line `idx` opens a `cap_add:` block or inline list, report dangerous caps. */
function scanCapabilities(lines: readonly string[], idx: number, file: string): readonly Finding[] {
  const line = lines[idx] ?? "";
  const head = /^([ \t]*)cap_add[ \t]*:[ \t]*(.*)$/i.exec(line);
  if (head === null) return [];
  const indent = (head[1] ?? "").length;
  const inline = (head[2] ?? "").trim();
  const caps: string[] = [];

  if (inline.startsWith("[")) {
    for (const tok of inline.replace(/[[\]]/g, "").split(",")) {
      const c = tok.trim().replace(/^["']|["']$/g, "");
      if (c !== "") caps.push(c);
    }
  } else {
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
    if (DANGEROUS_CAPS.has(cap.toUpperCase())) {
      findings.push(
        mk(
          file,
          idx + 1,
          "compose-dangerous-capability",
          cap.toUpperCase() === "ALL" || cap.toUpperCase() === "SYS_ADMIN" ? "high" : "medium",
          `Dangerous Linux capability added: ${cap}`,
          `\`cap_add\` grants ${cap}, which substantially widens what the container can do to the kernel and host. SYS_ADMIN and ALL in particular are routinely used for container escapes.`,
          "Grant only the minimal capabilities the workload proves it needs. Start from `cap_drop: [ALL]` and add back individually verified capabilities.",
          ["CWE-250", "CWE-269"],
          `cap_add: ${cap}`,
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
  return buildContainerFinding(
    {
      rule,
      severity,
      title,
      description,
      remediation,
      cwe,
      references: REFS,
      evidence,
      tags: ["compose"],
      line,
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
