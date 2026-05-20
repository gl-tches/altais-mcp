// Dockerfile auditor (altais_audit_dockerfile).
//
// Parses a Dockerfile into logical instructions (joining `\` line
// continuations, dropping comments) and checks each build stage for the
// well-known image-hardening failures: running as root, mutable base
// image tags, `ADD` of remote URLs, pipe-to-shell installs, credentials
// baked into ENV/ARG, world-writable permissions, and missing hygiene.

import type { Finding } from "../../core/types.js";
import { buildContainerFinding } from "./finding.js";

export interface DockerfileAuditInput {
  readonly content: string;
  readonly filename?: string;
}

const REFS = [
  "https://docs.docker.com/develop/develop-images/instructions/",
  "https://docs.docker.com/develop/security-best-practices/",
  "https://owasp.org/www-project-docker-top-10/",
];

interface Instruction {
  readonly keyword: string;
  readonly args: string;
  readonly line: number;
}

/**
 * Parse a Dockerfile into logical instructions. Comment-only and blank
 * lines are dropped; `\` continuations are joined onto the instruction
 * they belong to. The reported line is the instruction's first line.
 */
function parseInstructions(content: string): readonly Instruction[] {
  const lines = content.split(/\r?\n/);
  const out: Instruction[] = [];
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i] ?? "";
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("#")) {
      i += 1;
      continue;
    }
    const startLine = i + 1;
    let buf = raw;
    while (/\\\s*$/.test(buf) && i + 1 < lines.length) {
      buf = buf.replace(/\\\s*$/, " ");
      i += 1;
      const next = lines[i] ?? "";
      // Comment lines inside a continuation are ignored by the Docker parser.
      buf += next.trim().startsWith("#") ? "" : next;
    }
    const m = /^\s*(\w+)\s+([\s\S]*)$/.exec(buf);
    const keyword = m?.[1];
    const args = m?.[2];
    if (keyword !== undefined && args !== undefined) {
      out.push({ keyword: keyword.toUpperCase(), args: args.trim(), line: startLine });
    }
    i += 1;
  }
  return out;
}

interface FromRef {
  readonly image: string;
  readonly alias: string | undefined;
  readonly line: number;
}

/** Parse a `FROM` instruction's arguments into image ref + optional stage alias. */
function parseFrom(instr: Instruction): FromRef {
  const tokens = instr.args.split(/\s+/).filter((t) => t.length > 0 && !t.startsWith("--"));
  const image = tokens[0] ?? "";
  let alias: string | undefined;
  for (let j = 1; j < tokens.length - 1; j++) {
    if (tokens[j]?.toLowerCase() === "as") {
      alias = tokens[j + 1]?.toLowerCase();
      break;
    }
  }
  return { image, alias, line: instr.line };
}

const ROOT_USERS = new Set(["root", "0", "0:0", "root:root"]);

export function auditDockerfile(input: DockerfileAuditInput): readonly Finding[] {
  const file = input.filename ?? "Dockerfile";
  const instructions = parseInstructions(input.content);
  const findings: Finding[] = [];

  const froms = instructions.filter((i) => i.keyword === "FROM").map(parseFrom);
  const stageAliases = new Set(
    froms.map((f) => f.alias).filter((a): a is string => a !== undefined),
  );

  // ── Unpinned base images ──────────────────────────────────────────────
  for (const from of froms) {
    const image = from.image;
    const lower = image.toLowerCase();
    if (image === "" || lower === "scratch" || stageAliases.has(lower)) continue;
    if (image.includes("@sha256:")) continue; // digest-pinned — reproducible
    const tag = extractTag(image);
    if (tag === undefined || tag.toLowerCase() === "latest") {
      findings.push(
        buildContainerFinding(
          {
            rule: "dockerfile-unpinned-base-image",
            severity: "medium",
            title: `Base image \`${image}\` is not pinned to a fixed version`,
            description:
              "An untagged image or the `latest` tag is mutable: the same Dockerfile can resolve to a different, possibly malicious or breaking, image on the next build. Builds are not reproducible.",
            remediation:
              "Pin the base image to an explicit version tag, and ideally to an immutable digest (`image:1.2.3@sha256:...`).",
            cwe: ["CWE-1357", "CWE-829"],
            references: REFS,
            evidence: `FROM ${image}`,
            tags: ["dockerfile", "supply-chain"],
            line: from.line,
          },
          file,
        ),
      );
    }
  }

  // ── Runs as root in the final stage ───────────────────────────────────
  const lastFromIdx = lastIndexOf(instructions, (i) => i.keyword === "FROM");
  const finalStage = lastFromIdx >= 0 ? instructions.slice(lastFromIdx) : instructions;
  const finalUsers = finalStage.filter((i) => i.keyword === "USER");
  const lastUser = finalUsers[finalUsers.length - 1];
  const finalStageFromLine = lastFromIdx >= 0 ? instructions[lastFromIdx]?.line : undefined;
  if (lastUser === undefined || ROOT_USERS.has(lastUser.args.trim().toLowerCase())) {
    findings.push(
      buildContainerFinding(
        {
          rule: "dockerfile-runs-as-root",
          severity: "high",
          title: "Container's final stage runs as root",
          description:
            lastUser === undefined
              ? "No `USER` instruction switches the final build stage to an unprivileged account, so the container runs as root by default. A process escape then starts with root on the host namespace."
              : "The final `USER` instruction sets the container back to root, so the runtime process has unnecessary privileges.",
          remediation:
            "Create a dedicated unprivileged user and add `USER <name>` (or a numeric UID) as the last user switch in the final stage.",
          cwe: ["CWE-250", "CWE-269"],
          references: REFS,
          evidence: lastUser ? `USER ${lastUser.args}` : "no USER instruction",
          tags: ["dockerfile", "privilege"],
          ...(lastUser
            ? { line: lastUser.line }
            : finalStageFromLine
              ? { line: finalStageFromLine }
              : {}),
        },
        file,
      ),
    );
  }

  // ── Per-instruction checks ────────────────────────────────────────────
  let hasHealthcheck = false;
  for (const instr of instructions) {
    if (instr.keyword === "HEALTHCHECK") hasHealthcheck = true;

    if (instr.keyword === "ADD") {
      if (/\bhttps?:\/\//i.test(instr.args)) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-add-remote-url",
            "medium",
            "`ADD` fetches a remote URL without integrity verification",
            "`ADD` with an `http(s)://` source downloads the file at build time with no checksum or signature check. A compromised or hijacked URL silently injects content into the image.",
            "Download with `RUN curl -fsSL`, verify a known checksum, then use the file. For local files use `COPY`.",
            ["CWE-494", "CWE-829"],
            `ADD ${instr.args}`.slice(0, 200),
          ),
        );
      } else {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-add-instead-of-copy",
            "low",
            "`ADD` used where `COPY` is sufficient",
            "`ADD` has surprising behavior: it auto-extracts local tar archives and accepts remote URLs. For plain file copies this is an unnecessary, error-prone superset of `COPY`.",
            "Use `COPY` for copying local files and directories into the image.",
            ["CWE-1357"],
            `ADD ${instr.args}`.slice(0, 200),
          ),
        );
      }
    }

    if (instr.keyword === "RUN") {
      if (/\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|a|da)?sh\b/i.test(instr.args)) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-curl-pipe-shell",
            "high",
            "Remote script piped directly into a shell",
            "Piping a downloaded script straight into a shell executes unverified, attacker-controllable code at build time. There is no opportunity to inspect or checksum the payload.",
            "Download the script to a file, verify its checksum or signature, review it, then execute it.",
            ["CWE-494", "CWE-829"],
            instr.args.slice(0, 200),
          ),
        );
      }
      if (/\bchmod\s+(?:-[A-Za-z]+\s+)*0?777\b/.test(instr.args)) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-world-writable-permissions",
            "medium",
            "`chmod 777` grants world-writable permissions",
            "Mode 777 lets any user in the container read, write, and execute the target. A lower-privileged or compromised process can then tamper with those files.",
            "Grant the narrowest permissions that work — typically `chmod 755` for executables, `644` for data — owned by the runtime user.",
            ["CWE-732"],
            instr.args.slice(0, 200),
          ),
        );
      }
      if (/(?:^|[;&|]|\s)sudo\s/.test(instr.args)) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-sudo-in-run",
            "low",
            "`sudo` used inside a `RUN` instruction",
            "Build steps already run as the current `USER` (root unless changed). `sudo` adds an unaudited privilege path and is unnecessary in a Dockerfile.",
            "Remove `sudo`; if a step needs elevated privileges, sequence the `USER` instructions instead.",
            ["CWE-250"],
            instr.args.slice(0, 200),
          ),
        );
      }
      if (
        /\bapt(?:-get)?\s+install\b/.test(instr.args) &&
        !instr.args.includes("--no-install-recommends")
      ) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-apt-no-recommends",
            "info",
            "`apt-get install` without `--no-install-recommends`",
            "Without `--no-install-recommends`, apt pulls recommended packages, enlarging the image and its attack surface with software the application does not use.",
            "Add `--no-install-recommends` to `apt-get install` and run `rm -rf /var/lib/apt/lists/*` in the same layer.",
            ["CWE-1357"],
            instr.args.slice(0, 200),
          ),
        );
      }
    }

    if (instr.keyword === "ENV" || instr.keyword === "ARG") {
      const secret = detectSecretAssignment(instr.args);
      if (secret !== undefined) {
        findings.push(
          finding(
            file,
            instr.line,
            "dockerfile-secret-in-build-arg",
            "high",
            `Credential baked into a Dockerfile ${instr.keyword} instruction`,
            "`ENV` values persist in the final image and `ARG`/`ENV` values are recorded in image history (`docker history`). Anyone who can pull the image can read the secret.",
            "Never bake secrets into the image. Use BuildKit secret mounts (`RUN --mount=type=secret`) at build time, or inject secrets at runtime from a secrets manager.",
            ["CWE-798", "CWE-538"],
            `${instr.keyword} ${secret}`.slice(0, 200),
          ),
        );
      }
    }

    if (instr.keyword === "COPY" && /(?:^|\s)\.\s+\S/.test(instr.args)) {
      findings.push(
        finding(
          file,
          instr.line,
          "dockerfile-copy-entire-context",
          "low",
          "`COPY .` copies the entire build context",
          "Copying the whole context risks pulling `.git`, local `.env` files, credentials, and `node_modules` into the image, leaking secrets and bloating layers.",
          "Copy only the paths the image needs, and add a `.dockerignore` that excludes `.git`, `.env`, secrets, and build artifacts.",
          ["CWE-538"],
          `COPY ${instr.args}`.slice(0, 200),
        ),
      );
    }
  }

  if (instructions.length > 0 && !hasHealthcheck) {
    findings.push(
      buildContainerFinding(
        {
          rule: "dockerfile-no-healthcheck",
          severity: "info",
          title: "No `HEALTHCHECK` instruction",
          description:
            "Without a `HEALTHCHECK`, the orchestrator cannot tell a wedged or unresponsive container from a healthy one, delaying restarts and masking failures.",
          remediation:
            "Add a `HEALTHCHECK` that probes a real liveness signal (an HTTP endpoint or a CLI check).",
          cwe: ["CWE-1357"],
          references: REFS,
          tags: ["dockerfile", "hygiene"],
        },
        file,
      ),
    );
  }

  return findings;
}

function finding(
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
      tags: ["dockerfile"],
      line,
    },
    file,
  );
}

/** Extract the tag from an image reference, ignoring any registry port. */
function extractTag(image: string): string | undefined {
  const withoutDigest = image.split("@")[0] ?? image;
  const lastSlash = withoutDigest.lastIndexOf("/");
  const namePart = withoutDigest.slice(lastSlash + 1);
  const colon = namePart.lastIndexOf(":");
  return colon >= 0 ? namePart.slice(colon + 1) : undefined;
}

/** Name of an assigned variable if it looks credential-bearing, else undefined. */
const SECRET_KEY_RE =
  /\b([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|AUTH_KEY)[A-Za-z0-9_]*)\b\s*=\s*("[^"]+"|'[^']+'|\S+)/i;

function detectSecretAssignment(args: string): string | undefined {
  const m = SECRET_KEY_RE.exec(args);
  if (m === null) return undefined;
  const value = (m[2] ?? "").replace(/^["']|["']$/g, "");
  // A bare `ARG NAME` (no value) or a placeholder build-arg reference is not a leak.
  if (value === "" || value.startsWith("$")) return undefined;
  return m[0];
}

function lastIndexOf<T>(arr: readonly T[], pred: (v: T) => boolean): number {
  for (let i = arr.length - 1; i >= 0; i--) {
    const v = arr[i];
    if (v !== undefined && pred(v)) return i;
  }
  return -1;
}
