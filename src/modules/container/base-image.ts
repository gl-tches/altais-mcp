// Base image assessor (altais_check_base_image).
//
// Takes a single image reference (as written in a `FROM` line or a
// Compose `image:` key) and assesses it for the three things that make a
// base image a liability: it is not pinned to an immutable version, it is
// past end-of-life and no longer patched, or it is a full OS image whose
// bulk is unused attack surface.

import type { Finding } from "../../core/types.js";
import { buildContainerFinding } from "./finding.js";

export interface BaseImageAuditInput {
  readonly image: string;
  readonly filename?: string;
}

const REFS = [
  "https://docs.docker.com/develop/security-best-practices/",
  "https://owasp.org/www-project-docker-top-10/",
  "https://github.com/GoogleContainerTools/distroless",
];

interface ParsedImage {
  readonly registry: string;
  readonly repository: string;
  /** Official Docker Hub image name (e.g. "node"), or undefined. */
  readonly official: string | undefined;
  readonly tag: string | undefined;
  readonly digest: string | undefined;
}

function parseImage(image: string): ParsedImage {
  const trimmed = image.trim();
  const atIdx = trimmed.indexOf("@");
  const digest = atIdx >= 0 ? trimmed.slice(atIdx + 1) : undefined;
  const beforeDigest = atIdx >= 0 ? trimmed.slice(0, atIdx) : trimmed;

  let registry = "docker.io";
  let remainder = beforeDigest;
  const firstSlash = beforeDigest.indexOf("/");
  if (firstSlash >= 0) {
    const head = beforeDigest.slice(0, firstSlash);
    if (head.includes(".") || head.includes(":") || head === "localhost") {
      registry = head;
      remainder = beforeDigest.slice(firstSlash + 1);
    }
  }

  const nameSeg = remainder.slice(remainder.lastIndexOf("/") + 1);
  const colon = nameSeg.lastIndexOf(":");
  const tag = colon >= 0 ? nameSeg.slice(colon + 1) : undefined;
  const repository =
    colon >= 0 ? remainder.slice(0, remainder.length - (tag?.length ?? 0) - 1) : remainder;

  return { registry, repository, official: officialName(registry, repository), tag, digest };
}

/** The Docker Hub official image name for a repository, or undefined. */
function officialName(registry: string, repository: string): string | undefined {
  if (registry !== "docker.io") return undefined;
  if (repository.startsWith("library/")) return repository.slice("library/".length);
  if (!repository.includes("/")) return repository;
  return undefined;
}

interface EolRule {
  readonly name: string;
  readonly tag: RegExp;
  readonly detail: string;
}

const EOL_RULES: readonly EolRule[] = [
  {
    name: "centos",
    tag: /.*/,
    detail: "CentOS Linux reached end-of-life in 2024 and receives no further updates",
  },
  { name: "python", tag: /^2(?:[.-]|$)/, detail: "Python 2 reached end-of-life on 2020-01-01" },
  {
    name: "node",
    tag: /^(?:[0-9]|1[0-9])(?:[.-]|$)/,
    detail: "Node.js releases before v20 are end-of-life",
  },
  {
    name: "ubuntu",
    tag: /^(?:14\.04|16\.04|18\.04)(?:[.-]|$)/,
    detail: "this Ubuntu release is past its standard end-of-life",
  },
  {
    name: "debian",
    tag: /^(?:8|9|10|jessie|stretch|buster)(?:[.-]|$)/i,
    detail: "this Debian release is past its end-of-life",
  },
];

// Official base images that ship a smaller `-slim` / `-alpine` variant.
const HAS_MINIMAL_VARIANT = new Set([
  "node",
  "python",
  "ruby",
  "golang",
  "php",
  "openjdk",
  "eclipse-temurin",
  "perl",
]);

// Full OS images whose bulk is rarely needed at runtime.
const FULL_OS_IMAGES = new Set([
  "ubuntu",
  "debian",
  "centos",
  "fedora",
  "rockylinux",
  "almalinux",
  "amazonlinux",
  "oraclelinux",
]);

const MINIMAL_TAG_RE = /(?:alpine|slim|distroless|-bookworm-slim|chiseled|wolfi)/i;

export function checkBaseImage(input: BaseImageAuditInput): readonly Finding[] {
  const file = input.filename;
  const image = input.image.trim();
  const findings: Finding[] = [];
  if (image === "" || image.toLowerCase() === "scratch") return findings;

  const parsed = parseImage(image);
  const tagLower = parsed.tag?.toLowerCase();

  // ── Pinning ───────────────────────────────────────────────────────────
  if (parsed.digest === undefined) {
    if (parsed.tag === undefined || tagLower === "latest") {
      findings.push(
        mk(
          file,
          "base-image-unpinned",
          "medium",
          `Base image \`${image}\` is not pinned to a fixed version`,
          "An untagged image or the `latest` tag is mutable. The same reference can resolve to a different image over time, so builds are not reproducible and a compromised or breaking image can be pulled silently.",
          "Reference an explicit version tag, and pin to an immutable digest for full reproducibility (`image:1.2.3@sha256:...`).",
          ["CWE-1357", "CWE-829"],
          image,
        ),
      );
    } else {
      findings.push(
        mk(
          file,
          "base-image-not-digest-pinned",
          "low",
          `Base image \`${image}\` is tagged but not digest-pinned`,
          "A version tag is mutable: a registry can re-point it, so a tag alone does not guarantee the exact bytes pulled. Digest pinning makes the dependency tamper-evident.",
          "Append the image digest (`@sha256:...`) so the build always pulls the exact reviewed image.",
          ["CWE-1357"],
          image,
        ),
      );
    }
  }

  // ── End-of-life base images ───────────────────────────────────────────
  if (parsed.official !== undefined && parsed.tag !== undefined) {
    for (const rule of EOL_RULES) {
      if (parsed.official === rule.name && rule.tag.test(parsed.tag)) {
        findings.push(
          mk(
            file,
            "base-image-end-of-life",
            "high",
            `Base image \`${image}\` is end-of-life`,
            `${capitalize(rule.detail)}. An EOL base image receives no security patches, so every CVE disclosed against it remains exploitable.`,
            "Move to a currently supported release of the base image and rebuild on a regular cadence.",
            ["CWE-1104", "CWE-1329"],
            image,
          ),
        );
        break;
      }
    }
  }

  // ── Image bloat / minimal-variant opportunity ─────────────────────────
  const tagIsMinimal = parsed.tag !== undefined && MINIMAL_TAG_RE.test(parsed.tag);
  if (parsed.official !== undefined && !tagIsMinimal) {
    if (HAS_MINIMAL_VARIANT.has(parsed.official)) {
      findings.push(
        mk(
          file,
          "base-image-not-minimal",
          "info",
          `Base image \`${image}\` is not a minimal variant`,
          "The default language image bundles a full toolchain and OS userland. Most of it is unused at runtime and only adds CVE exposure and image size.",
          `Use the \`-slim\` or \`-alpine\` variant of \`${parsed.official}\`, or a distroless runtime image for the final stage of a multi-stage build.`,
          ["CWE-1357"],
          image,
        ),
      );
    } else if (FULL_OS_IMAGES.has(parsed.official)) {
      findings.push(
        mk(
          file,
          "base-image-full-os",
          "info",
          `Base image \`${image}\` is a full operating-system image`,
          "A full OS image ships a package manager, shell, and many libraries the application does not need, enlarging the runtime attack surface.",
          "Where a shell and package manager are not required at runtime, prefer a distroless or minimal image; otherwise use the `-slim` variant.",
          ["CWE-1357"],
          image,
        ),
      );
    }
  }

  return findings;
}

function mk(
  file: string | undefined,
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
      tags: ["base-image", "supply-chain"],
    },
    file,
  );
}

function capitalize(s: string): string {
  return s.length === 0 ? s : s.charAt(0).toUpperCase() + s.slice(1);
}
