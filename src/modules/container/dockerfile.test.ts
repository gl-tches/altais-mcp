import { describe, expect, it } from "vitest";
import { auditDockerfile } from "./dockerfile.js";

const has = (content: string, rule: string): boolean =>
  auditDockerfile({ content }).some((f) => f.rule === rule);

describe("auditDockerfile — base image pinning", () => {
  it("flags an explicit :latest tag", () => {
    expect(has("FROM node:latest\nUSER node\n", "dockerfile-unpinned-base-image")).toBe(true);
  });

  it("flags an untagged base image", () => {
    expect(has("FROM ubuntu\nUSER app\n", "dockerfile-unpinned-base-image")).toBe(true);
  });

  it("accepts a version-pinned base image", () => {
    expect(has("FROM node:20.11.0\nUSER node\n", "dockerfile-unpinned-base-image")).toBe(false);
  });

  it("accepts a digest-pinned base image", () => {
    const df = "FROM node:20@sha256:0123456789abcdef\nUSER node\n";
    expect(has(df, "dockerfile-unpinned-base-image")).toBe(false);
  });

  it("does not flag a stage alias referenced by a later FROM", () => {
    const df = "FROM golang:1.22 AS build\nRUN go build\nFROM build\nUSER app\n";
    const unpinned = auditDockerfile({ content: df }).filter(
      (f) => f.rule === "dockerfile-unpinned-base-image",
    );
    expect(unpinned).toHaveLength(0);
  });

  it("ignores FROM scratch", () => {
    expect(has("FROM scratch\nUSER app\n", "dockerfile-unpinned-base-image")).toBe(false);
  });
});

describe("auditDockerfile — root user", () => {
  it("flags a Dockerfile with no USER instruction", () => {
    expect(has("FROM node:20\nRUN npm ci\n", "dockerfile-runs-as-root")).toBe(true);
  });

  it("flags a final USER root", () => {
    expect(has("FROM node:20\nUSER node\nUSER root\n", "dockerfile-runs-as-root")).toBe(true);
  });

  it("accepts a non-root USER in the final stage", () => {
    expect(has("FROM node:20\nUSER node\n", "dockerfile-runs-as-root")).toBe(false);
  });

  it("does not flag a root builder stage when the final stage drops privileges", () => {
    const df = "FROM node:20 AS build\nRUN npm ci\nFROM node:20-slim\nUSER node\n";
    expect(has(df, "dockerfile-runs-as-root")).toBe(false);
  });
});

describe("auditDockerfile — ADD / COPY", () => {
  it("flags ADD of a remote URL", () => {
    const df = "FROM node:20\nADD https://example.com/app.tar.gz /app\nUSER node\n";
    expect(has(df, "dockerfile-add-remote-url")).toBe(true);
  });

  it("flags ADD used for a local file", () => {
    expect(
      has("FROM node:20\nADD ./app.js /app.js\nUSER node\n", "dockerfile-add-instead-of-copy"),
    ).toBe(true);
  });

  it("flags COPY of the entire build context", () => {
    expect(has("FROM node:20\nCOPY . .\nUSER node\n", "dockerfile-copy-entire-context")).toBe(true);
  });

  it("does not flag a scoped COPY", () => {
    const df = "FROM node:20\nCOPY package.json ./\nUSER node\n";
    expect(has(df, "dockerfile-copy-entire-context")).toBe(false);
  });
});

describe("auditDockerfile — RUN hardening", () => {
  it("flags a remote script piped into a shell", () => {
    const df = "FROM node:20\nRUN curl -fsSL https://get.example.com | sh\nUSER node\n";
    expect(has(df, "dockerfile-curl-pipe-shell")).toBe(true);
  });

  it("flags wget piped into bash", () => {
    const df = "FROM node:20\nRUN wget -qO- https://x.sh | bash\nUSER node\n";
    expect(has(df, "dockerfile-curl-pipe-shell")).toBe(true);
  });

  it("does not flag curl that writes to a file", () => {
    const df = "FROM node:20\nRUN curl -fsSL https://x -o /tmp/x.sh\nUSER node\n";
    expect(has(df, "dockerfile-curl-pipe-shell")).toBe(false);
  });

  it("flags chmod 777", () => {
    expect(
      has(
        "FROM node:20\nRUN chmod -R 0777 /app\nUSER node\n",
        "dockerfile-world-writable-permissions",
      ),
    ).toBe(true);
  });

  it("does not flag chmod 755", () => {
    expect(
      has("FROM node:20\nRUN chmod 755 /app\nUSER node\n", "dockerfile-world-writable-permissions"),
    ).toBe(false);
  });

  it("flags sudo inside RUN", () => {
    expect(
      has("FROM node:20\nRUN sudo apt-get update\nUSER node\n", "dockerfile-sudo-in-run"),
    ).toBe(true);
  });

  it("flags apt-get install without --no-install-recommends", () => {
    const df = "FROM node:20\nRUN apt-get install -y curl\nUSER node\n";
    expect(has(df, "dockerfile-apt-no-recommends")).toBe(true);
  });

  it("accepts apt-get install with --no-install-recommends across a line continuation", () => {
    const df =
      "FROM node:20\nRUN apt-get update && \\\n    apt-get install -y --no-install-recommends curl\nUSER node\n";
    expect(has(df, "dockerfile-apt-no-recommends")).toBe(false);
  });
});

describe("auditDockerfile — secrets and hygiene", () => {
  it("flags a credential baked into ENV", () => {
    expect(
      has("FROM node:20\nENV API_KEY=abcdef123456\nUSER node\n", "dockerfile-secret-in-build-arg"),
    ).toBe(true);
  });

  it("flags a credential baked into ARG", () => {
    const df = 'FROM node:20\nARG DB_PASSWORD="hunter2pass"\nUSER node\n';
    expect(has(df, "dockerfile-secret-in-build-arg")).toBe(true);
  });

  it("does not flag a non-secret ARG", () => {
    expect(
      has("FROM node:20\nARG NODE_VERSION=20\nUSER node\n", "dockerfile-secret-in-build-arg"),
    ).toBe(false);
  });

  it("does not flag an ARG declared without a value", () => {
    expect(
      has("FROM node:20\nARG BUILD_TOKEN\nUSER node\n", "dockerfile-secret-in-build-arg"),
    ).toBe(false);
  });

  it("flags a missing HEALTHCHECK", () => {
    expect(has("FROM node:20\nUSER node\n", "dockerfile-no-healthcheck")).toBe(true);
  });

  it("accepts a Dockerfile with a HEALTHCHECK", () => {
    const df = "FROM node:20\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nUSER node\n";
    expect(has(df, "dockerfile-no-healthcheck")).toBe(false);
  });
});

describe("auditDockerfile — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const df = "FROM node:latest\nRUN chmod 777 /app\n";
    const a = auditDockerfile({ content: df, filename: "Dockerfile" });
    const b = auditDockerfile({ content: df, filename: "Dockerfile" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the container module and a CWE", () => {
    const findings = auditDockerfile({ content: "FROM node:latest\nRUN chmod 777 /x\n" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("container");
      expect(f.tags).toContain("container");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
