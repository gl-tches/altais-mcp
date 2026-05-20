import { describe, expect, it } from "vitest";
import { checkBaseImage } from "./base-image.js";

const has = (image: string, rule: string): boolean =>
  checkBaseImage({ image }).some((f) => f.rule === rule);

describe("checkBaseImage — pinning", () => {
  it("flags an untagged image as unpinned", () => {
    expect(has("ubuntu", "base-image-unpinned")).toBe(true);
  });

  it("flags a :latest image as unpinned", () => {
    expect(has("nginx:latest", "base-image-unpinned")).toBe(true);
  });

  it("flags a tagged-but-not-digest-pinned image", () => {
    expect(has("nginx:1.27.3", "base-image-not-digest-pinned")).toBe(true);
  });

  it("does not flag a digest-pinned image", () => {
    const findings = checkBaseImage({
      image: "node:20-alpine@sha256:0123456789abcdef0123456789abcdef",
    });
    expect(findings.some((f) => f.rule.startsWith("base-image-unpinned"))).toBe(false);
    expect(findings.some((f) => f.rule === "base-image-not-digest-pinned")).toBe(false);
  });

  it("returns no findings for FROM scratch", () => {
    expect(checkBaseImage({ image: "scratch" })).toHaveLength(0);
  });
});

describe("checkBaseImage — end of life", () => {
  it("flags CentOS as end-of-life", () => {
    expect(has("centos:7", "base-image-end-of-life")).toBe(true);
  });

  it("flags Python 2 as end-of-life", () => {
    expect(has("python:2.7", "base-image-end-of-life")).toBe(true);
  });

  it("flags an EOL Node.js major version", () => {
    expect(has("node:16", "base-image-end-of-life")).toBe(true);
  });

  it("flags an EOL Ubuntu release", () => {
    expect(has("ubuntu:18.04", "base-image-end-of-life")).toBe(true);
  });

  it("flags an EOL Debian release by codename", () => {
    expect(has("debian:buster", "base-image-end-of-life")).toBe(true);
  });

  it("does not flag a supported Node.js LTS", () => {
    expect(has("node:22", "base-image-end-of-life")).toBe(false);
  });

  it("does not flag a current Python 3 release", () => {
    expect(has("python:3.12", "base-image-end-of-life")).toBe(false);
  });
});

describe("checkBaseImage — bloat", () => {
  it("flags a full language image as non-minimal", () => {
    expect(has("node:20", "base-image-not-minimal")).toBe(true);
  });

  it("does not flag a slim or alpine variant", () => {
    expect(has("node:20-alpine", "base-image-not-minimal")).toBe(false);
    expect(has("python:3.12-slim", "base-image-not-minimal")).toBe(false);
  });

  it("flags a full OS image", () => {
    expect(has("ubuntu:24.04", "base-image-full-os")).toBe(true);
  });
});

describe("checkBaseImage — registries and shape", () => {
  it("parses a registry-qualified image without a false official match", () => {
    const findings = checkBaseImage({ image: "myregistry.example.com/team/app:1.2.3" });
    expect(findings.some((f) => f.rule === "base-image-not-digest-pinned")).toBe(true);
    expect(findings.some((f) => f.rule === "base-image-not-minimal")).toBe(false);
  });

  it("produces deterministic finding IDs across runs", () => {
    const a = checkBaseImage({ image: "centos:7" });
    const b = checkBaseImage({ image: "centos:7" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the container module and a CWE", () => {
    const findings = checkBaseImage({ image: "centos:7" });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("container");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
