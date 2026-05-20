import { describe, expect, it } from "vitest";
import { detectLockfileKind, parseLockfile } from "./index.js";

describe("detectLockfileKind", () => {
  it("recognizes each lockfile", () => {
    expect(detectLockfileKind("package-lock.json")).toBe("npm");
    expect(detectLockfileKind("Cargo.lock")).toBe("cargo");
    expect(detectLockfileKind("poetry.lock")).toBe("poetry");
    expect(detectLockfileKind("go.sum")).toBe("go");
  });

  it("returns null for unknown", () => {
    expect(detectLockfileKind("requirements.txt")).toBeNull();
  });
});

describe("parseLockfile - npm v3", () => {
  it("parses packages map", () => {
    const content = JSON.stringify({
      name: "demo",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": {
          version: "4.17.10",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.10.tgz",
          integrity: "sha512-abc",
          dev: false,
        },
        "node_modules/@scope/pkg": {
          version: "2.0.0",
          license: "MIT",
        },
      },
    });
    const r = parseLockfile(content, "npm");
    expect(r.ecosystem).toBe("npm");
    expect(r.packages.map((p) => p.name).sort()).toEqual(["@scope/pkg", "lodash"]);
    expect(r.packages.find((p) => p.name === "lodash")?.version).toBe("4.17.10");
    expect(r.packages.find((p) => p.name === "@scope/pkg")?.license).toBe("MIT");
  });

  it("parses lockfileVersion 1 dependencies tree", () => {
    const content = JSON.stringify({
      name: "old",
      lockfileVersion: 1,
      dependencies: {
        lodash: {
          version: "4.17.10",
          dependencies: { underscore: { version: "1.10.0" } },
        },
      },
    });
    const r = parseLockfile(content, "npm");
    expect(r.packages.map((p) => p.name).sort()).toEqual(["lodash", "underscore"]);
  });
});

describe("parseLockfile - cargo", () => {
  it("parses package entries with version + checksum", () => {
    const content = `version = 3

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "tokio"
version = "1.36.0"
`;
    const r = parseLockfile(content, "cargo");
    expect(r.packages).toHaveLength(2);
    expect(r.packages[0]?.integrity).toBe("sha256:abc123");
  });
});

describe("parseLockfile - poetry", () => {
  it("parses [[package]] entries", () => {
    const content = `[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP for Humans"
category = "main"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"

[metadata]
lock-version = "2.0"
`;
    const r = parseLockfile(content, "poetry");
    expect(r.packages).toHaveLength(2);
    const pytest = r.packages.find((p) => p.name === "pytest");
    expect(pytest?.dev).toBe(true);
  });
});

describe("parseLockfile - go", () => {
  it("dedupes module and go.mod lines for the same version", () => {
    const content = `github.com/spf13/cobra v1.8.0 h1:abc=
github.com/spf13/cobra v1.8.0/go.mod h1:abc=
gopkg.in/yaml.v3 v3.0.0 h1:xyz=
`;
    const r = parseLockfile(content, "go");
    expect(r.packages).toHaveLength(2);
    expect(r.packages.map((p) => p.name).sort()).toEqual([
      "github.com/spf13/cobra",
      "gopkg.in/yaml.v3",
    ]);
  });

  it("skips comment and empty lines", () => {
    const content = `// this is a comment

github.com/example v0.1.0 h1:zzz=
`;
    const r = parseLockfile(content, "go");
    expect(r.packages).toHaveLength(1);
  });
});
