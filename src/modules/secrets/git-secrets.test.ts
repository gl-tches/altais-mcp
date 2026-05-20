import { describe, expect, it } from "vitest";
import { scanGitSecrets } from "./git-secrets.js";
import { SecretPatternRegistry } from "./patterns.js";

let cached: SecretPatternRegistry | null = null;
async function getRegistry(): Promise<SecretPatternRegistry> {
  cached ??= await SecretPatternRegistry.load();
  return cached;
}

describe("scanGitSecrets", () => {
  it("flags an AWS key inside an added line and attributes the commit", async () => {
    const registry = await getRegistry();
    const fake = `ghp_${"a".repeat(36)}`;
    const diff = `commit abc1234def5678
Author: Dev <dev@example.com>
Date:   Mon May 19 10:00:00 2026 +0000

    add config

diff --git a/config.js b/config.js
index 111..222 100644
--- a/config.js
+++ b/config.js
@@ -1,1 +1,2 @@
 const A = 1;
+const TOKEN = "${fake}";
`;
    const findings = scanGitSecrets({ source: diff }, registry);
    const pat = findings.find((f) => f.rule === "github-pat-classic");
    expect(pat).toBeDefined();
    expect(pat?.location?.file).toBe("config.js");
    expect(pat?.location?.line_start).toBe(2);
    expect(pat?.tags).toContain("commit:abc1234def5678");
  });

  it("attributes findings on deleted lines to the same commit, without a new-file line", async () => {
    const registry = await getRegistry();
    const fake = `ghp_${"b".repeat(36)}`;
    const diff = `commit deadbeef1234
diff --git a/old.js b/old.js
--- a/old.js
+++ b/old.js
@@ -1,2 +1,1 @@
-const OLD = "${fake}";
 const KEEP = 1;
`;
    const findings = scanGitSecrets({ source: diff }, registry);
    const pat = findings.find((f) => f.rule === "github-pat-classic");
    expect(pat).toBeDefined();
    expect(pat?.tags).toContain("commit:deadbeef1234");
  });

  it("works on a plain diff without commit headers", async () => {
    const registry = await getRegistry();
    const fake = `ghp_${"c".repeat(36)}`;
    const diff = `+++ b/app.js
@@ -1,1 +1,2 @@
 const X = 1;
+const T = "${fake}";
`;
    const findings = scanGitSecrets({ source: diff }, registry);
    const pat = findings.find((f) => f.rule === "github-pat-classic");
    expect(pat).toBeDefined();
    expect(pat?.location?.file).toBe("app.js");
    expect(pat?.tags.some((t) => t.startsWith("commit:"))).toBe(false);
  });

  it("scans entropy on added lines and tags appropriately", async () => {
    const registry = await getRegistry();
    // 35 distinct chars -> entropy ~5.13 bits/char, above the 5.0 base64 default.
    const HIGH = "Z9pK3mB7cR2vQjL8nF6tH4wY1dXuM5iE0oP";
    const diff = `+++ b/secrets.py
@@ -1,1 +1,2 @@
 import os
+api_key = "${HIGH}"
`;
    const findings = scanGitSecrets({ source: diff }, registry);
    expect(findings.some((f) => f.rule.startsWith("entropy-"))).toBe(true);
  });
});
