import { describe, expect, it } from "vitest";
import { parseUnifiedDiff } from "./diff.js";

describe("parseUnifiedDiff", () => {
  it("parses a single-file, single-hunk diff", () => {
    const diff = `diff --git a/app.js b/app.js
index 1111111..2222222 100644
--- a/app.js
+++ b/app.js
@@ -10,5 +10,7 @@
 unchanged
-removed line
+added line 1
+added line 2
 still here
`;
    const files = parseUnifiedDiff(diff);
    expect(files).toHaveLength(1);
    expect(files[0]?.path).toBe("app.js");
    expect(files[0]?.hunks).toHaveLength(1);
    const hunk = files[0]?.hunks[0];
    expect(hunk?.newStart).toBe(10);
    expect(hunk?.addedLineNumbers).toEqual([11, 12]);
    expect(hunk?.newLines).toContain("added line 1");
    expect(hunk?.newLines).not.toContain("removed line");
  });

  it("parses diffs with multiple files", () => {
    const diff = `diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,2 +1,2 @@
-old
+new
 same
diff --git a/b.ts b/b.ts
--- a/b.ts
+++ b/b.ts
@@ -1 +1,2 @@
 same
+brand new
`;
    const files = parseUnifiedDiff(diff);
    expect(files.map((f) => f.path)).toEqual(["a.py", "b.ts"]);
    expect(files[1]?.hunks[0]?.addedLineNumbers).toEqual([2]);
  });

  it("handles `/dev/null` headers for created/deleted files", () => {
    const diff = `diff --git a/new.js b/new.js
new file mode 100644
--- /dev/null
+++ b/new.js
@@ -0,0 +1,2 @@
+console.log(1);
+console.log(2);
`;
    const files = parseUnifiedDiff(diff);
    expect(files[0]?.path).toBe("new.js");
    expect(files[0]?.hunks[0]?.addedLineNumbers).toEqual([1, 2]);
  });

  it("tracks line numbers across multiple hunks", () => {
    const diff = `+++ b/x.ts
@@ -1,1 +1,1 @@
-a
+a1
@@ -10,2 +10,3 @@
 ctx
+added
 tail
`;
    const files = parseUnifiedDiff(diff);
    const hunks = files[0]?.hunks ?? [];
    expect(hunks).toHaveLength(2);
    expect(hunks[0]?.addedLineNumbers).toEqual([1]);
    expect(hunks[1]?.addedLineNumbers).toEqual([11]);
  });

  it("returns empty for an empty diff", () => {
    expect(parseUnifiedDiff("")).toEqual([]);
  });
});
