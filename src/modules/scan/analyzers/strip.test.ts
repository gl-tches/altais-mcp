import { describe, expect, it } from "vitest";
import { stripCommentsGo, stripCommentsPy, stripCommentsRust, stripCommentsTs } from "./strip.js";

describe("stripCommentsTs", () => {
  it("removes line comments while preserving line numbers", () => {
    const src = "const x = 1; // dangerous\nconst y = 2;";
    const stripped = stripCommentsTs(src);
    expect(stripped).not.toMatch(/dangerous/);
    expect(stripped.split("\n")).toHaveLength(2);
  });

  it("removes block comments", () => {
    const src = "const x = /* eval('bad') */ 1;";
    expect(stripCommentsTs(src)).not.toMatch(/eval/);
  });

  it("preserves multi-line block comments line-by-line", () => {
    const src = "a\n/* line1\nline2 */\nb";
    const stripped = stripCommentsTs(src);
    expect(stripped.split("\n")).toHaveLength(4);
    expect(stripped).not.toMatch(/line1/);
  });

  it("does not strip inside string literals", () => {
    const src = `const s = "this // is not a comment";`;
    expect(stripCommentsTs(src)).toMatch(/this \/\/ is not a comment/);
  });

  it("preserves template literal content", () => {
    const src = "const s = `hello ${name}`;";
    expect(stripCommentsTs(src)).toMatch(/\$\{name\}/);
  });

  it("handles escaped quotes in strings", () => {
    const src = `const s = "a\\"b"; // gone`;
    const out = stripCommentsTs(src);
    expect(out).toMatch(/a\\"b/);
    expect(out).not.toMatch(/gone/);
  });
});

describe("stripCommentsPy", () => {
  it("removes `#` comments", () => {
    const src = "x = 1  # dangerous\ny = 2";
    expect(stripCommentsPy(src)).not.toMatch(/dangerous/);
  });

  it("does not strip `#` inside strings", () => {
    const src = `s = "url#fragment"`;
    expect(stripCommentsPy(src)).toMatch(/url#fragment/);
  });

  it("preserves triple-quoted docstrings", () => {
    const src = `def f():\n    """eval is mentioned here"""\n    return 1`;
    expect(stripCommentsPy(src)).toMatch(/eval is mentioned here/);
  });
});

describe("stripCommentsGo", () => {
  it("removes line comments while preserving line numbers", () => {
    const src = "x := 1 // dangerous\ny := 2";
    const stripped = stripCommentsGo(src);
    expect(stripped).not.toMatch(/dangerous/);
    expect(stripped.split("\n")).toHaveLength(2);
  });

  it("removes block comments", () => {
    const src = "x := /* exec.Command here */ 1";
    expect(stripCommentsGo(src)).not.toMatch(/exec\.Command/);
  });

  it("preserves multi-line block comments line-by-line", () => {
    const src = "a\n/* line1\nline2 */\nb";
    const stripped = stripCommentsGo(src);
    expect(stripped.split("\n")).toHaveLength(4);
    expect(stripped).not.toMatch(/line1/);
  });

  it("does not strip inside interpreted strings", () => {
    const src = `s := "this // is not a comment"`;
    expect(stripCommentsGo(src)).toMatch(/this \/\/ is not a comment/);
  });

  it("preserves raw string content spanning multiple lines", () => {
    const src = "s := `select * from t\nwhere id = 1` // gone";
    const stripped = stripCommentsGo(src);
    expect(stripped).toMatch(/select \* from t/);
    expect(stripped).not.toMatch(/gone/);
    expect(stripped.split("\n")).toHaveLength(2);
  });

  it("handles escaped quotes and rune literals", () => {
    const src = `s := "a\\"b"; r := '\\n' // gone`;
    const out = stripCommentsGo(src);
    expect(out).toMatch(/a\\"b/);
    expect(out).not.toMatch(/gone/);
  });
});

describe("stripCommentsRust", () => {
  it("removes line comments while preserving line numbers", () => {
    const src = "let x = 1; // dangerous\nlet y = 2;";
    const stripped = stripCommentsRust(src);
    expect(stripped).not.toMatch(/dangerous/);
    expect(stripped.split("\n")).toHaveLength(2);
  });

  it("fully strips nested block comments", () => {
    const src = "let x = /* outer /* inner unwrap() */ still */ 1;";
    const stripped = stripCommentsRust(src);
    expect(stripped).not.toMatch(/outer/);
    expect(stripped).not.toMatch(/inner/);
    expect(stripped).not.toMatch(/unwrap/);
    expect(stripped).not.toMatch(/still/);
    expect(stripped).toMatch(/let x = .* 1;/);
  });

  it("preserves multi-line block comments line-by-line", () => {
    const src = "a\n/* line1\nline2 */\nb";
    const stripped = stripCommentsRust(src);
    expect(stripped.split("\n")).toHaveLength(4);
    expect(stripped).not.toMatch(/line1/);
  });

  it("does not strip inside string literals", () => {
    const src = `let s = "this // is not a comment";`;
    expect(stripCommentsRust(src)).toMatch(/this \/\/ is not a comment/);
  });

  it("preserves raw string content with hashes spanning lines", () => {
    const src = 'let s = r#"select * from t\nwhere x = "y""#; // gone';
    const stripped = stripCommentsRust(src);
    expect(stripped).toMatch(/select \* from t/);
    expect(stripped).toMatch(/where x = "y"/);
    expect(stripped).not.toMatch(/gone/);
    expect(stripped.split("\n")).toHaveLength(2);
  });

  it("keeps a lifetime like &'a str intact", () => {
    const src = "fn f<'a>(x: &'a str) -> &'a str { x } // gone";
    const stripped = stripCommentsRust(src);
    expect(stripped).toMatch(/&'a str/);
    expect(stripped).toMatch(/<'a>/);
    expect(stripped).not.toMatch(/gone/);
  });

  it("treats a char literal as a string and leaves its content", () => {
    const src = "let c = '/'; let n = '\\n'; // gone";
    const stripped = stripCommentsRust(src);
    expect(stripped).toMatch(/'\/'/);
    expect(stripped).not.toMatch(/gone/);
    expect(stripped.split("\n")).toHaveLength(1);
  });
});
