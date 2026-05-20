import { describe, expect, it } from "vitest";
import { checkErrorHandling, type ErrorHandlingLanguage } from "./error-handling.js";

const has = (source: string, language: ErrorHandlingLanguage, rule: string): boolean =>
  checkErrorHandling({ source, language }).some((f) => f.rule === rule);

describe("checkErrorHandling — information leakage", () => {
  it("flags a stack trace returned in a response", () => {
    expect(has("res.send(err.stack);\n", "javascript", "stack-trace-in-response")).toBe(true);
  });

  it("flags an exception message returned in a response", () => {
    expect(
      has("res.json({ error: err.message });\n", "typescript", "exception-message-in-response"),
    ).toBe(true);
  });

  it("flags Java printStackTrace", () => {
    expect(has("e.printStackTrace();\n", "java", "print-stack-trace")).toBe(true);
  });

  it("flags a Python traceback returned to the client", () => {
    expect(
      has("return jsonify(error=traceback.format_exc())\n", "python", "traceback-in-response"),
    ).toBe(true);
  });

  it("does not flag a sanitized error response", () => {
    expect(
      has(
        'res.json({ error: "Internal Server Error" });\n',
        "javascript",
        "exception-message-in-response",
      ),
    ).toBe(false);
  });
});

describe("checkErrorHandling — swallowed errors", () => {
  it("flags an empty catch block", () => {
    expect(
      has("try { f(); } catch (e) {}\n", "javascript", "swallowed-exception-empty-catch"),
    ).toBe(true);
  });

  it("flags except: pass", () => {
    expect(has("try:\n    f()\nexcept: pass\n", "python", "swallowed-exception-pass")).toBe(true);
  });

  it("flags a broad catch of Exception", () => {
    expect(has("} catch (Exception ex) {\n", "java", "broad-exception-catch")).toBe(true);
  });

  it("does not flag a catch block that logs the error", () => {
    expect(
      has("try { f(); } catch (e) { log(e); }\n", "javascript", "swallowed-exception-empty-catch"),
    ).toBe(false);
  });
});

describe("checkErrorHandling — debug mode", () => {
  it("flags Flask debug mode enabled", () => {
    expect(has("app.run(debug=True)\n", "python", "debug-mode-enabled")).toBe(true);
  });

  it("flags DEBUG = True", () => {
    expect(has("DEBUG = True\n", "python", "debug-mode-enabled")).toBe(true);
  });

  it("does not flag debug disabled", () => {
    expect(has("DEBUG = False\n", "python", "debug-mode-enabled")).toBe(false);
  });
});

describe("checkErrorHandling — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const src = "res.send(err.stack);\ntry { f(); } catch (e) {}\n";
    const a = checkErrorHandling({ source: src, language: "javascript", filename: "app.js" });
    const b = checkErrorHandling({ source: src, language: "javascript", filename: "app.js" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the code module and a CWE", () => {
    const findings = checkErrorHandling({
      source: "res.send(err.stack);\n",
      language: "javascript",
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("code");
      expect(f.tags).toContain("code");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
