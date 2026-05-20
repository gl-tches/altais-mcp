import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { CRLF_INJECTION_PATTERNS } from "./crlf-injection.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(CRLF_INJECTION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("crlf-injection patterns - pattern ids", () => {
  it("has unique rule ids", () => {
    const ids = CRLF_INJECTION_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every pattern carries a CWE and a reference", () => {
    for (const p of CRLF_INJECTION_PATTERNS) {
      expect(p.cwe.length).toBeGreaterThan(0);
      expect(p.references.length).toBeGreaterThan(0);
    }
  });
});

describe("crlf-injection patterns - response header splitting", () => {
  describe("positives", () => {
    it("flags setHeader with req.query value", () => {
      const rules = scan(`res.setHeader("X-Track", req.query.ref);`, "javascript");
      expect(rules).toContain("crlf-header-from-request-js");
    });

    it("flags res.redirect with request input", () => {
      const rules = scan(`res.redirect(req.query.next);`, "javascript");
      expect(rules).toContain("crlf-redirect-from-request-js");
    });

    it("flags a Location header built from request input", () => {
      const rules = scan(`res.setHeader("Location", req.query.url);`, "javascript");
      expect(rules).toContain("crlf-redirect-from-request-js");
    });

    it("flags a Python response header from request", () => {
      const rules = scan(`response.headers["X-Track"] = request.args.get("ref")`, "python");
      expect(rules).toContain("crlf-header-from-request-py");
    });

    it("flags a Go response header from r.URL.Query()", () => {
      const rules = scan(`w.Header().Set("X-Track", r.URL.Query().Get("ref"))`, "go");
      expect(rules).toContain("crlf-header-from-request-go");
    });

    it("flags a literal CRLF inside a header value", () => {
      const rules = scan(`res.setHeader("X-Multi", "a\\r\\nX-Injected: b");`, "javascript");
      expect(rules).toContain("crlf-literal-in-header-value");
    });
  });

  describe("negatives", () => {
    it("does not flag a static header value", () => {
      const rules = scan(`res.setHeader("X-Frame-Options", "DENY");`, "javascript");
      expect(rules.filter((r) => r.startsWith("crlf-header"))).toEqual([]);
    });

    it("does not flag a redirect to a constant path", () => {
      const rules = scan(`res.redirect("/dashboard");`, "javascript");
      expect(rules).not.toContain("crlf-redirect-from-request-js");
    });
  });
});

describe("crlf-injection patterns - log injection", () => {
  describe("positives", () => {
    it("flags console.log with template interpolation of req", () => {
      const rules = scan("console.log(`login attempt: ${req.body.user}`);", "javascript");
      expect(rules).toContain("crlf-log-injection-request-input-js");
    });

    it("flags logger.info with concatenated req input", () => {
      const rules = scan(`logger.info("user=" + req.query.user);`, "javascript");
      expect(rules).toContain("crlf-log-injection-request-input-js");
    });

    it("flags Python logging.info with f-string of request", () => {
      const rules = scan(`logging.info(f"login: {request.form['user']}")`, "python");
      expect(rules).toContain("crlf-log-injection-request-input-py");
    });
  });

  describe("negatives", () => {
    it("does not flag a static log message", () => {
      const rules = scan(`console.log("server started");`, "javascript");
      expect(rules).not.toContain("crlf-log-injection-request-input-js");
    });

    it("does not flag structured logging with discrete fields", () => {
      const rules = scan(`logger.info("login", { user: sanitize(req.body.user) });`, "javascript");
      expect(rules).not.toContain("crlf-log-injection-request-input-js");
    });
  });
});
