import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { REQUEST_SMUGGLING_PATTERNS } from "./request-smuggling.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(REQUEST_SMUGGLING_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("request-smuggling patterns - pattern ids", () => {
  it("has unique rule ids", () => {
    const ids = REQUEST_SMUGGLING_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every pattern references CWE-444", () => {
    for (const p of REQUEST_SMUGGLING_PATTERNS) {
      expect(p.cwe).toContain("CWE-444");
      expect(p.references.length).toBeGreaterThan(0);
    }
  });
});

describe("request-smuggling patterns - manual framing headers", () => {
  describe("positives", () => {
    it("flags setHeader('Transfer-Encoding', ...) in JS", () => {
      const rules = scan(`res.setHeader("Transfer-Encoding", "chunked");`, "javascript");
      expect(rules).toContain("request-smuggling-manual-transfer-encoding-js");
    });

    it("flags a Transfer-Encoding header in a JS object literal", () => {
      const rules = scan(`const h = { "transfer-encoding": "chunked" };`, "javascript");
      expect(rules).toContain("request-smuggling-manual-transfer-encoding-js");
    });

    it("flags a Python Transfer-Encoding assignment", () => {
      const rules = scan(`headers["Transfer-Encoding"] = "chunked"`, "python");
      expect(rules).toContain("request-smuggling-manual-transfer-encoding-py");
    });

    it("flags a Go Header().Set for Transfer-Encoding", () => {
      const rules = scan(`w.Header().Set("Transfer-Encoding", "chunked")`, "go");
      expect(rules).toContain("request-smuggling-manual-transfer-encoding-go");
    });

    it("flags both Content-Length and Transfer-Encoding in one object", () => {
      const rules = scan(
        `const headers = { "content-length": "10", "transfer-encoding": "chunked" };`,
        "javascript",
      );
      expect(rules).toContain("request-smuggling-conflicting-framing-headers-js");
    });

    it("flags manual Content-Length on a forwarded request", () => {
      const rules = scan(`proxyReq.setHeader("Content-Length", len);`, "javascript");
      expect(rules).toContain("request-smuggling-manual-content-length-forwarded-js");
    });
  });

  describe("negatives", () => {
    it("does not flag a normal Content-Type header", () => {
      const rules = scan(`res.setHeader("Content-Type", "application/json");`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag a single Content-Length without Transfer-Encoding", () => {
      const rules = scan(`const h = { "content-length": "10" };`, "javascript");
      expect(rules).not.toContain("request-smuggling-conflicting-framing-headers-js");
    });
  });
});

describe("request-smuggling patterns - header forwarding", () => {
  describe("positives", () => {
    it("flags forwarding spread req.headers", () => {
      const rules = scan(`http.request(target, { headers: { ...req.headers } });`, "javascript");
      expect(rules).toContain("request-smuggling-forward-raw-headers-js");
    });

    it("flags forwarding req.headers directly", () => {
      const rules = scan(`got(url, { headers: req.headers });`, "javascript");
      expect(rules).toContain("request-smuggling-forward-raw-headers-js");
    });

    it("flags Python forwarding request.headers", () => {
      const rules = scan(`requests.get(url, headers=request.headers)`, "python");
      expect(rules).toContain("request-smuggling-forward-raw-headers-py");
    });
  });

  describe("negatives", () => {
    it("does not flag an allowlisted upstream header set", () => {
      const rules = scan(
        `got(url, { headers: { authorization: req.headers.authorization } });`,
        "javascript",
      );
      expect(rules).not.toContain("request-smuggling-forward-raw-headers-js");
    });

    it("does not flag a Python call with explicit headers", () => {
      const rules = scan(`requests.get(url, headers={"Accept": "application/json"})`, "python");
      expect(rules).not.toContain("request-smuggling-forward-raw-headers-py");
    });
  });
});
