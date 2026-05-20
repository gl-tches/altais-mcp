import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { HOST_HEADER_INJECTION_PATTERNS } from "./host-header-injection.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(HOST_HEADER_INJECTION_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("host-header-injection patterns - pattern ids", () => {
  it("has unique rule ids", () => {
    const ids = HOST_HEADER_INJECTION_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every pattern references CWE-644", () => {
    for (const p of HOST_HEADER_INJECTION_PATTERNS) {
      expect(p.cwe).toContain("CWE-644");
      expect(p.references.length).toBeGreaterThan(0);
    }
  });
});

describe("host-header-injection patterns - URL from Host", () => {
  describe("positives", () => {
    it("flags a template URL built from req.headers.host", () => {
      const rules = scan("const url = `https://${req.headers.host}/x`;", "javascript");
      expect(rules).toContain("host-header-url-from-host-js");
    });

    it("flags a concatenated URL from req.hostname", () => {
      const rules = scan(`const url = "https://" + req.hostname;`, "javascript");
      expect(rules).toContain("host-header-url-from-host-js");
    });

    it("flags use of the X-Forwarded-Host header", () => {
      const rules = scan(`const h = req.headers["x-forwarded-host"];`, "javascript");
      expect(rules).toContain("host-header-forwarded-host-js");
    });

    it("flags a Python URL from request.host_url", () => {
      const rules = scan(`link = request.host_url + "/reset"`, "python");
      expect(rules).toContain("host-header-url-from-host-py");
    });

    it("flags Django request.get_host()", () => {
      const rules = scan(`host = request.get_host()`, "python");
      expect(rules).toContain("host-header-url-from-host-py");
    });

    it("flags a Go URL built from r.Host", () => {
      const rules = scan(`url := "https://" + r.Host + "/x"`, "go");
      expect(rules).toContain("host-header-url-from-host-go");
    });
  });

  describe("negatives", () => {
    it("does not flag a URL built from a configured base", () => {
      const rules = scan("const url = `${config.baseUrl}/x`;", "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag a Python url_for call", () => {
      const rules = scan(`link = url_for("reset", _external=True)`, "python");
      expect(rules).toEqual([]);
    });
  });
});

describe("host-header-injection patterns - password reset links", () => {
  it("flags a reset link built from the Host header in JS", () => {
    const rules = scan(
      "const resetUrl = `https://${req.headers.host}/reset?token=${token}`;",
      "javascript",
    );
    expect(rules).toContain("host-header-password-reset-link-js");
  });

  it("flags a Python reset link built from request.host_url", () => {
    const rules = scan(`reset_link = request.host_url + "/reset/" + token`, "python");
    expect(rules).toContain("host-header-password-reset-link-py");
  });

  it("does not flag a reset link from a configured base URL", () => {
    const rules = scan("const resetUrl = `${CONFIG.appUrl}/reset?token=${token}`;", "javascript");
    expect(rules).not.toContain("host-header-password-reset-link-js");
  });

  it("ranks the password-reset rule as critical severity", () => {
    const p = HOST_HEADER_INJECTION_PATTERNS.find(
      (x) => x.id === "host-header-password-reset-link-js",
    );
    expect(p?.severity).toBe("critical");
  });
});
