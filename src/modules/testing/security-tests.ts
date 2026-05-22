// Security test-case generator (altais_generate_security_tests).
//
// Produces concrete, runnable-shaped test-case templates that assert a
// given vulnerability class is mitigated, with both positive (benign input
// is accepted) and negative (malicious input is rejected) cases.

export type VulnerabilityClass =
  | "injection"
  | "xss"
  | "auth"
  | "access-control"
  | "ssrf"
  | "csrf"
  | "crypto"
  | "business-logic";

export type TestLanguage = "c" | "cpp" | "rust" | "go" | "python" | "javascript" | "java";

export interface SecurityTestsInput {
  readonly vulnerability_class: VulnerabilityClass;
  readonly language: TestLanguage;
  readonly framework?: string;
}

export interface SecurityTestCase {
  readonly name: string;
  readonly type: "positive" | "negative";
  readonly intent: string;
}

export interface SecurityTestsResult {
  readonly vulnerability_class: VulnerabilityClass;
  readonly language: TestLanguage;
  readonly framework: string;
  readonly test_file: { readonly filename: string; readonly content: string };
  readonly cases: readonly SecurityTestCase[];
  readonly cwe: readonly string[];
  readonly references: readonly string[];
}

const DEFAULT_FRAMEWORK: Readonly<Record<TestLanguage, string>> = {
  c: "ctest",
  cpp: "catch2",
  rust: "cargo-test",
  go: "go-test",
  python: "pytest",
  javascript: "jest",
  java: "junit5",
};

const FRAMEWORK_RE = /^[A-Za-z0-9._-]{1,48}$/;

interface ClassMeta {
  readonly cwe: readonly string[];
  readonly references: readonly string[];
  readonly malicious: string;
  readonly benign: string;
  readonly intent_negative: string;
  readonly intent_positive: string;
}

const CLASS_META: Readonly<Record<VulnerabilityClass, ClassMeta>> = {
  injection: {
    cwe: ["CWE-89", "CWE-78", "CWE-77"],
    references: ["https://owasp.org/Top10/A03_2021-Injection/"],
    malicious: "' OR '1'='1' --",
    benign: "alice",
    intent_negative:
      "A SQL meta-character payload must be parameterized and must not alter the query.",
    intent_positive: "A normal identifier is accepted and resolves to exactly one record.",
  },
  xss: {
    cwe: ["CWE-79"],
    references: [
      "https://owasp.org/www-community/attacks/xss/",
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    malicious: "<script>alert(1)</script>",
    benign: "Hello, world",
    intent_negative: "A script payload must be HTML-encoded so it renders inert in the response.",
    intent_positive: "Ordinary text passes through unchanged and is displayed verbatim.",
  },
  auth: {
    cwe: ["CWE-287", "CWE-307", "CWE-521"],
    references: ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    malicious: "wrong-password",
    benign: "correct-password",
    intent_negative:
      "An invalid credential is rejected and repeated attempts trigger lockout / backoff.",
    intent_positive: "A valid credential authenticates and issues a fresh, scoped session token.",
  },
  "access-control": {
    cwe: ["CWE-285", "CWE-639", "CWE-862"],
    references: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    malicious: "other-users-resource-id",
    benign: "own-resource-id",
    intent_negative: "A request for another tenant's object is denied with 403, not 404-as-200.",
    intent_positive: "A request for the caller's own object succeeds.",
  },
  ssrf: {
    cwe: ["CWE-918"],
    references: ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
    malicious: "http://169.254.169.254/latest/meta-data/",
    benign: "https://api.example.com/v1/items",
    intent_negative:
      "A URL pointing at link-local / internal addresses is rejected before any outbound request is made.",
    intent_positive: "A URL on the allow-list is requested normally.",
  },
  csrf: {
    cwe: ["CWE-352"],
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ],
    malicious: "missing-or-forged-token",
    benign: "valid-csrf-token",
    intent_negative: "A state-changing request without a valid anti-CSRF token is rejected.",
    intent_positive: "The same request with a valid token bound to the session succeeds.",
  },
  crypto: {
    cwe: ["CWE-327", "CWE-328", "CWE-916"],
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    ],
    malicious: "password123",
    benign: "password123",
    intent_negative:
      "A stored secret must not be recoverable: the persisted value is a salted slow hash, not plaintext or a fast digest.",
    intent_positive: "The correct password verifies against the stored hash.",
  },
  "business-logic": {
    cwe: ["CWE-840", "CWE-841"],
    references: [
      "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
    ],
    malicious: "-5",
    benign: "3",
    intent_negative:
      "A negative or out-of-bounds quantity must be rejected and must not yield a credit.",
    intent_positive: "A valid quantity within limits is accepted and priced correctly.",
  },
};

function renderCases(meta: ClassMeta): readonly SecurityTestCase[] {
  return [
    { name: "rejects_malicious_input", type: "negative", intent: meta.intent_negative },
    { name: "accepts_benign_input", type: "positive", intent: meta.intent_positive },
    {
      name: "is_consistent_under_repetition",
      type: "negative",
      intent: "The mitigation behaves identically when the malicious input is replayed.",
    },
  ];
}

function pythonTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "# security test for " + vc + " — generated template",
    "import pytest",
    "from app import handle  # the function or endpoint under test",
    "",
    "",
    "def test_rejects_malicious_input():",
    `    """${meta.intent_negative}"""`,
    `    malicious = ${JSON.stringify(meta.malicious)}`,
    "    with pytest.raises(Exception):",
    "        handle(malicious)",
    "",
    "",
    "def test_accepts_benign_input():",
    `    """${meta.intent_positive}"""`,
    `    benign = ${JSON.stringify(meta.benign)}`,
    "    result = handle(benign)",
    "    assert result is not None",
  ].join("\n");
}

function jsTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "// security test for " + vc + " — generated template",
    'const { handle } = require("./app");',
    "",
    `describe("${vc} mitigation", () => {`,
    `  it("rejects malicious input", () => {`,
    `    // ${meta.intent_negative}`,
    `    const malicious = ${JSON.stringify(meta.malicious)};`,
    "    expect(() => handle(malicious)).toThrow();",
    "  });",
    "",
    `  it("accepts benign input", () => {`,
    `    // ${meta.intent_positive}`,
    `    const benign = ${JSON.stringify(meta.benign)};`,
    "    expect(handle(benign)).toBeDefined();",
    "  });",
    "});",
  ].join("\n");
}

function goTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "// security test for " + vc + " — generated template",
    "package app",
    "",
    'import "testing"',
    "",
    "func TestRejectsMaliciousInput(t *testing.T) {",
    `\t// ${meta.intent_negative}`,
    `\tif _, err := Handle(${JSON.stringify(meta.malicious)}); err == nil {`,
    '\t\tt.Fatal("expected malicious input to be rejected")',
    "\t}",
    "}",
    "",
    "func TestAcceptsBenignInput(t *testing.T) {",
    `\t// ${meta.intent_positive}`,
    `\tif _, err := Handle(${JSON.stringify(meta.benign)}); err != nil {`,
    '\t\tt.Fatalf("expected benign input to be accepted: %v", err)',
    "\t}",
    "}",
  ].join("\n");
}

function rustTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "// security test for " + vc + " — generated template",
    "#[cfg(test)]",
    "mod tests {",
    "    use crate::handle;",
    "",
    "    #[test]",
    "    fn rejects_malicious_input() {",
    `        // ${meta.intent_negative}`,
    `        assert!(handle(${JSON.stringify(meta.malicious)}).is_err());`,
    "    }",
    "",
    "    #[test]",
    "    fn accepts_benign_input() {",
    `        // ${meta.intent_positive}`,
    `        assert!(handle(${JSON.stringify(meta.benign)}).is_ok());`,
    "    }",
    "}",
  ].join("\n");
}

function javaTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "// security test for " + vc + " — generated template",
    "import org.junit.jupiter.api.Test;",
    "import static org.junit.jupiter.api.Assertions.*;",
    "",
    "class SecurityTest {",
    "  @Test",
    "  void rejectsMaliciousInput() {",
    `    // ${meta.intent_negative}`,
    `    assertThrows(Exception.class, () -> App.handle(${JSON.stringify(meta.malicious)}));`,
    "  }",
    "",
    "  @Test",
    "  void acceptsBenignInput() {",
    `    // ${meta.intent_positive}`,
    `    assertNotNull(App.handle(${JSON.stringify(meta.benign)}));`,
    "  }",
    "}",
  ].join("\n");
}

function cTest(vc: VulnerabilityClass, meta: ClassMeta): string {
  return [
    "/* security test for " + vc + " — generated template */",
    "#include <assert.h>",
    '#include "app.h"',
    "",
    "int main(void) {",
    `  /* ${meta.intent_negative} */`,
    `  assert(handle(${JSON.stringify(meta.malicious)}) != 0);`,
    `  /* ${meta.intent_positive} */`,
    `  assert(handle(${JSON.stringify(meta.benign)}) == 0);`,
    "  return 0;",
    "}",
  ].join("\n");
}

function renderTestFile(
  language: TestLanguage,
  vc: VulnerabilityClass,
  meta: ClassMeta,
): {
  filename: string;
  content: string;
} {
  switch (language) {
    case "python":
      return {
        filename: `test_${vc.replace(/-/g, "_")}_security.py`,
        content: pythonTest(vc, meta),
      };
    case "javascript":
      return { filename: `${vc}.security.test.js`, content: jsTest(vc, meta) };
    case "go":
      return { filename: `${vc.replace(/-/g, "_")}_security_test.go`, content: goTest(vc, meta) };
    case "rust":
      return {
        filename: `tests/${vc.replace(/-/g, "_")}_security.rs`,
        content: rustTest(vc, meta),
      };
    case "java":
      return { filename: "src/test/java/SecurityTest.java", content: javaTest(vc, meta) };
    case "c":
    case "cpp":
      return {
        filename: `test_${vc.replace(/-/g, "_")}_security.${language === "cpp" ? "cc" : "c"}`,
        content: cTest(vc, meta),
      };
  }
}

export class SecurityTestsError extends Error {
  override readonly name = "SecurityTestsError";
}

export function generateSecurityTests(input: SecurityTestsInput): SecurityTestsResult {
  const framework = input.framework ?? DEFAULT_FRAMEWORK[input.language];
  if (!FRAMEWORK_RE.test(framework)) {
    throw new SecurityTestsError(
      "`framework` must be a short identifier (letters, digits, dot, dash, underscore).",
    );
  }
  const meta = CLASS_META[input.vulnerability_class];
  return {
    vulnerability_class: input.vulnerability_class,
    language: input.language,
    framework,
    test_file: renderTestFile(input.language, input.vulnerability_class, meta),
    cases: renderCases(meta),
    cwe: meta.cwe,
    references: meta.references,
  };
}
