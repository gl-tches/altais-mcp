import { describe, expect, it } from "vitest";
import {
  detectLanguage,
  isSupported,
  languageFromExtension,
  normalizeLanguage,
} from "./languages.js";

describe("languageFromExtension", () => {
  it("maps TS/JS extensions", () => {
    expect(languageFromExtension("foo.ts")).toBe("typescript");
    expect(languageFromExtension("foo.tsx")).toBe("typescript");
    expect(languageFromExtension("foo.js")).toBe("javascript");
    expect(languageFromExtension("foo.mjs")).toBe("javascript");
  });

  it("maps Python extensions", () => {
    expect(languageFromExtension("a/b/foo.py")).toBe("python");
    expect(languageFromExtension("foo.PYW")).toBe("python");
  });

  it("maps Go and Rust extensions", () => {
    expect(languageFromExtension("foo.go")).toBe("go");
    expect(languageFromExtension("src/lib.rs")).toBe("rust");
  });

  it("returns unknown for unfamiliar extensions", () => {
    expect(languageFromExtension("foo.xyz")).toBe("unknown");
    expect(languageFromExtension("Makefile")).toBe("unknown");
  });
});

describe("normalizeLanguage", () => {
  it("normalizes common aliases", () => {
    expect(normalizeLanguage("TS")).toBe("typescript");
    expect(normalizeLanguage("Python3")).toBe("python");
    expect(normalizeLanguage("golang")).toBe("go");
  });

  it("returns unknown for unrecognized input", () => {
    expect(normalizeLanguage("klingon")).toBe("unknown");
  });
});

describe("detectLanguage", () => {
  it("prefers explicit language", () => {
    expect(detectLanguage({ language: "python", filename: "a.ts" })).toBe("python");
  });

  it("falls back to filename", () => {
    expect(detectLanguage({ filename: "foo.py" })).toBe("python");
  });

  it("sniffs shebang as last resort", () => {
    expect(detectLanguage({ source: "#!/usr/bin/env python3\nprint(1)\n" })).toBe("python");
    expect(detectLanguage({ source: "#!/usr/bin/env node\nconsole.log(1)\n" })).toBe("javascript");
  });

  it("returns unknown when no signal", () => {
    expect(detectLanguage({})).toBe("unknown");
    expect(detectLanguage({ source: "x = 1" })).toBe("unknown");
  });
});

describe("isSupported", () => {
  it("accepts Phase 1 languages", () => {
    expect(isSupported("typescript")).toBe(true);
    expect(isSupported("javascript")).toBe(true);
    expect(isSupported("python")).toBe(true);
  });

  it("accepts Go and Rust", () => {
    expect(isSupported("go")).toBe(true);
    expect(isSupported("rust")).toBe(true);
  });

  it("rejects others", () => {
    expect(isSupported("java")).toBe(false);
    expect(isSupported("unknown")).toBe(false);
  });
});
