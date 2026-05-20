import { describe, expect, it } from "vitest";
import { auditPasswordHashing } from "./password.js";

describe("auditPasswordHashing", () => {
  it("flags MD5 password hashing as critical", () => {
    const r = auditPasswordHashing({
      source: 'const hashed = crypto.createHash("md5").update(password).digest("hex");',
    });
    expect(r.some((f) => f.rule === "password-weak-hash-context")).toBe(true);
    expect(r.find((f) => f.rule === "password-weak-hash-context")?.severity).toBe("critical");
  });

  it("flags SHA-1 in password context", () => {
    const r = auditPasswordHashing({
      source: 'const h = hashlib.new("sha1", password.encode()).hexdigest();',
    });
    expect(r.some((f) => f.rule === "password-weak-hash-context")).toBe(true);
  });

  it("does not flag SHA-256 in non-password context", () => {
    const r = auditPasswordHashing({
      source:
        'const etag = crypto.createHash("sha256").update(body).digest("hex");\nimport argon2 from "argon2";',
    });
    // Suspect finding may fire but not the high-confidence password one.
    expect(r.filter((f) => f.rule === "password-weak-hash-context")).toEqual([]);
  });

  it("accepts argon2 use", () => {
    const r = auditPasswordHashing({
      source: 'import argon2 from "argon2";\nconst hash = await argon2.hash(password);',
    });
    expect(r.filter((f) => f.rule === "password-no-strong-kdf-detected")).toEqual([]);
  });

  it("notes when no strong KDF is detected", () => {
    const r = auditPasswordHashing({ source: "const x = 1;" });
    expect(r.some((f) => f.rule === "password-no-strong-kdf-detected")).toBe(true);
  });

  it("recognizes bcryptjs", () => {
    const r = auditPasswordHashing({
      source: 'import bcrypt from "bcryptjs";\nconst h = bcrypt.hash(password, 12);',
    });
    expect(r.filter((f) => f.rule === "password-no-strong-kdf-detected")).toEqual([]);
  });
});
