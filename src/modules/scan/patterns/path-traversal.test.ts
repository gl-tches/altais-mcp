import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { PATH_TRAVERSAL_PATTERNS } from "./path-traversal.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(PATH_TRAVERSAL_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("Path traversal patterns", () => {
  describe("positives", () => {
    it("flags fs.readFile with req.body", () => {
      expect(scan(`fs.readFile(req.body.file, cb);`, "javascript")).toContain(
        "path-traversal-fs-request-js",
      );
    });

    it("flags fs.readFileSync with req.params", () => {
      expect(scan(`fs.readFileSync(req.params.path);`, "javascript")).toContain(
        "path-traversal-fs-request-js",
      );
    });

    it("flags fs path concatenation", () => {
      expect(scan(`fs.readFileSync("/tmp/" + name);`, "javascript")).toContain(
        "path-traversal-fs-concat-js",
      );
    });

    it("flags dynamic require()", () => {
      expect(scan(`const m = require(modulePath);`, "javascript")).toContain(
        "path-traversal-require-dynamic",
      );
    });

    it("flags open() with request data (Python)", () => {
      expect(scan(`open(request.args["file"], "r")`, "python")).toContain(
        "path-traversal-open-request-py",
      );
    });

    it("flags os.path.join with request data", () => {
      expect(scan(`p = os.path.join("uploads", request.form["name"])`, "python")).toContain(
        "path-traversal-os-path-join-request-py",
      );
    });

    it("flags Flask send_file with request data", () => {
      expect(scan(`return send_file(request.args["path"])`, "python")).toContain(
        "path-traversal-send-file-py",
      );
    });
  });

  describe("negatives", () => {
    it("does not flag fs.readFile with a static path", () => {
      expect(
        scan(`fs.readFile("./config.json", "utf8", cb);`, "javascript").filter((r) =>
          r.startsWith("path-traversal"),
        ),
      ).toEqual([]);
    });

    it("does not flag require() with a string literal", () => {
      expect(
        scan(`const fs = require("node:fs");`, "javascript").filter((r) =>
          r.startsWith("path-traversal"),
        ),
      ).toEqual([]);
    });

    it("does not flag open() with a literal path", () => {
      expect(
        scan(`open("/etc/known", "r")`, "python").filter((r) => r.startsWith("path-traversal")),
      ).toEqual([]);
    });

    it("does not flag send_from_directory with validated name", () => {
      expect(
        scan(`return send_from_directory(UPLOAD_DIR, safe_name)`, "python").filter((r) =>
          r.startsWith("path-traversal"),
        ),
      ).toEqual([]);
    });
  });

  describe("Go positives", () => {
    it("flags os.ReadFile with filepath.Join", () => {
      expect(scan(`data, err := os.ReadFile(filepath.Join(base, name))`, "go")).toContain(
        "path-traversal-os-join-go",
      );
    });

    it("flags os.Open with fmt.Sprintf", () => {
      expect(scan(`f, err := os.Open(fmt.Sprintf("/data/%s", name))`, "go")).toContain(
        "path-traversal-os-join-go",
      );
    });

    it("flags os.ReadFile with string concatenation", () => {
      expect(scan(`data, err := os.ReadFile("/uploads/" + name)`, "go")).toContain(
        "path-traversal-fs-concat-go",
      );
    });
  });

  describe("Go negatives", () => {
    it("does not flag os.ReadFile with a static path", () => {
      expect(
        scan(`data, err := os.ReadFile("/etc/config.toml")`, "go").filter((r) =>
          r.startsWith("path-traversal"),
        ),
      ).toEqual([]);
    });
  });

  describe("Rust positives", () => {
    it("flags File::open with format!", () => {
      expect(scan(`let f = File::open(format!("/data/{}", name))?;`, "rust")).toContain(
        "path-traversal-fs-format-rust",
      );
    });

    it("flags fs::read_to_string with a variable path", () => {
      expect(scan(`let s = fs::read_to_string(path)?;`, "rust")).toContain(
        "path-traversal-fs-variable-rust",
      );
    });

    it("flags PathBuf::from with format!", () => {
      expect(scan(`let p = PathBuf::from(format!("uploads/{name}"));`, "rust")).toContain(
        "path-traversal-fs-format-rust",
      );
    });
  });

  describe("Rust negatives", () => {
    it("does not flag File::open with a static path", () => {
      expect(
        scan(`let f = File::open("/etc/config.toml")?;`, "rust").filter((r) =>
          r.startsWith("path-traversal"),
        ),
      ).toEqual([]);
    });
  });
});
