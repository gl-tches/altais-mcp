import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { SSRF_PATTERNS } from "./ssrf.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(SSRF_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("SSRF patterns", () => {
  describe("positives", () => {
    it("flags fetch(req.body.url)", () => {
      expect(scan(`await fetch(req.body.url);`, "javascript")).toContain("ssrf-fetch-request-data");
    });

    it("flags axios.get(req.query.target)", () => {
      expect(scan(`axios.get(req.query.target);`, "javascript")).toContain(
        "ssrf-axios-request-data",
      );
    });

    it("flags http.get with variable URL", () => {
      expect(scan(`http.get(target);`, "javascript")).toContain("ssrf-http-get-variable");
    });

    it("flags Python requests.get with request.args", () => {
      expect(scan(`requests.get(request.args["url"])`, "python")).toContain("ssrf-requests-py");
    });

    it("flags Python urllib.urlopen with variable", () => {
      expect(scan(`urllib.request.urlopen(target)`, "python")).toContain("ssrf-urllib-variable-py");
    });

    it("flags Python httpx with framework request", () => {
      expect(scan(`httpx.get(request.json["url"])`, "python")).toContain(
        "ssrf-httpx-request-data-py",
      );
    });
  });

  describe("negatives", () => {
    it("does not flag fetch with literal URL", () => {
      expect(
        scan(`await fetch("https://api.example.com/v1");`, "javascript").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });

    it("does not flag axios with literal URL", () => {
      expect(
        scan(`axios.get("https://api.example.com/v1");`, "javascript").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });

    it("does not flag http.get with literal URL", () => {
      expect(
        scan(`http.get("https://api.example.com/v1");`, "javascript").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });

    it("does not flag requests.get with literal URL", () => {
      expect(
        scan(`requests.get("https://api.example.com/v1")`, "python").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });

    it("does not flag urlopen with literal URL", () => {
      expect(
        scan(`urllib.request.urlopen("https://api.example.com/v1")`, "python").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });
  });

  describe("Go positives", () => {
    it("flags http.Get with a variable URL", () => {
      expect(scan(`resp, err := http.Get(target)`, "go")).toContain("ssrf-net-http-variable-go");
    });

    it("flags http.NewRequest with a variable URL", () => {
      expect(scan(`req, _ := http.NewRequest("GET", userURL, nil)`, "go")).toContain(
        "ssrf-net-http-variable-go",
      );
    });

    it("flags client.Post with a fmt.Sprintf URL", () => {
      expect(
        scan(
          `resp, err := client.Post(fmt.Sprintf("%s/api", base), "application/json", body)`,
          "go",
        ),
      ).toContain("ssrf-net-http-sprintf-go");
    });
  });

  describe("Go negatives", () => {
    it("does not flag http.Get with a literal URL", () => {
      expect(
        scan(`resp, err := http.Get("https://api.example.com/v1")`, "go").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });
  });

  describe("Rust positives", () => {
    it("flags reqwest::get with a variable URL", () => {
      expect(scan(`let body = reqwest::get(target).await?.text().await?;`, "rust")).toContain(
        "ssrf-reqwest-variable-rust",
      );
    });

    it("flags reqwest Client get with a format! URL", () => {
      expect(
        scan(
          `let resp = reqwest::Client::new().get(format!("{}/api", base)).send().await?;`,
          "rust",
        ),
      ).toContain("ssrf-reqwest-variable-rust");
    });

    it("flags ureq::get with a variable URL", () => {
      expect(scan(`let resp = ureq::get(target).call()?;`, "rust")).toContain(
        "ssrf-ureq-variable-rust",
      );
    });
  });

  describe("Rust negatives", () => {
    it("does not flag reqwest::get with a literal URL", () => {
      expect(
        scan(`let body = reqwest::get("https://api.example.com/v1").await?;`, "rust").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });

    it("does not flag ureq::get with a literal URL", () => {
      expect(
        scan(`let resp = ureq::get("https://api.example.com/v1").call()?;`, "rust").filter((r) =>
          r.startsWith("ssrf-"),
        ),
      ).toEqual([]);
    });
  });
});
