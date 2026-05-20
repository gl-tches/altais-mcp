import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { SSTI_PATTERNS } from "./ssti.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(SSTI_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("ssti patterns", () => {
  it("has unique pattern ids", () => {
    const ids = SSTI_PATTERNS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  describe("positives", () => {
    it("flags Handlebars.compile with a variable", () => {
      const rules = scan(`const tpl = Handlebars.compile(userTemplate);`, "javascript");
      expect(rules).toContain("ssti-handlebars-compile-nonliteral-js");
    });

    it("flags ejs.render with a variable", () => {
      const rules = scan(`ejs.render(req.body.template, data);`, "javascript");
      expect(rules).toContain("ssti-ejs-render-nonliteral-js");
    });

    it("flags ejs.compile with a variable", () => {
      const rules = scan(`const fn = ejs.compile(tplString);`, "typescript");
      expect(rules).toContain("ssti-ejs-render-nonliteral-js");
    });

    it("flags pug.compile with a variable", () => {
      const rules = scan(`pug.compile(source);`, "javascript");
      expect(rules).toContain("ssti-pug-lodash-template-nonliteral-js");
    });

    it("flags _.template with a variable", () => {
      const rules = scan(`const compiled = _.template(userInput);`, "javascript");
      expect(rules).toContain("ssti-pug-lodash-template-nonliteral-js");
    });

    it("flags nunjucks.renderString with a variable", () => {
      const rules = scan(`nunjucks.renderString(tpl, ctx);`, "javascript");
      expect(rules).toContain("ssti-nunjucks-renderstring-nonliteral-js");
    });

    it("flags Jinja render_template_string with a variable (Python)", () => {
      const rules = scan(`render_template_string(user_template)`, "python");
      expect(rules).toContain("ssti-jinja-template-string-py");
    });

    it("flags Jinja Environment.from_string with a variable (Python)", () => {
      const rules = scan(`tpl = env.from_string(raw_template)`, "python");
      expect(rules).toContain("ssti-jinja-template-string-py");
    });

    it("flags Go text/template Parse with a variable", () => {
      const rules = scan(`t, err := template.New("x").Parse(userTpl)`, "go");
      expect(rules).toContain("ssti-go-template-parse-nonliteral");
    });
  });

  describe("negatives", () => {
    it("does not flag Handlebars.compile of a literal template", () => {
      const rules = scan("Handlebars.compile(`<p>{{name}}</p>`);", "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag ejs.render of a string literal", () => {
      const rules = scan(`ejs.render("<p><%= name %></p>", data);`, "javascript");
      expect(rules).toEqual([]);
    });

    it("does not flag Jinja Template of a string literal (Python)", () => {
      const rules = scan(`tpl = Template("Hello {{ name }}")`, "python");
      expect(rules).toEqual([]);
    });

    it("does not flag Go Parse of a string constant", () => {
      const rules = scan(`t, err := template.New("x").Parse("Hello {{.Name}}")`, "go");
      expect(rules).toEqual([]);
    });
  });
});
