import { describe, expect, it } from "vitest";
import { runPatterns } from "../engine.js";
import type { Language } from "../languages.js";
import { XSS_PATTERNS } from "./xss.js";

function scan(source: string, language: Language): readonly string[] {
  return runPatterns(XSS_PATTERNS, { source, language }).map((f) => f.rule);
}

describe("XSS patterns - DOM sinks", () => {
  describe("positives", () => {
    it("flags innerHTML assignment from a variable", () => {
      expect(scan(`el.innerHTML = userComment;`, "javascript")).toContain("xss-dom-innerhtml");
    });

    it("flags outerHTML assignment", () => {
      expect(scan(`node.outerHTML = data;`, "typescript")).toContain("xss-dom-innerhtml");
    });

    it("flags document.write", () => {
      expect(scan(`document.write("<h1>" + title + "</h1>");`, "javascript")).toContain(
        "xss-document-write",
      );
    });

    it("flags eval()", () => {
      expect(scan(`eval(userInput);`, "javascript")).toContain("xss-eval");
    });

    it("flags new Function(code)", () => {
      expect(scan(`const f = new Function(body);`, "javascript")).toContain("xss-eval");
    });

    it("flags setTimeout with string arg", () => {
      expect(scan(`setTimeout("doStuff()", 100);`, "javascript")).toContain(
        "xss-settimeout-string",
      );
    });

    it("flags React dangerouslySetInnerHTML", () => {
      expect(scan(`<div dangerouslySetInnerHTML={{__html: payload}} />`, "javascript")).toContain(
        "xss-react-dangerously-set-inner-html",
      );
    });

    it("flags jQuery .html with variable", () => {
      expect(scan(`$('#x').html(payload);`, "javascript")).toContain("xss-jquery-html");
    });
  });

  describe("negatives", () => {
    it("does not flag textContent assignment", () => {
      expect(
        scan(`el.textContent = userComment;`, "javascript").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });

    it("does not flag a method named Function on a class", () => {
      expect(
        scan(`class C { Function() {} } new C().Function();`, "javascript").filter((r) =>
          r.startsWith("xss-"),
        ),
      ).toEqual([]);
    });

    it("does not flag a method named eval on an object", () => {
      // The lookbehind prevents `obj.eval(...)` from matching the `eval` rule.
      expect(
        scan(`evaluator.eval(expr);`, "javascript").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });

    it("does not flag setTimeout with function arg", () => {
      expect(
        scan(`setTimeout(() => doStuff(), 100);`, "javascript").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });

    it("does not flag eval inside a comment", () => {
      expect(
        scan(`// eval(x) used to be here\nconst y = 1;`, "javascript").filter((r) =>
          r.startsWith("xss-"),
        ),
      ).toEqual([]);
    });
  });
});

describe("XSS patterns - server-side", () => {
  describe("positives", () => {
    it("flags res.send with HTML concat", () => {
      expect(scan(`res.send("<h1>" + name + "</h1>");`, "javascript")).toContain(
        "xss-server-html-concat-js",
      );
    });

    it("flags Django mark_safe with variable", () => {
      expect(scan(`return mark_safe(user_html)`, "python")).toContain("xss-django-mark-safe");
    });

    it("flags Python HTML f-string", () => {
      expect(scan(`return f"<div>{user_input}</div>"`, "python")).toContain("xss-fstring-html-py");
    });
  });

  describe("negatives", () => {
    it("does not flag res.send with sanitized variable", () => {
      expect(scan(`res.send(template);`, "javascript").filter((r) => r.startsWith("xss-"))).toEqual(
        [],
      );
    });

    it("does not flag mark_safe with literal", () => {
      expect(
        scan(`return mark_safe("hello")`, "python").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });

    it("does not flag plain f-string without HTML", () => {
      expect(scan(`return f"Hello {name}"`, "python").filter((r) => r.startsWith("xss-"))).toEqual(
        [],
      );
    });
  });
});

describe("XSS patterns - Go", () => {
  describe("positives", () => {
    it("flags template.HTML cast on a variable", () => {
      expect(scan(`out := template.HTML(userInput)`, "go")).toContain("xss-go-template-html-cast");
    });

    it("flags template.JS cast on a variable", () => {
      expect(scan(`s := template.JS(payload)`, "go")).toContain("xss-go-template-html-cast");
    });

    it("flags fmt.Fprintf building an HTML response", () => {
      expect(scan(`fmt.Fprintf(w, "<div>%s</div>", name)`, "go")).toContain("xss-go-fprintf-html");
    });
  });

  describe("negatives", () => {
    it("does not flag template.HTML on a string literal", () => {
      expect(
        scan(`out := template.HTML("<b>static</b>")`, "go").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });

    it("does not flag fmt.Sprintf without HTML tags", () => {
      expect(
        scan(`msg := fmt.Sprintf("hello %s", name)`, "go").filter((r) => r.startsWith("xss-")),
      ).toEqual([]);
    });
  });
});
