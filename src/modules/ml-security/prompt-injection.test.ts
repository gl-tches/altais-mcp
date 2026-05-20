import { describe, expect, it } from "vitest";
import { auditPromptInjection } from "./prompt-injection.js";

const rules = (input: Parameters<typeof auditPromptInjection>[0]): string[] =>
  auditPromptInjection(input).map((f) => f.rule);

describe("auditPromptInjection — source patterns", () => {
  it("flags user input interpolated into an f-string prompt", () => {
    expect(rules({ source: 'prompt = f"Answer the question: {user_input}"' })).toContain(
      "prompt-injection-fstring-interpolation",
    );
  });

  it("flags user input interpolated into a template literal", () => {
    expect(rules({ source: "const prompt = `System: do X. ${userInput}`;" })).toContain(
      "prompt-injection-template-literal",
    );
  });

  it("flags user input concatenated onto a prompt with +", () => {
    expect(rules({ source: "full_prompt = system_prompt + user_message" })).toContain(
      "prompt-injection-string-concat",
    );
  });

  it("flags unsanitized tool output fed back into messages", () => {
    expect(rules({ source: "messages = tool_result + prompt" })).toContain(
      "prompt-injection-unsanitized-tool-output",
    );
  });

  it("does not flag a static prompt with no interpolation", () => {
    expect(rules({ source: 'prompt = "You are a helpful assistant."' })).toHaveLength(0);
  });
});

describe("auditPromptInjection — config", () => {
  it("flags missing instruction/data separation", () => {
    expect(rules({ config: { instruction_data_separation: false } })).toContain(
      "prompt-injection-no-instruction-separation",
    );
  });

  it("flags missing input filtering, output validation, and tool-output sanitization", () => {
    const r = rules({
      config: {
        input_filtering: false,
        output_validation: false,
        tool_output_sanitized: false,
      },
    });
    expect(r).toContain("prompt-injection-no-input-filtering");
    expect(r).toContain("prompt-injection-no-output-validation");
    expect(r).toContain("prompt-injection-unsanitized-tool-output-config");
  });

  it("returns no findings for a fully hardened prompt-handling config", () => {
    expect(
      auditPromptInjection({
        config: {
          instruction_data_separation: true,
          input_filtering: true,
          output_validation: true,
          tool_output_sanitized: true,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditPromptInjection — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = auditPromptInjection({ source: 'p = f"{user_input}"', filename: "agent.py" });
    const b = auditPromptInjection({ source: 'p = f"{user_input}"', filename: "agent.py" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditPromptInjection({
      source: 'p = f"{user_input}"',
      config: { input_filtering: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
