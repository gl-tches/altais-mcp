// ASI05 — Code Execution auditor (altais_audit_code_execution).
//
// Agents that generate and run code are a direct RCE path. Unsandboxed
// execution, or a sandbox with network / filesystem access, turns model
// output into arbitrary code on the host.

import type { Finding } from "../../core/types.js";
import { buildAgenticFinding, lineAt } from "./finding.js";

export type SandboxType =
  | "none"
  | "process"
  | "container"
  | "microvm"
  | "wasm"
  | "gvisor"
  | "firecracker";

export interface CodeExecutionConfig {
  /** The agent executes code it (or a model) generated. */
  readonly executes_generated_code?: boolean;
  /** Generated code runs inside a sandbox. */
  readonly sandboxed?: boolean;
  /** The sandbox technology in use. */
  readonly sandbox_type?: SandboxType;
  /** Only an allowlist of operations / modules is permitted in the sandbox. */
  readonly allowlist_enforced?: boolean;
  /** The sandbox has network access. */
  readonly network_access_in_sandbox?: boolean;
  /** The sandbox has host filesystem access. */
  readonly filesystem_access_in_sandbox?: boolean;
  /** CPU / memory / time resource limits are enforced on the sandbox. */
  readonly resource_limits?: boolean;
}

export interface CodeExecutionAuditInput {
  readonly config?: CodeExecutionConfig;
  readonly source?: string;
  readonly filename?: string;
}

const REFS = [
  "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/",
  "https://owasp.org/www-community/attacks/Code_Injection",
  "https://cwe.mitre.org/data/definitions/94.html",
];

// A line that invokes a dynamic-execution sink AND mentions a model /
// LLM / completion output variable on the same line is a likely path
// from model output straight to code execution.
const EXEC_SINK_RE = /\b(?:eval|exec|Function|child_process|execSync|spawn|spawnSync|compile)\s*\(/;
const MODEL_VAR_RE = /\b(?:llm|model|completion|generated|response|output|ai_?|gpt|claude|agent)/i;

export function auditCodeExecution(input: CodeExecutionAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const file = input.filename;

  if (input.source !== undefined && input.source.length > 0) {
    findings.push(...scanSource(input.source, file));
  }

  const c = input.config;
  if (c !== undefined) {
    const executes = c.executes_generated_code === true;
    const sandboxType = c.sandbox_type;
    const unsandboxed = executes && (c.sandboxed === false || sandboxType === "none");

    if (unsandboxed) {
      findings.push(
        buildAgenticFinding(
          {
            rule: "code-exec-no-sandbox",
            severity: "critical",
            title: "ASI05: The agent executes generated code with no sandbox",
            description:
              "Running model-generated code directly on the host is remote code execution by design: any injected or hijacked instruction becomes arbitrary code with the process's privileges (ASI05 Code Execution).",
            remediation:
              "Execute generated code only inside a strong isolation boundary (microVM, gVisor, or a hardened container) with no host access.",
            cwe: ["CWE-94", "CWE-913"],
            references: REFS,
            evidence: `executes_generated_code=true, sandboxed=${String(c.sandboxed ?? sandboxType ?? "unset")}`,
            tags: ["ASI05", "code-execution"],
          },
          file,
        ),
      );
    }

    if (c.network_access_in_sandbox === true) {
      findings.push(
        buildAgenticFinding(
          {
            rule: "code-exec-sandbox-network-access",
            severity: "high",
            title: "ASI05: The code-execution sandbox has network access",
            description:
              "A sandbox with network egress lets executed code exfiltrate data, reach internal services, or pull a second-stage payload — undermining the isolation (ASI05 Code Execution).",
            remediation:
              "Disable network access in the sandbox by default; allow only an explicit egress allowlist when strictly required.",
            cwe: ["CWE-913", "CWE-94"],
            references: REFS,
            evidence: "network_access_in_sandbox=true",
            tags: ["ASI05", "code-execution"],
          },
          file,
        ),
      );
    }

    if (c.filesystem_access_in_sandbox === true) {
      findings.push(
        buildAgenticFinding(
          {
            rule: "code-exec-sandbox-filesystem-access",
            severity: "high",
            title: "ASI05: The code-execution sandbox has host filesystem access",
            description:
              "Host filesystem access from the sandbox lets executed code read secrets and source, or write a persistence payload, breaking the isolation boundary (ASI05 Code Execution).",
            remediation:
              "Give the sandbox only an ephemeral, isolated filesystem; mount no host paths.",
            cwe: ["CWE-913"],
            references: REFS,
            evidence: "filesystem_access_in_sandbox=true",
            tags: ["ASI05", "code-execution"],
          },
          file,
        ),
      );
    }

    if (executes && c.allowlist_enforced === false) {
      findings.push(
        buildAgenticFinding(
          {
            rule: "code-exec-no-allowlist",
            severity: "medium",
            title: "ASI05: No operation / module allowlist on executed code",
            description:
              "Without an allowlist of permitted operations and imports, executed code can reach dangerous APIs even inside a sandbox (ASI05 Code Execution).",
            remediation:
              "Restrict the execution environment to an allowlist of safe modules and operations; deny everything else.",
            cwe: ["CWE-94"],
            references: REFS,
            evidence: "allowlist_enforced=false",
            tags: ["ASI05", "code-execution"],
          },
          file,
        ),
      );
    }

    if (executes && c.resource_limits === false) {
      findings.push(
        buildAgenticFinding(
          {
            rule: "code-exec-no-resource-limits",
            severity: "medium",
            title: "ASI05: No resource limits on executed code",
            description:
              "Without CPU, memory, and wall-clock limits, generated code can exhaust host resources or run indefinitely, enabling denial of service (ASI05 Code Execution).",
            remediation:
              "Enforce strict CPU, memory, and timeout limits on every execution; kill runs that exceed them.",
            cwe: ["CWE-913", "CWE-400"],
            references: REFS,
            evidence: "resource_limits=false",
            tags: ["ASI05", "code-execution"],
          },
          file,
        ),
      );
    }
  }

  return findings;
}

function scanSource(source: string, file: string | undefined): readonly Finding[] {
  const findings: Finding[] = [];
  const lines = source.split("\n");
  let offset = 0;
  for (const line of lines) {
    const lineStart = offset;
    offset += line.length + 1;
    if (EXEC_SINK_RE.exec(line) === null) continue;
    if (MODEL_VAR_RE.exec(line) === null) continue;
    findings.push(
      buildAgenticFinding(
        {
          rule: "code-exec-model-output-to-sink",
          severity: "critical",
          title: "ASI05: Model output flows into a dynamic code-execution sink",
          description:
            "A dynamic-execution call (`eval` / `exec` / `Function` / `child_process`) on a line that also references a model / LLM output variable is a direct path from generated text to arbitrary code execution (ASI05 Code Execution).",
          remediation:
            "Never pass model output to an execution sink. If code must run, route it through a strongly isolated sandbox with allowlisting and no host access.",
          cwe: ["CWE-94", "CWE-913"],
          references: REFS,
          evidence: line.trim().slice(0, 200),
          tags: ["ASI05", "code-execution"],
          line: lineAt(source, lineStart),
        },
        file,
      ),
    );
  }
  return findings;
}
