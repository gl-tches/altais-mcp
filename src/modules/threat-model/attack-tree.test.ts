import { describe, expect, it } from "vitest";
import type { AttackNode } from "./attack-tree.js";
import { generateAttackTree } from "./attack-tree.js";

describe("generateAttackTree", () => {
  it("matches account takeover keywords", () => {
    const r = generateAttackTree({ goal: "Take over an admin account" });
    expect(r.matched_template).toBe("account-takeover");
    expect(r.root.children?.length).toBeGreaterThan(0);
  });

  it("matches data exfiltration", () => {
    const r = generateAttackTree({ goal: "Exfiltrate customer data" });
    expect(r.matched_template).toBe("data-exfiltration");
  });

  it("matches remote code execution", () => {
    const r = generateAttackTree({ goal: "Achieve RCE on the API server" });
    expect(r.matched_template).toBe("remote-code-execution");
  });

  it("matches privilege escalation", () => {
    const r = generateAttackTree({ goal: "Escalate privileges from user to admin" });
    expect(r.matched_template).toBe("privilege-escalation");
  });

  it("matches denial of service", () => {
    const r = generateAttackTree({ goal: "Cause a denial of service" });
    expect(r.matched_template).toBe("denial-of-service");
  });

  it("matches supply chain", () => {
    const r = generateAttackTree({ goal: "Compromise the build supply chain" });
    expect(r.matched_template).toBe("supply-chain");
  });

  it("falls back to generic for unknown goals", () => {
    const r = generateAttackTree({ goal: "Win the bug bounty leaderboard" });
    expect(r.matched_template).toBe("generic");
    expect(r.notes.length).toBeGreaterThan(0);
  });

  it("includes CWE and mitigations on leaf nodes", () => {
    const r = generateAttackTree({ goal: "RCE via dependency" });
    const leaves = collectLeaves(r.root);
    expect(leaves.length).toBeGreaterThan(0);
    expect(leaves.every((l) => (l.cwe?.length ?? 0) > 0)).toBe(true);
    expect(leaves.every((l) => (l.mitigations?.length ?? 0) > 0)).toBe(true);
  });
});

function collectLeaves(node: AttackNode): {
  cwe?: readonly string[];
  mitigations?: readonly string[];
}[] {
  if (node.type === "leaf") return [{ cwe: node.cwe, mitigations: node.mitigations }];
  return (node.children ?? []).flatMap(collectLeaves);
}
