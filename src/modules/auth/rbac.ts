// RBAC / ABAC policy auditor.
//
// Accepts a structured policy: roles with allowed actions (per-resource
// or wildcard), plus optional assignments and inheritance. Looks for
// wildcards on dangerous actions, default-allow patterns, and self-elevation
// (a role that can grant itself other roles).

import type { Finding } from "../../core/types.js";
import { buildAuthFinding } from "./finding.js";

export interface RbacAction {
  readonly resource: string;
  readonly action: string;
}

export interface RbacRole {
  readonly name: string;
  readonly description?: string;
  readonly inherits?: readonly string[];
  readonly permissions: readonly (string | RbacAction)[];
}

export interface RbacPolicy {
  readonly model?: "rbac" | "abac" | "rebac";
  readonly default?: "allow" | "deny";
  readonly roles: readonly RbacRole[];
  readonly assignments?: readonly { readonly user: string; readonly role: string }[];
}

export interface RbacAuditInput {
  readonly policy: RbacPolicy;
  readonly filename?: string;
}

const REFS = [
  "https://owasp.org/www-project-cheat-sheets/cheatsheets/Authorization_Cheat_Sheet.html",
];

const DANGEROUS_ACTIONS = new Set([
  "delete",
  "destroy",
  "drop",
  "wipe",
  "purge",
  "grant",
  "assume",
  "impersonate",
  "rotate",
  "exfiltrate",
  "*",
  "admin",
]);

export function auditRbac(input: RbacAuditInput): readonly Finding[] {
  const findings: Finding[] = [];
  const policy = input.policy;
  const source = input.filename;

  if (policy.default === "allow") {
    findings.push(
      buildAuthFinding(
        {
          rule: "rbac-default-allow",
          severity: "critical",
          title: "Policy default is `allow`",
          description:
            "Default-allow policies grant access to every action that isn't explicitly denied. The reverse — default-deny — is the safer baseline.",
          remediation:
            "Switch the default to `deny`. Use explicit allows for every permitted action.",
          cwe: ["CWE-284", "CWE-285"],
          references: REFS,
          evidence: "policy.default=allow",
          tags: ["rbac"],
        },
        source,
      ),
    );
  }

  const roleByName = new Map<string, RbacRole>();
  for (const r of policy.roles) roleByName.set(r.name, r);

  for (const role of policy.roles) {
    for (const perm of role.permissions) {
      const resource = typeof perm === "string" ? splitPerm(perm).resource : perm.resource;
      const action = typeof perm === "string" ? splitPerm(perm).action : perm.action;

      if (resource === "*" && action === "*") {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-superuser",
              severity: "high",
              title: `Role \`${role.name}\` grants \`*\` on \`*\``,
              description:
                "A role with universal permissions is a superuser. Reserve for break-glass; review every assignment.",
              remediation:
                "Replace `*` with the specific resources/actions the role actually needs.",
              cwe: ["CWE-269"],
              references: REFS,
              evidence: `${role.name}: ${resource}.${action}`,
              tags: ["rbac"],
            },
            source,
          ),
        );
        continue;
      }
      if (action === "*" && DANGEROUS_ACTIONS.has(resource.toLowerCase())) {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-wildcard-on-dangerous-resource",
              severity: "high",
              title: `Role \`${role.name}\` grants \`*\` on dangerous resource \`${resource}\``,
              description:
                "Wildcards on resources tied to destructive or privilege-related actions deserve closer scrutiny.",
              remediation: "Enumerate specific actions (read, list, ...) instead of `*`.",
              cwe: ["CWE-269"],
              references: REFS,
              evidence: `${role.name}: ${resource}.${action}`,
              tags: ["rbac"],
            },
            source,
          ),
        );
      } else if (action === "*") {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-wildcard-action",
              severity: "medium",
              title: `Role \`${role.name}\` grants every action on \`${resource}\``,
              description:
                "Wildcard actions hide which operations the role is actually used for. Auditors cannot tell intent from policy.",
              remediation: "List specific actions (read, write, delete, ...).",
              cwe: ["CWE-285"],
              references: REFS,
              evidence: `${role.name}: ${resource}.${action}`,
              tags: ["rbac"],
            },
            source,
          ),
        );
      }
      if (resource.toLowerCase() === "roles" && /grant|assign|create|update|delete/i.test(action)) {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-self-elevation",
              severity: "high",
              title: `Role \`${role.name}\` can mutate roles — possible self-elevation`,
              description: "A role that can grant or modify roles can promote itself.",
              remediation:
                "Constrain role-management actions to a dedicated, restricted administrative role. Require two-party approval for role grants.",
              cwe: ["CWE-269"],
              references: REFS,
              evidence: `${role.name}: ${resource}.${action}`,
              tags: ["rbac"],
            },
            source,
          ),
        );
      }
    }
    for (const parent of role.inherits ?? []) {
      if (!roleByName.has(parent)) {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-unknown-parent",
              severity: "low",
              title: `Role \`${role.name}\` inherits from unknown role \`${parent}\``,
              description:
                "Dangling inheritance suggests the policy is out of sync with the implementation.",
              remediation: "Remove the inheritance or define the parent role.",
              cwe: ["CWE-693"],
              references: REFS,
              evidence: `${role.name} -> ${parent}`,
              tags: ["rbac"],
            },
            source,
          ),
        );
      }
    }
  }

  // Detect inheritance cycles.
  for (const role of policy.roles) {
    const seen = new Set<string>();
    const stack = [...(role.inherits ?? [])];
    while (stack.length > 0) {
      const next = stack.pop();
      if (next === undefined) break;
      if (next === role.name) {
        findings.push(
          buildAuthFinding(
            {
              rule: "rbac-inheritance-cycle",
              severity: "medium",
              title: `Inheritance cycle starting at \`${role.name}\``,
              description:
                "Cyclic inheritance produces undefined effective permissions, depending on traversal order.",
              remediation: "Flatten the inheritance graph; eliminate cycles.",
              cwe: ["CWE-693"],
              references: REFS,
              evidence: role.name,
              tags: ["rbac"],
            },
            source,
          ),
        );
        break;
      }
      if (seen.has(next)) continue;
      seen.add(next);
      const r = roleByName.get(next);
      if (r) stack.push(...(r.inherits ?? []));
    }
  }
  return findings;
}

function splitPerm(p: string): { resource: string; action: string } {
  const idx = p.indexOf(":");
  if (idx < 0) return { resource: p, action: "*" };
  return { resource: p.slice(0, idx), action: p.slice(idx + 1) };
}
