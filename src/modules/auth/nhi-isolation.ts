// NHI isolation auditor — environment / namespace / boundary separation.

import type { Finding } from "../../core/types.js";
import { buildAuthFinding } from "./finding.js";

export interface NhiIsolationIdentity {
  readonly name: string;
  readonly environment?: string;
  readonly namespace?: string;
  readonly project?: string;
  readonly scopes?: readonly string[];
  readonly cross_environment_access?: readonly string[];
}

export interface NhiIsolationInput {
  readonly identities: readonly NhiIsolationIdentity[];
  readonly filename?: string;
}

const REFS = ["https://owasp.org/www-project-non-human-identities-top-10/"];

const PROD_RE = /^(?:prod|production|prd|live)$/i;
const PREPROD_RE = /^(?:dev|stage|staging|test|qa|sandbox|preview)$/i;

function isProd(env: string | undefined): boolean {
  return env !== undefined && PROD_RE.test(env);
}

function isPreProd(env: string | undefined): boolean {
  return env !== undefined && PREPROD_RE.test(env);
}

export function checkNhiIsolation(input: NhiIsolationInput): readonly Finding[] {
  const findings: Finding[] = [];
  const byName = new Map<string, NhiIsolationIdentity[]>();
  for (const id of input.identities) {
    const arr = byName.get(id.name) ?? [];
    arr.push(id);
    byName.set(id.name, arr);
  }
  for (const [name, group] of byName) {
    const envs = new Set(group.map((i) => i.environment ?? "(unknown)"));
    const hasProd = group.some((g) => isProd(g.environment));
    const hasPreProd = group.some((g) => isPreProd(g.environment));
    if (envs.size > 1 && hasProd && hasPreProd && group.length === 1) {
      // a single identity is being used across both
      findings.push(
        buildAuthFinding(
          {
            rule: "nhi-shared-prod-preprod",
            severity: "high",
            title: `NHI \`${name}\` shared between prod and pre-prod`,
            description:
              "A single non-human identity used across prod and non-prod environments lets non-prod compromise reach prod.",
            remediation:
              "Mint one identity per environment. Restrict trust policy to the workload's own environment.",
            cwe: ["CWE-269", "CWE-501"],
            references: REFS,
            evidence: `${name} environments=${Array.from(envs).join(",")}`,
            tags: ["nhi", "isolation"],
          },
          input.filename,
        ),
      );
    }
  }

  for (const id of input.identities) {
    const cross = id.cross_environment_access ?? [];
    if (isPreProd(id.environment)) {
      const reaches = cross.filter(isProd);
      if (reaches.length > 0) {
        findings.push(
          buildAuthFinding(
            {
              rule: "nhi-preprod-reaches-prod",
              severity: "critical",
              title: `Pre-prod identity \`${id.name}\` can access prod`,
              description:
                "A credential that lives in a less-trusted environment but can reach production turns dev compromise into prod compromise.",
              remediation:
                "Remove the cross-environment grant. Issue a separate, scoped credential in prod when cross-env work is genuinely needed.",
              cwe: ["CWE-501"],
              references: REFS,
              evidence: `${id.name} cross_env=${reaches.join(",")}`,
              tags: ["nhi", "isolation"],
            },
            input.filename,
          ),
        );
      }
    }
    if (id.namespace === undefined && id.environment === undefined && id.project === undefined) {
      findings.push(
        buildAuthFinding(
          {
            rule: "nhi-no-boundary",
            severity: "medium",
            title: `NHI \`${id.name}\` has no environment / namespace / project boundary declared`,
            description: "Without a declared boundary, blast radius cannot be reasoned about.",
            remediation:
              "Annotate the identity with its environment, project, and (where applicable) namespace.",
            cwe: ["CWE-693"],
            references: REFS,
            evidence: id.name,
            tags: ["nhi", "isolation"],
          },
          input.filename,
        ),
      );
    }
    if ((id.scopes ?? []).some((s) => s === "*" || s.includes(":*"))) {
      findings.push(
        buildAuthFinding(
          {
            rule: "nhi-isolation-broad-scope",
            severity: "medium",
            title: `NHI \`${id.name}\` has wildcard scope`,
            description:
              "Broad scopes cross resource and tenant boundaries in cloud APIs. Even with environment separation, this widens blast radius.",
            remediation: "Replace wildcard scopes with explicit actions per resource.",
            cwe: ["CWE-269"],
            references: REFS,
            evidence: `${id.name} scopes=${(id.scopes ?? []).join(",")}`,
            tags: ["nhi", "isolation"],
          },
          input.filename,
        ),
      );
    }
  }
  return findings;
}
