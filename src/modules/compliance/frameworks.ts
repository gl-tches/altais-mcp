// Compliance-framework knowledge-base loader.
//
// Loads `data/compliance-frameworks.json` — a map of framework id to a
// framework descriptor with a list of controls. Each control carries the
// CWE IDs and lowercase keywords that indicate a finding relates to it.

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The 16 frameworks bundled with altais-mcp. */
export const FRAMEWORK_IDS = [
  "owasp-asvs",
  "owasp-samm",
  "owasp-dsomm",
  "nist-800-53",
  "nist-ssdf",
  "nist-ai-rmf",
  "iso-27001",
  "soc2",
  "gdpr",
  "pci-dss",
  "nis2",
  "dora",
  "cra",
  "cisa-sbd",
  "eo-14028",
  "fda-524b",
] as const;

export type FrameworkId = (typeof FRAMEWORK_IDS)[number];

export interface ComplianceControl {
  readonly id: string;
  readonly title: string;
  readonly family: string;
  readonly description: string;
  readonly cwes: readonly string[];
  readonly keywords: readonly string[];
}

export interface ComplianceFramework {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly controls: readonly ComplianceControl[];
}

/** A reference URL for each framework, used on emitted findings. */
export const FRAMEWORK_REFERENCES: Readonly<Record<FrameworkId, string>> = {
  "owasp-asvs": "https://owasp.org/www-project-application-security-verification-standard/",
  "owasp-samm": "https://owasp.org/www-project-samm/",
  "owasp-dsomm": "https://owasp.org/www-project-devsecops-maturity-model/",
  "nist-800-53": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
  "nist-ssdf": "https://csrc.nist.gov/pubs/sp/800/218/final",
  "nist-ai-rmf": "https://www.nist.gov/itl/ai-risk-management-framework",
  "iso-27001": "https://www.iso.org/standard/27001",
  soc2: "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
  gdpr: "https://gdpr.eu/",
  "pci-dss": "https://www.pcisecuritystandards.org/document_library/",
  nis2: "https://digital-strategy.ec.europa.eu/en/policies/nis2-directive",
  dora: "https://www.digital-operational-resilience-act.com/",
  cra: "https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act",
  "cisa-sbd": "https://www.cisa.gov/securebydesign",
  "eo-14028": "https://www.cisa.gov/executive-order-improving-nations-cybersecurity",
  "fda-524b": "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity",
};

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * Locate the bundled `data/` directory. Works whether the package is run
 * from `dist/modules/compliance/` (compiled) or `src/modules/compliance/`
 * (ts-node). The data files ship at the package root under `data/`.
 */
function defaultDataDir(): string {
  return path.resolve(HERE, "..", "..", "..", "data");
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

function isControl(value: unknown): value is ComplianceControl {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "string" &&
    typeof v.title === "string" &&
    typeof v.family === "string" &&
    typeof v.description === "string" &&
    isStringArray(v.cwes) &&
    isStringArray(v.keywords)
  );
}

function isFramework(value: unknown): value is ComplianceFramework {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "string" &&
    typeof v.name === "string" &&
    typeof v.version === "string" &&
    Array.isArray(v.controls) &&
    v.controls.every(isControl)
  );
}

/**
 * Typed, in-memory view over the bundled compliance frameworks. Provides
 * lookup by framework id and by control id within a framework.
 */
export class FrameworkRegistry {
  private readonly byId = new Map<string, ComplianceFramework>();

  constructor(frameworks: readonly ComplianceFramework[]) {
    for (const fw of frameworks) {
      this.byId.set(fw.id, fw);
    }
  }

  static async load(dataDir: string = defaultDataDir()): Promise<FrameworkRegistry> {
    const file = path.join(dataDir, "compliance-frameworks.json");
    const raw = await readFile(file, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(`Compliance frameworks file is not an object: ${file}`);
    }
    const frameworks: ComplianceFramework[] = [];
    for (const value of Object.values(parsed as Record<string, unknown>)) {
      if (!isFramework(value)) {
        throw new Error(`Malformed compliance framework entry in ${file}`);
      }
      frameworks.push(value);
    }
    return new FrameworkRegistry(frameworks);
  }

  get(id: string): ComplianceFramework | undefined {
    return this.byId.get(id);
  }

  has(id: string): boolean {
    return this.byId.has(id);
  }

  ids(): readonly string[] {
    return Array.from(this.byId.keys()).sort();
  }

  size(): number {
    return this.byId.size;
  }

  control(frameworkId: string, controlId: string): ComplianceControl | undefined {
    const fw = this.byId.get(frameworkId);
    if (fw === undefined) return undefined;
    return fw.controls.find((c) => c.id === controlId);
  }
}
