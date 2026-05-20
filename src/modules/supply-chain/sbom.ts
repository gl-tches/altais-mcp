// SBOM generators: CycloneDX 1.5 JSON + SPDX 2.3 JSON.

import { randomUUID } from "node:crypto";
import type { DependencyPackage, LockfileParseResult } from "./types.js";

export type SbomFormat = "cyclonedx" | "spdx";

export interface SbomOptions {
  readonly format: SbomFormat;
  readonly project_name?: string;
  readonly project_version?: string;
  readonly tool_name?: string;
  readonly tool_version?: string;
}

const DEFAULT_TOOL_NAME = "altais-mcp";
const DEFAULT_TOOL_VERSION = "0.2.0";

export function generateSbom(
  parsed: LockfileParseResult,
  options: SbomOptions,
): { readonly format: SbomFormat; readonly document: unknown } {
  if (options.format === "cyclonedx") {
    return { format: "cyclonedx", document: cyclonedx(parsed, options) };
  }
  return { format: "spdx", document: spdx(parsed, options) };
}

function cyclonedx(parsed: LockfileParseResult, options: SbomOptions): unknown {
  const components = parsed.packages.map((p) => cyclonedxComponent(p));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: "altais",
          name: options.tool_name ?? DEFAULT_TOOL_NAME,
          version: options.tool_version ?? DEFAULT_TOOL_VERSION,
        },
      ],
      component: {
        type: "application",
        name: options.project_name ?? "unknown",
        version: options.project_version ?? "0.0.0",
      },
    },
    components,
  };
}

function cyclonedxComponent(pkg: DependencyPackage): unknown {
  return {
    type: "library",
    name: pkg.name,
    version: pkg.version,
    purl: pkg.purl,
    ...(pkg.license !== undefined ? { licenses: [{ license: { id: pkg.license } }] } : {}),
    ...(pkg.integrity !== undefined ? { hashes: parseHash(pkg.integrity) } : {}),
    scope: pkg.dev === true ? "optional" : "required",
  };
}

function parseHash(integrity: string): readonly { alg: string; content: string }[] {
  // npm-style "sha512-base64..." or "sha256:hex" or "h1:base64="
  const m1 = /^(sha\d+)[:-](.+?)=*$/i.exec(integrity);
  if (m1?.[1] && m1[2]) return [{ alg: m1[1].toUpperCase(), content: m1[2] }];
  return [{ alg: "SHA-256", content: integrity }];
}

function spdx(parsed: LockfileParseResult, options: SbomOptions): unknown {
  const ts = new Date().toISOString();
  const documentNamespace = `https://altais-mcp.example/sbom/${parsed.ecosystem}/${randomUUID()}`;
  const packages = parsed.packages.map((p, idx) => ({
    SPDXID: `SPDXRef-Package-${idx + 1}`,
    name: p.name,
    versionInfo: p.version,
    downloadLocation: p.source ?? "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: p.license ?? "NOASSERTION",
    licenseDeclared: p.license ?? "NOASSERTION",
    externalRefs: p.purl
      ? [
          {
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: p.purl,
          },
        ]
      : [],
    ...(p.integrity !== undefined ? { checksums: spdxChecksums(p.integrity) } : {}),
  }));
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: options.project_name ?? `${parsed.ecosystem}-bom`,
    documentNamespace,
    creationInfo: {
      created: ts,
      creators: [
        `Tool: ${options.tool_name ?? DEFAULT_TOOL_NAME}-${options.tool_version ?? DEFAULT_TOOL_VERSION}`,
      ],
    },
    packages,
    relationships: packages.map((pkg) => ({
      spdxElementId: "SPDXRef-DOCUMENT",
      relatedSpdxElement: pkg.SPDXID,
      relationshipType: "DESCRIBES",
    })),
  };
}

function spdxChecksums(integrity: string): readonly { algorithm: string; checksumValue: string }[] {
  const m = /^(sha\d+)[:-](.+?)=*$/i.exec(integrity);
  if (m?.[1] && m[2]) return [{ algorithm: m[1].toUpperCase(), checksumValue: m[2] }];
  return [{ algorithm: "SHA256", checksumValue: integrity }];
}
