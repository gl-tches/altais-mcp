// Sigstore / cosign + GPG signature metadata inspection.
//
// We do not perform cryptographic verification (that requires a trust
// store and is out of scope for read-only static analysis). Instead we
// parse the structure and report on signer identity, algorithm, and
// whether key material looks well-formed.

import type { Finding } from "../../core/types.js";
import { findingId } from "../../core/utils.js";

export type SignatureKind = "cosign-bundle" | "cosign-signature" | "gpg" | "unknown";

export interface SignatureReport {
  readonly kind: SignatureKind;
  readonly findings: readonly Finding[];
  readonly metadata: Readonly<Record<string, string | undefined>>;
}

interface CosignBundle {
  readonly mediaType?: string;
  readonly verificationMaterial?: {
    readonly certificate?: { readonly rawBytes?: string };
    readonly tlogEntries?: readonly unknown[];
  };
  readonly messageSignature?: { readonly signature?: string; readonly messageDigest?: unknown };
  readonly dsseEnvelope?: unknown;
}

const PEM_BLOCK = /-----BEGIN (PGP SIGNATURE|PGP PUBLIC KEY BLOCK)-----[\s\S]*-----END \1-----/;

export function inspectSignature(input: string): SignatureReport {
  const trimmed = input.trim();
  if (PEM_BLOCK.test(trimmed)) return inspectGpg(trimmed);
  // Cosign bundle JSON?
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return inspectCosign(parsed);
  } catch {
    /* fall through */
  }
  return {
    kind: "unknown",
    findings: [
      buildFinding(
        "signature-unknown-format",
        "medium",
        "Unable to classify signature input",
        "Provide a cosign bundle (JSON), a raw cosign .sig payload, or an ASCII-armored GPG signature.",
        trimmed.slice(0, 64),
      ),
    ],
    metadata: {},
  };
}

function inspectCosign(parsed: unknown): SignatureReport {
  const bundle = parsed as CosignBundle;
  const findings: Finding[] = [];
  const metadata: Record<string, string | undefined> = {};

  if (bundle.mediaType !== undefined) {
    metadata.mediaType = bundle.mediaType;
  }
  const hasCertificate = bundle.verificationMaterial?.certificate?.rawBytes !== undefined;
  const hasTlog = (bundle.verificationMaterial?.tlogEntries?.length ?? 0) > 0;
  const hasSignature = bundle.messageSignature?.signature !== undefined;

  if (!hasCertificate) {
    findings.push(
      buildFinding(
        "cosign-no-certificate",
        "high",
        "Cosign bundle has no certificate",
        "Sign with a keyless workflow that publishes a Fulcio certificate, or include the verification certificate explicitly.",
        "",
      ),
    );
  } else {
    metadata.certificate_present = "true";
  }
  if (!hasTlog) {
    findings.push(
      buildFinding(
        "cosign-no-tlog",
        "high",
        "Cosign bundle has no transparency-log entry",
        "Publish the signature to a Rekor instance so verifiers can audit the signing event.",
        "",
      ),
    );
  } else {
    metadata.tlog_entries = String(bundle.verificationMaterial?.tlogEntries?.length ?? 0);
  }
  if (!hasSignature && bundle.dsseEnvelope === undefined) {
    findings.push(
      buildFinding(
        "cosign-no-signature",
        "critical",
        "Cosign bundle has neither messageSignature nor dsseEnvelope",
        "Re-sign the artifact. A bundle without signature payload is unverifiable.",
        "",
      ),
    );
  }
  return {
    kind: bundle.dsseEnvelope !== undefined ? "cosign-bundle" : "cosign-signature",
    findings,
    metadata,
  };
}

function inspectGpg(content: string): SignatureReport {
  const findings: Finding[] = [];
  const metadata: Record<string, string | undefined> = {};
  const isSignature = content.includes("-----BEGIN PGP SIGNATURE-----");
  const hashAlg = /^Hash:\s*(\S+)\s*$/m.exec(content)?.[1];
  if (hashAlg) metadata.hash = hashAlg;

  // Recognized weak hashes.
  if (hashAlg && /^(MD5|SHA1|RIPEMD160)$/i.test(hashAlg)) {
    findings.push(
      buildFinding(
        "gpg-weak-hash",
        "high",
        `GPG signature uses weak hash: ${hashAlg}`,
        "Re-sign with a SHA-256 or stronger digest. Update gpg.conf `personal-digest-preferences SHA512 SHA384 SHA256`.",
        hashAlg,
      ),
    );
  }
  if (isSignature) {
    metadata.kind = "signature";
  } else {
    metadata.kind = "public-key-block";
  }
  return { kind: "gpg", findings, metadata };
}

function buildFinding(
  rule: string,
  severity: Finding["severity"],
  title: string,
  remediation: string,
  evidence: string,
): Finding {
  return {
    id: findingId("supply_chain", rule, undefined, evidence),
    module: "supply_chain",
    rule,
    severity,
    cwe: ["CWE-345", "CWE-347"],
    title,
    description: title,
    ...(evidence ? { evidence } : {}),
    remediation,
    references: ["https://docs.sigstore.dev/cosign/overview"],
    tags: ["supply-chain", "signature"],
    status: "open",
  };
}
