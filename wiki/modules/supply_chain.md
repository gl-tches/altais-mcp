# `supply_chain` module

The `supply_chain` module audits software supply-chain risk end to end. It parses lockfiles (npm, cargo, poetry, go) for known vulnerabilities, generates SBOM and VEX artifacts, classifies dependency licenses, detects typosquatting and dependency-confusion exposure, structurally verifies SLSA provenance and cosign / GPG signatures, and audits CI/CD pipeline and package-registry configuration. Lockfile-based tools share a common input shape — `content`, optional `kind`, and optional `filename` for kind detection. Auditor tools append findings to the shared session report; the two generators return their artifacts directly.

| Property | Value |
|----------|-------|
| Module name | `supply_chain` |
| Status | Default-enabled |
| Config key | `[modules] supply_chain` in `altais.config.toml` |
| Tools | 10 |

## Tools

| Tool | Description |
|------|-------------|
| [`altais_audit_deps`](../tools/altais_audit_deps.md) | Parses a lockfile and matches every dependency against the bundled OSV vulnerability snapshot. |
| [`altais_generate_sbom`](../tools/altais_generate_sbom.md) | Emits a CycloneDX 1.5 or SPDX 2.3 software bill of materials from a lockfile. |
| [`altais_check_licenses`](../tools/altais_check_licenses.md) | Classifies each dependency's license against allow / warn / deny lists. |
| [`altais_detect_typosquat`](../tools/altais_detect_typosquat.md) | Flags dependency names within edit-distance 1–2 of a popular package in the same ecosystem. |
| [`altais_verify_slsa`](../tools/altais_verify_slsa.md) | Structurally verifies a SLSA provenance attestation (DSSE envelope or in-toto Statement). |
| [`altais_verify_signatures`](../tools/altais_verify_signatures.md) | Classifies and inspects cosign or GPG signature metadata. |
| [`altais_check_dependency_confusion`](../tools/altais_check_dependency_confusion.md) | Flags packages matching an internal name pattern but resolved from a public registry. |
| [`altais_generate_vex`](../tools/altais_generate_vex.md) | Emits an OpenVEX 0.2.0 or CycloneDX 1.5 VEX document from a list of statements. |
| [`altais_check_build_integrity`](../tools/altais_check_build_integrity.md) | Pattern-based audit of CI/CD configuration for build-tampering vectors. |
| [`altais_audit_registry`](../tools/altais_audit_registry.md) | Checks a package-registry configuration file for HTTP registries, plaintext tokens, and disabled TLS. |

## Enabling this module

Both `auth` and `supply_chain` are default-enabled (on out of the box); they can be turned off by setting the key to `false` under `[modules]` in `altais.config.toml`.

```toml
[modules]
supply_chain = false   # disable the supply_chain module
```

## See also

- [Wiki home](../Home.md)
