import { describe, expect, it } from "vitest";
import { auditTerraform } from "./terraform.js";

const has = (content: string, rule: string): boolean =>
  auditTerraform({ content }).some((f) => f.rule === rule);

describe("auditTerraform — network exposure", () => {
  it("flags SSH open to 0.0.0.0/0 as critical", () => {
    const c = [
      'resource "aws_security_group" "web" {',
      "  ingress {",
      "    from_port   = 22",
      "    to_port     = 22",
      '    cidr_blocks = ["0.0.0.0/0"]',
      "  }",
      "}",
    ].join("\n");
    const findings = auditTerraform({ content: c });
    const f = findings.find((x) => x.rule === "tf-world-open-admin-port");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("flags RDP open to 0.0.0.0/0 as an admin port", () => {
    const c = [
      'resource "aws_security_group" "rdp" {',
      "  ingress {",
      "    from_port   = 3389",
      "    to_port     = 3389",
      '    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]',
      "  }",
      "}",
    ].join("\n");
    expect(has(c, "tf-world-open-admin-port")).toBe(true);
  });

  it("flags a generic world-open ingress on a non-admin port", () => {
    const c = [
      'resource "aws_security_group" "app" {',
      "  ingress {",
      "    from_port   = 8080",
      "    to_port     = 8080",
      '    cidr_blocks = ["0.0.0.0/0"]',
      "  }",
      "}",
    ].join("\n");
    expect(has(c, "tf-world-open-ingress")).toBe(true);
    expect(has(c, "tf-world-open-admin-port")).toBe(false);
  });

  it("does not flag a restricted CIDR block", () => {
    const c = [
      'resource "aws_security_group" "web" {',
      "  ingress {",
      "    from_port   = 22",
      "    to_port     = 22",
      '    cidr_blocks = ["10.0.0.0/16"]',
      "  }",
      "}",
    ].join("\n");
    expect(has(c, "tf-world-open-admin-port")).toBe(false);
    expect(has(c, "tf-world-open-ingress")).toBe(false);
  });
});

describe("auditTerraform — storage and encryption", () => {
  it("flags a public-read bucket ACL", () => {
    const c = 'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n';
    expect(has(c, "tf-public-storage-acl")).toBe(true);
  });

  it("flags a public-read-write bucket ACL", () => {
    const c = 'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read-write"\n}\n';
    expect(has(c, "tf-public-storage-acl")).toBe(true);
  });

  it("flags disabled public-access blocking", () => {
    const c =
      'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = false\n}\n';
    expect(has(c, "tf-public-access-block-disabled")).toBe(true);
  });

  it("flags an unencrypted volume", () => {
    const c = 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n';
    expect(has(c, "tf-unencrypted-resource")).toBe(true);
  });

  it("flags an unencrypted database", () => {
    const c = 'resource "aws_db_instance" "d" {\n  storage_encrypted = false\n}\n';
    expect(has(c, "tf-unencrypted-resource")).toBe(true);
  });

  it("does not flag a private, encrypted bucket", () => {
    const c =
      'resource "aws_s3_bucket_acl" "b" {\n  acl = "private"\n}\nresource "aws_ebs_volume" "v" {\n  encrypted = true\n}\n';
    expect(has(c, "tf-public-storage-acl")).toBe(false);
    expect(has(c, "tf-unencrypted-resource")).toBe(false);
  });
});

describe("auditTerraform — IAM, secrets, and databases", () => {
  it("flags a JSON-encoded IAM wildcard action", () => {
    const c = 'resource "aws_iam_policy" "p" {\n  policy = "{\\"Action\\": \\"*\\"}"\n}\n';
    expect(has(c, "tf-iam-wildcard")).toBe(true);
  });

  it("flags a native HCL actions wildcard", () => {
    const c = 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["*"]\n  }\n}\n';
    expect(has(c, "tf-iam-wildcard")).toBe(true);
  });

  it("flags a hardcoded secret literal", () => {
    const c = 'resource "aws_db_instance" "d" {\n  password = "hunter2pass"\n}\n';
    expect(has(c, "tf-hardcoded-secret")).toBe(true);
  });

  it("flags a plaintext provider credential", () => {
    const c = 'provider "aws" {\n  access_key = "AKIAEXAMPLE123"\n  region = "us-east-1"\n}\n';
    expect(has(c, "tf-plaintext-provider-credential")).toBe(true);
  });

  it("does not flag a secret driven by a variable", () => {
    const c = 'resource "aws_db_instance" "d" {\n  password = "${var.db_password}"\n}\n';
    expect(has(c, "tf-hardcoded-secret")).toBe(false);
  });

  it("flags a publicly accessible database", () => {
    const c = 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n';
    expect(has(c, "tf-publicly-accessible-db")).toBe(true);
  });

  it("flags disabled logging", () => {
    const c = 'resource "aws_eks_cluster" "c" {\n  enable_logging = false\n}\n';
    expect(has(c, "tf-logging-disabled")).toBe(true);
  });

  it("masks the secret value in finding evidence", () => {
    const c = 'resource "aws_db_instance" "d" {\n  password = "hunter2pass"\n}\n';
    const f = auditTerraform({ content: c }).find((x) => x.rule === "tf-hardcoded-secret");
    expect(f?.evidence ?? "").not.toContain("hunter2pass");
  });
});

describe("auditTerraform — finding shape", () => {
  it("produces deterministic finding IDs across runs", () => {
    const c = [
      'resource "aws_db_instance" "d" {',
      "  publicly_accessible = true",
      "  storage_encrypted   = false",
      "}",
    ].join("\n");
    const a = auditTerraform({ content: c, filename: "main.tf" });
    const b = auditTerraform({ content: c, filename: "main.tf" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("emits findings tagged iac with a real CWE", () => {
    const c = 'resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n';
    const f = auditTerraform({ content: c })[0];
    expect(f?.module).toBe("iac");
    expect(f?.tags).toContain("iac");
    expect((f?.cwe ?? []).some((id) => id.startsWith("CWE-"))).toBe(true);
  });

  it("returns no findings for a clean configuration", () => {
    const c =
      'resource "aws_ebs_volume" "v" {\n  encrypted = true\n  kms_key_id = aws_kms_key.k.arn\n}\n';
    expect(auditTerraform({ content: c })).toHaveLength(0);
  });
});
