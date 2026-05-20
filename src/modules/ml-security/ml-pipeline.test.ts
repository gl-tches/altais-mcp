import { describe, expect, it } from "vitest";
import { auditMlPipeline } from "./ml-pipeline.js";

const rules = (input: Parameters<typeof auditMlPipeline>[0]): string[] =>
  auditMlPipeline(input).map((f) => f.rule);

describe("auditMlPipeline — source patterns", () => {
  it("flags pickle.load as insecure deserialization", () => {
    expect(rules({ source: "model = pickle.load(open('m.pkl','rb'))" })).toContain(
      "ml-pipeline-pickle-load",
    );
  });

  it("flags joblib.load", () => {
    expect(rules({ source: "clf = joblib.load('clf.joblib')" })).toContain(
      "ml-pipeline-joblib-load",
    );
  });

  it("flags torch.load without weights_only=True", () => {
    expect(rules({ source: "m = torch.load('ckpt.pt')" })).toContain(
      "ml-pipeline-torch-load-unsafe",
    );
  });

  it("does not flag torch.load with weights_only=True", () => {
    expect(rules({ source: "m = torch.load('ckpt.pt', weights_only=True)" })).not.toContain(
      "ml-pipeline-torch-load-unsafe",
    );
  });

  it("flags reading training data from a remote URL", () => {
    expect(rules({ source: "df = pd.read_csv('https://evil.example/data.csv')" })).toContain(
      "ml-pipeline-remote-data-read",
    );
  });

  it("does not flag a local pandas read", () => {
    expect(rules({ source: "df = pd.read_csv('local/data.csv')" })).not.toContain(
      "ml-pipeline-remote-data-read",
    );
  });
});

describe("auditMlPipeline — config", () => {
  it("flags untrusted training data source", () => {
    expect(rules({ config: { training_data_source: "scraped" } })).toContain(
      "ml-pipeline-untrusted-training-data",
    );
  });

  it("does not flag a trusted training data source", () => {
    expect(rules({ config: { training_data_source: "internal" } })).not.toContain(
      "ml-pipeline-untrusted-training-data",
    );
  });

  it("flags missing data validation and an executable model format", () => {
    const r = rules({ config: { data_validation: false, model_format: "pickle" } });
    expect(r).toContain("ml-pipeline-no-data-validation");
    expect(r).toContain("ml-pipeline-insecure-model-format");
  });

  it("flags unsigned models, unpinned deps, and secrets in notebooks", () => {
    const r = rules({
      config: { model_signed: false, pinned_dependencies: false, secrets_in_notebooks: true },
    });
    expect(r).toContain("ml-pipeline-unsigned-model");
    expect(r).toContain("ml-pipeline-unpinned-dependencies");
    expect(r).toContain("ml-pipeline-secrets-in-notebooks");
  });

  it("returns no findings for a fully hardened pipeline", () => {
    expect(
      auditMlPipeline({
        config: {
          training_data_source: "internal",
          data_validation: true,
          data_provenance_tracked: true,
          model_format: "safetensors",
          model_signed: true,
          pinned_dependencies: true,
          secrets_in_notebooks: false,
          lineage_tracked: true,
        },
      }),
    ).toHaveLength(0);
  });
});

describe("auditMlPipeline — shape and determinism", () => {
  it("produces deterministic finding IDs", () => {
    const a = auditMlPipeline({ source: "pickle.load(f)", filename: "train.py" });
    const b = auditMlPipeline({ source: "pickle.load(f)", filename: "train.py" });
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
  });

  it("tags every finding with the ml_security module, ml-security tag, and a CWE", () => {
    const findings = auditMlPipeline({
      source: "pickle.load(f)",
      config: { model_signed: false },
    });
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.module).toBe("ml_security");
      expect(f.tags).toContain("ml-security");
      expect(f.cwe?.length ?? 0).toBeGreaterThan(0);
    }
  });
});
