// Fuzz-testing configuration generator (altais_generate_fuzz_config).
//
// Given a target language, a fuzzing engine, and (optionally) the name of
// the function under test, this produces a fuzz harness skeleton, a runner
// configuration, corpus / seed and dictionary guidance, and a sanitizer
// recommendation. It generates static text only — it never compiles or
// runs the harness.

export type FuzzLanguage = "c" | "cpp" | "rust" | "go" | "python" | "javascript" | "java";

export type Fuzzer =
  | "libfuzzer"
  | "afl++"
  | "cargo-fuzz"
  | "go-fuzz"
  | "atheris"
  | "jazzer"
  | "jsfuzz";

export interface FuzzConfigInput {
  readonly language: FuzzLanguage;
  readonly fuzzer?: Fuzzer;
  readonly target_function?: string;
}

export interface FuzzConfigResult {
  readonly language: FuzzLanguage;
  readonly fuzzer: Fuzzer;
  readonly target_function: string;
  readonly harness: { readonly filename: string; readonly code: string };
  readonly runner: { readonly filename: string; readonly content: string };
  readonly sanitizers: {
    readonly recommended: readonly string[];
    readonly rationale: string;
  };
  readonly corpus: {
    readonly seed_directory: string;
    readonly guidance: readonly string[];
  };
  readonly dictionary: {
    readonly filename: string;
    readonly guidance: readonly string[];
  };
  readonly references: readonly string[];
}

const REFERENCES: readonly string[] = [
  "https://llvm.org/docs/LibFuzzer.html",
  "https://aflplus.plus/",
  "https://rust-fuzz.github.io/book/cargo-fuzz.html",
  "https://go.dev/doc/security/fuzz/",
  "https://github.com/google/atheris",
  "https://github.com/CodeIntelligenceTesting/jazzer",
  "https://google.github.io/oss-fuzz/",
];

const DEFAULT_FUZZER: Readonly<Record<FuzzLanguage, Fuzzer>> = {
  c: "libfuzzer",
  cpp: "libfuzzer",
  rust: "cargo-fuzz",
  go: "go-fuzz",
  python: "atheris",
  javascript: "jsfuzz",
  java: "jazzer",
};

/** Sanitizer recommendation per language. */
function sanitizerFor(language: FuzzLanguage): {
  recommended: readonly string[];
  rationale: string;
} {
  switch (language) {
    case "c":
    case "cpp":
      return {
        recommended: ["AddressSanitizer (ASan)", "UndefinedBehaviorSanitizer (UBSan)"],
        rationale:
          "ASan catches heap / stack / global buffer overflows and use-after-free; UBSan catches integer overflow and other undefined behavior. Run a separate MemorySanitizer (MSan) build to catch uninitialized reads, since MSan cannot be combined with ASan.",
      };
    case "rust":
      return {
        recommended: ["AddressSanitizer (ASan)"],
        rationale:
          "Safe Rust is memory-safe, but ASan still surfaces bugs in `unsafe` blocks and in C dependencies linked through FFI.",
      };
    case "go":
      return {
        recommended: ["Go race detector (-race)"],
        rationale:
          "The Go runtime already bounds-checks memory; the race detector is the highest-value instrumentation for a concurrent target.",
      };
    case "python":
    case "javascript":
      return {
        recommended: ["Native exception capture"],
        rationale:
          "Managed runtimes do not expose C-style memory sanitizers; the fuzzer treats uncaught exceptions, hangs, and assertion failures as findings.",
      };
    case "java":
      return {
        recommended: ["Jazzer bug detectors"],
        rationale:
          "Jazzer ships detectors for SQL/OS-command injection, SSRF, deserialization, and path traversal that fire on instrumented sink calls.",
      };
  }
}

function harnessFor(language: FuzzLanguage, fn: string): { filename: string; code: string } {
  switch (language) {
    case "c":
      return {
        filename: "fuzz/fuzz_target.c",
        code: [
          "#include <stddef.h>",
          "#include <stdint.h>",
          "",
          `/* Replace the body with a call into the function under test: ${fn}. */`,
          "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {",
          "  if (size == 0) return 0;",
          `  ${fn}(data, size);`,
          "  return 0;",
          "}",
        ].join("\n"),
      };
    case "cpp":
      return {
        filename: "fuzz/fuzz_target.cc",
        code: [
          "#include <cstddef>",
          "#include <cstdint>",
          "#include <string>",
          "",
          'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {',
          "  std::string input(reinterpret_cast<const char *>(data), size);",
          `  ${fn}(input);  // function under test`,
          "  return 0;",
          "}",
        ].join("\n"),
      };
    case "rust":
      return {
        filename: "fuzz/fuzz_targets/fuzz_target_1.rs",
        code: [
          "#![no_main]",
          "use libfuzzer_sys::fuzz_target;",
          "",
          "fuzz_target!(|data: &[u8]| {",
          "    if let Ok(text) = std::str::from_utf8(data) {",
          `        let _ = crate_under_test::${fn}(text);`,
          "    }",
          "});",
        ].join("\n"),
      };
    case "go":
      return {
        filename: "fuzz_test.go",
        code: [
          "package target",
          "",
          'import "testing"',
          "",
          `func Fuzz${capitalize(fn)}(f *testing.F) {`,
          '\tf.Add([]byte("seed"))',
          "\tf.Fuzz(func(t *testing.T, data []byte) {",
          `\t\t_ = ${fn}(data)  // must not panic on any input`,
          "\t})",
          "}",
        ].join("\n"),
      };
    case "python":
      return {
        filename: "fuzz_target.py",
        code: [
          "import sys",
          "import atheris",
          "",
          "with atheris.instrument_imports():",
          "    from target import " + fn,
          "",
          "",
          "def TestOneInput(data: bytes) -> None:",
          "    fdp = atheris.FuzzedDataProvider(data)",
          `    ${fn}(fdp.ConsumeUnicodeNoSurrogates(1024))`,
          "",
          "",
          "atheris.Setup(sys.argv, TestOneInput)",
          "atheris.Fuzz()",
        ].join("\n"),
      };
    case "javascript":
      return {
        filename: "fuzz_target.js",
        code: [
          "const { " + fn + ' } = require("./target");',
          "",
          "module.exports = function fuzz(buf) {",
          `  ${fn}(buf.toString("utf8"));  // function under test`,
          "};",
        ].join("\n"),
      };
    case "java":
      return {
        filename: "src/test/java/FuzzTarget.java",
        code: [
          "import com.code_intelligence.jazzer.api.FuzzedDataProvider;",
          "",
          "public final class FuzzTarget {",
          "  public static void fuzzerTestOneInput(FuzzedDataProvider data) {",
          `    Target.${fn}(data.consumeRemainingAsString());`,
          "  }",
          "}",
        ].join("\n"),
      };
  }
}

function runnerFor(
  language: FuzzLanguage,
  fuzzer: Fuzzer,
  fn: string,
): {
  filename: string;
  content: string;
} {
  const header = `# Fuzz runner for ${language} target \`${fn}\` using ${fuzzer}.`;
  switch (fuzzer) {
    case "cargo-fuzz":
      return {
        filename: "fuzz/run.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "cargo install cargo-fuzz",
          "cargo fuzz run fuzz_target_1 -- -max_total_time=300 -rss_limit_mb=2048",
        ].join("\n"),
      };
    case "go-fuzz":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          `go test -run='^$' -fuzz='^Fuzz${capitalize(fn)}$' -fuzztime=5m -race ./...`,
        ].join("\n"),
      };
    case "atheris":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "pip install atheris",
          "python fuzz_target.py -max_total_time=300 -artifact_prefix=crashes/",
        ].join("\n"),
      };
    case "jsfuzz":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "npm install --save-dev jsfuzz",
          "npx jsfuzz fuzz_target.js corpus/ --timeout=10",
        ].join("\n"),
      };
    case "jazzer":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "jazzer --cp=target/classes --target_class=FuzzTarget \\",
          "  -max_total_time=300 -artifact_prefix=crashes/",
        ].join("\n"),
      };
    case "afl++":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "afl-cc -fsanitize=address -o target_afl fuzz/fuzz_target.c",
          "afl-fuzz -i corpus/ -o findings/ -- ./target_afl @@",
        ].join("\n"),
      };
    case "libfuzzer":
      return {
        filename: "run-fuzz.sh",
        content: [
          "#!/usr/bin/env bash",
          header,
          "set -euo pipefail",
          "clang -g -O1 -fsanitize=fuzzer,address,undefined \\",
          "  -o fuzz_target fuzz/fuzz_target.c",
          "./fuzz_target corpus/ -max_total_time=300 -artifact_prefix=crashes/",
        ].join("\n"),
      };
  }
}

const CORPUS_GUIDANCE: readonly string[] = [
  "Seed the corpus with real, valid inputs from production logs or unit-test fixtures — a good seed corpus reaches deep code paths far faster than starting empty.",
  "Keep each seed small and minimized; large seeds slow every iteration and waste coverage budget.",
  "Commit the corpus to version control so the fuzzer resumes from prior coverage on every CI run.",
  "After a crash, minimize the reproducer (tmin / -minimize_crash=1) before filing it.",
];

const DICTIONARY_GUIDANCE: readonly string[] = [
  'List format-specific tokens (magic bytes, keywords, delimiters) one per line as quoted strings, e.g. `keyword="SELECT"`.',
  "A dictionary helps the fuzzer get past structural checks (headers, tags) that random mutation rarely satisfies.",
  "Pass it to the engine with `-dict=target.dict` (libFuzzer) or `-x target.dict` (AFL++).",
];

function capitalize(s: string): string {
  return s.length === 0 ? s : s.charAt(0).toUpperCase() + s.slice(1);
}

const TARGET_FUNCTION_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export class FuzzConfigError extends Error {
  override readonly name = "FuzzConfigError";
}

export function generateFuzzConfig(input: FuzzConfigInput): FuzzConfigResult {
  const fuzzer = input.fuzzer ?? DEFAULT_FUZZER[input.language];
  const fn = input.target_function ?? "parse_input";
  if (!TARGET_FUNCTION_RE.test(fn)) {
    throw new FuzzConfigError(
      "`target_function` must be a plain identifier (letters, digits, underscores; not starting with a digit).",
    );
  }
  return {
    language: input.language,
    fuzzer,
    target_function: fn,
    harness: harnessFor(input.language, fn),
    runner: runnerFor(input.language, fuzzer, fn),
    sanitizers: sanitizerFor(input.language),
    corpus: { seed_directory: "corpus/", guidance: CORPUS_GUIDANCE },
    dictionary: { filename: "target.dict", guidance: DICTIONARY_GUIDANCE },
    references: REFERENCES,
  };
}
