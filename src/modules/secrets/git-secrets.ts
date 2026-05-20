// Git log / diff scanner.
//
// Walks `git log -p` or `git diff` output line by line, tracking the
// current commit (from `commit <sha>` headers), the current file (from
// `+++ b/<path>` headers), and the line number in the new file (from
// `@@` hunk headers). For each diff content line, runs the secret-pattern
// registry and entropy detector, and attributes the resulting findings
// to the commit + file + line where they appear.

import type { Finding, FindingLocation } from "../../core/types.js";
import { findingId } from "../../core/utils.js";
import { DEFAULT_THRESHOLDS, type EntropyThresholds, scanEntropy } from "./entropy.js";
import type { SecretPatternRegistry } from "./patterns.js";

export interface GitScanInput {
  readonly source: string;
}

const COMMIT_RE = /^commit\s+([0-9a-f]{7,40})\b/;
const FILE_PLUS_RE = /^\+\+\+\s+(.+)$/;
const HUNK_RE = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/;

function stripPathMarker(raw: string): string {
  const tab = raw.indexOf("\t");
  const trimmed = tab >= 0 ? raw.slice(0, tab) : raw;
  if (trimmed === "/dev/null") return trimmed;
  if (trimmed.startsWith("b/")) return trimmed.slice(2);
  if (trimmed.startsWith("a/")) return trimmed.slice(2);
  return trimmed;
}

interface LineContext {
  readonly commit: string | null;
  readonly file: string;
  readonly line: number | undefined;
}

function relocate(f: Finding, ctx: LineContext): Finding {
  const baseLine = ctx.line ?? f.location?.line_start ?? 1;
  const baseColumn = f.location?.column;
  const location: FindingLocation = {
    file: ctx.file,
    line_start: baseLine,
    ...(baseColumn !== undefined ? { column: baseColumn } : {}),
  };
  const tags = ctx.commit ? [...f.tags, `commit:${ctx.commit}`] : f.tags;
  return {
    ...f,
    id: findingId(f.module, f.rule, location, f.evidence ?? ""),
    location,
    tags,
  };
}

export function scanGitSecrets(
  input: GitScanInput,
  registry: SecretPatternRegistry,
  thresholds: EntropyThresholds = DEFAULT_THRESHOLDS,
): readonly Finding[] {
  const lines = input.source.split(/\r?\n/);
  let currentCommit: string | null = null;
  let currentFile = "<unknown>";
  let cursorInNew = 0;
  const out: Finding[] = [];

  for (const line of lines) {
    const commitMatch = COMMIT_RE.exec(line);
    if (commitMatch?.[1]) {
      currentCommit = commitMatch[1];
      continue;
    }
    if (line.startsWith("diff --git ")) continue;
    if (line.startsWith("index ")) continue;
    const fileMatch = FILE_PLUS_RE.exec(line);
    if (fileMatch?.[1]) {
      currentFile = stripPathMarker(fileMatch[1].trim());
      continue;
    }
    if (line.startsWith("--- ")) continue;
    const hunkMatch = HUNK_RE.exec(line);
    if (hunkMatch?.[1]) {
      cursorInNew = Number.parseInt(hunkMatch[1], 10);
      continue;
    }

    let body: string;
    let lineInFile: number | undefined;
    const tag = line[0];
    if (tag === "+" && !line.startsWith("+++")) {
      body = line.slice(1);
      lineInFile = cursorInNew;
      cursorInNew += 1;
    } else if (tag === " ") {
      body = line.slice(1);
      lineInFile = cursorInNew;
      cursorInNew += 1;
    } else if (tag === "-" && !line.startsWith("---")) {
      body = line.slice(1);
      // Historical (deleted) content — still worth flagging since secrets in
      // history are not "removed" until rotated. line number in NEW file is
      // not meaningful here, so omit.
    } else if (tag === "\\") {
      // "\ No newline at end of file" — skip.
      continue;
    } else {
      body = line;
    }

    if (body.length === 0) continue;

    const ctx: LineContext = {
      commit: currentCommit,
      file: currentFile,
      line: lineInFile,
    };

    const patternFindings = registry.scan({ source: body, file: currentFile });
    for (const f of patternFindings) out.push(relocate(f, ctx));

    const entropyFindings = scanEntropy({ source: body, file: currentFile }, thresholds);
    for (const f of entropyFindings) out.push(relocate(f, ctx));
  }

  return out;
}
