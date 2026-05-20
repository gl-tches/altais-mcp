// Minimal unified-diff parser for `altais_scan_diff`.
//
// Extracts the post-image of each touched hunk along with the absolute
// line numbers that were added. Only the new (right-hand) side is kept —
// pure-deletion hunks contribute no scannable content.

export interface DiffHunk {
  /** 1-indexed line in the new file where this hunk begins. */
  readonly newStart: number;
  /** Post-image lines (context + additions), in order. */
  readonly newLines: readonly string[];
  /** Absolute line numbers in the new file that were added (`+` lines). */
  readonly addedLineNumbers: readonly number[];
}

export interface DiffFile {
  /** Path of the file as it appears on the new side. */
  readonly path: string;
  readonly hunks: readonly DiffHunk[];
}

const HUNK_HEADER = /^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/;

/**
 * Parse a unified diff. Tolerant of `git diff` output (with index/extended
 * headers) and plain `diff -u` output. Unrecognized lines outside of hunks
 * are ignored.
 */
export function parseUnifiedDiff(diff: string): readonly DiffFile[] {
  const lines = diff.split(/\r?\n/);
  const files: DiffFile[] = [];

  let currentPath: string | null = null;
  let currentHunks: DiffHunk[] = [];
  let hunkLines: string[] | null = null;
  let hunkAdded: number[] | null = null;
  let hunkNewStart = 0;
  let cursorInNew = 0;

  const flushFile = (): void => {
    if (currentPath !== null && currentHunks.length > 0) {
      files.push({ path: currentPath, hunks: currentHunks });
    }
    currentPath = null;
    currentHunks = [];
  };

  const flushHunk = (): void => {
    if (hunkLines !== null && hunkAdded !== null) {
      currentHunks.push({
        newStart: hunkNewStart,
        newLines: hunkLines,
        addedLineNumbers: hunkAdded,
      });
    }
    hunkLines = null;
    hunkAdded = null;
  };

  for (const line of lines) {
    if (line.startsWith("diff --git ")) {
      flushHunk();
      flushFile();
      continue;
    }
    if (line.startsWith("+++ ")) {
      flushHunk();
      flushFile();
      currentPath = stripPathMarker(line.slice(4).trim());
      currentHunks = [];
      continue;
    }
    if (line.startsWith("--- ")) {
      // Old-side header — ignore.
      continue;
    }
    if (line.startsWith("@@")) {
      flushHunk();
      const m = HUNK_HEADER.exec(line);
      if (!m?.[1]) continue;
      hunkNewStart = Number.parseInt(m[1], 10);
      cursorInNew = hunkNewStart;
      hunkLines = [];
      hunkAdded = [];
      continue;
    }
    if (hunkLines === null || hunkAdded === null) continue;

    const tag = line[0];
    const rest = line.slice(1);
    if (tag === "+") {
      hunkLines.push(rest);
      hunkAdded.push(cursorInNew);
      cursorInNew += 1;
    } else if (tag === "-") {
      // Deletion: not present in the new file.
    } else if (tag === " " || tag === undefined) {
      hunkLines.push(rest);
      cursorInNew += 1;
    } else if (tag === "\\") {
      // "\ No newline at end of file" marker — ignore.
    } else {
      // Unknown line type: treat as context to keep line numbers consistent.
      hunkLines.push(line);
      cursorInNew += 1;
    }
  }
  flushHunk();
  flushFile();
  return files;
}

function stripPathMarker(raw: string): string {
  // `+++ b/path/to/file` → `path/to/file`. Strip trailing tab+timestamp from
  // GNU diff output.
  const tab = raw.indexOf("\t");
  const trimmed = tab >= 0 ? raw.slice(0, tab) : raw;
  if (trimmed === "/dev/null") return trimmed;
  if (trimmed.startsWith("b/")) return trimmed.slice(2);
  if (trimmed.startsWith("a/")) return trimmed.slice(2);
  return trimmed;
}
