// Dispatcher: pick the right lockfile parser by filename or explicit kind.

import type { LockfileParseResult } from "../types.js";
import { parseCargoLock } from "./cargo.js";
import { parseGoSum } from "./go.js";
import { parseNpmLock } from "./npm.js";
import { parsePoetryLock } from "./poetry.js";

export type LockfileKind = "npm" | "cargo" | "poetry" | "go";

export const LOCKFILE_KINDS: readonly LockfileKind[] = ["npm", "cargo", "poetry", "go"];

export function detectLockfileKind(filename: string): LockfileKind | null {
  const lower = filename.toLowerCase();
  if (lower.endsWith("package-lock.json") || lower.endsWith("npm-shrinkwrap.json")) return "npm";
  if (lower.endsWith("cargo.lock")) return "cargo";
  if (lower.endsWith("poetry.lock")) return "poetry";
  if (lower.endsWith("go.sum")) return "go";
  return null;
}

export function parseLockfile(content: string, kind: LockfileKind): LockfileParseResult {
  switch (kind) {
    case "npm":
      return parseNpmLock(content);
    case "cargo":
      return parseCargoLock(content);
    case "poetry":
      return parsePoetryLock(content);
    case "go":
      return parseGoSum(content);
  }
}
