// Comment-stripping for source text.
//
// The stripper replaces comment bodies with spaces while preserving each
// character's column offset and line number. String literals are left intact
// so injection patterns can still see their content.

import type { Language } from "../languages.js";

export function stripCommentsForLanguage(source: string, language: Language): string {
  if (language === "typescript" || language === "javascript") {
    return stripCommentsTs(source);
  }
  if (language === "python") {
    return stripCommentsPy(source);
  }
  if (language === "go") {
    return stripCommentsGo(source);
  }
  if (language === "rust") {
    return stripCommentsRust(source);
  }
  return source;
}

/**
 * Strip `//` and block comments from JS/TS source, preserving column offsets
 * by substituting spaces. String and template literals are left intact.
 * Regex literals are not specifically tracked; misclassification is rare in
 * practice because regex `/.../` does not span lines.
 */
export function stripCommentsTs(src: string): string {
  const out: string[] = [];
  const len = src.length;
  let i = 0;
  while (i < len) {
    const ch = src[i];
    const next = i + 1 < len ? src[i + 1] : "";

    if (ch === "/" && next === "/") {
      out.push("  ");
      i += 2;
      while (i < len && src[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      out.push("  ");
      i += 2;
      while (i < len) {
        if (src[i] === "*" && src[i + 1] === "/") {
          out.push("  ");
          i += 2;
          break;
        }
        out.push(src[i] === "\n" ? "\n" : " ");
        i++;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      out.push(ch);
      i++;
      while (i < len) {
        const c = src[i];
        if (c === "\\" && i + 1 < len) {
          const peek = src[i + 1] ?? "";
          out.push(c, peek);
          i += 2;
          continue;
        }
        if (c === undefined) break;
        out.push(c);
        i++;
        if (c === quote) break;
        if (quote !== "`" && c === "\n") break;
      }
      continue;
    }
    out.push(ch ?? "");
    i++;
  }
  return out.join("");
}

/**
 * Strip `#` comments from Python source. Triple-quoted and single-quoted
 * strings are skipped over to avoid misclassifying `#` inside strings.
 */
export function stripCommentsPy(src: string): string {
  const out: string[] = [];
  const len = src.length;
  let i = 0;
  while (i < len) {
    const ch = src[i];
    const c1 = i + 1 < len ? src[i + 1] : "";
    const c2 = i + 2 < len ? src[i + 2] : "";

    if ((ch === '"' || ch === "'") && c1 === ch && c2 === ch) {
      const q = ch;
      out.push(q, q, q);
      i += 3;
      while (i < len) {
        if (src[i] === "\\" && i + 1 < len) {
          out.push(src[i] ?? "", src[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (src[i] === q && src[i + 1] === q && src[i + 2] === q) {
          out.push(q, q, q);
          i += 3;
          break;
        }
        out.push(src[i] ?? "");
        i++;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      out.push(ch);
      i++;
      while (i < len) {
        if (src[i] === "\\" && i + 1 < len) {
          out.push(src[i] ?? "", src[i + 1] ?? "");
          i += 2;
          continue;
        }
        const c = src[i];
        if (c === undefined) break;
        if (c === quote) {
          out.push(c);
          i++;
          break;
        }
        if (c === "\n") break;
        out.push(c);
        i++;
      }
      continue;
    }
    if (ch === "#") {
      out.push(" ");
      i++;
      while (i < len && src[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    out.push(ch ?? "");
    i++;
  }
  return out.join("");
}

/**
 * Strip line and block comments from Go source, preserving column offsets by
 * substituting spaces. Go block comments do NOT nest. Interpreted strings
 * (`"..."`), raw strings (`` `...` ``, which may span lines), and rune literals
 * (`'x'`) are all left intact.
 */
export function stripCommentsGo(src: string): string {
  const out: string[] = [];
  const len = src.length;
  let i = 0;
  while (i < len) {
    const ch = src[i];
    const next = i + 1 < len ? src[i + 1] : "";

    if (ch === "/" && next === "/") {
      out.push("  ");
      i += 2;
      while (i < len && src[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      out.push("  ");
      i += 2;
      while (i < len) {
        if (src[i] === "*" && src[i + 1] === "/") {
          out.push("  ");
          i += 2;
          break;
        }
        out.push(src[i] === "\n" ? "\n" : " ");
        i++;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      out.push(ch);
      i++;
      while (i < len) {
        const c = src[i];
        if (c === "\\" && i + 1 < len) {
          out.push(c, src[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (c === undefined) break;
        out.push(c);
        i++;
        if (c === quote) break;
        if (c === "\n") break;
      }
      continue;
    }
    if (ch === "`") {
      out.push("`");
      i++;
      while (i < len) {
        const c = src[i];
        if (c === undefined) break;
        out.push(c);
        i++;
        if (c === "`") break;
      }
      continue;
    }
    out.push(ch ?? "");
    i++;
  }
  return out.join("");
}

/**
 * Strip line and block comments from Rust source, preserving column offsets by
 * substituting spaces. Unlike Go, Rust block comments DO nest, so the stripper
 * tracks nesting depth. Regular strings (`"..."`), raw strings (`r"..."`,
 * `r#"..."#`, ...), and char literals (`'x'`) are left intact. A `'` is only
 * treated as a char-literal delimiter when it matches the strict shape
 * `'\\?.'`; otherwise it is an ordinary character, so lifetimes such as
 * `&'a str` are not mis-parsed.
 */
export function stripCommentsRust(src: string): string {
  const out: string[] = [];
  const len = src.length;
  let i = 0;
  while (i < len) {
    const ch = src[i];
    const next = i + 1 < len ? src[i + 1] : "";

    if (ch === "/" && next === "/") {
      out.push("  ");
      i += 2;
      while (i < len && src[i] !== "\n") {
        out.push(" ");
        i++;
      }
      continue;
    }
    if (ch === "/" && next === "*") {
      let depth = 1;
      out.push("  ");
      i += 2;
      while (i < len && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") {
          depth++;
          out.push("  ");
          i += 2;
          continue;
        }
        if (src[i] === "*" && src[i + 1] === "/") {
          depth--;
          out.push("  ");
          i += 2;
          continue;
        }
        out.push(src[i] === "\n" ? "\n" : " ");
        i++;
      }
      continue;
    }
    // Raw strings: r"...", r#"..."#, r##"..."##, etc.
    if (ch === "r" && (next === '"' || next === "#")) {
      let hashes = 0;
      let j = i + 1;
      while (j < len && src[j] === "#") {
        hashes++;
        j++;
      }
      if (j < len && src[j] === '"') {
        // Confirmed raw string opener.
        for (let k = i; k <= j; k++) out.push(src[k] ?? "");
        i = j + 1;
        while (i < len) {
          if (src[i] === '"') {
            let closeHashes = 0;
            while (closeHashes < hashes && src[i + 1 + closeHashes] === "#") {
              closeHashes++;
            }
            if (closeHashes === hashes) {
              for (let k = 0; k <= hashes; k++) out.push(src[i + k] ?? "");
              i += hashes + 1;
              break;
            }
          }
          out.push(src[i] ?? "");
          i++;
        }
        continue;
      }
    }
    if (ch === '"') {
      out.push('"');
      i++;
      while (i < len) {
        const c = src[i];
        if (c === "\\" && i + 1 < len) {
          out.push(c, src[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (c === undefined) break;
        out.push(c);
        i++;
        if (c === '"') break;
      }
      continue;
    }
    // Char literal vs lifetime: only consume `'` as a char literal when it
    // matches the strict shape `'\\?.'` (one char or one escape, then `'`).
    if (ch === "'") {
      const c1 = i + 1 < len ? src[i + 1] : "";
      let isCharLiteral = false;
      if (c1 === "\\") {
        // Escape: `'\?'` — the escape consumes one char, then a closing quote.
        if (i + 3 < len && src[i + 3] === "'") isCharLiteral = true;
      } else if (c1 !== "" && c1 !== "'" && i + 2 < len && src[i + 2] === "'") {
        isCharLiteral = true;
      }
      if (isCharLiteral) {
        const end = c1 === "\\" ? i + 3 : i + 2;
        for (let k = i; k <= end; k++) out.push(src[k] ?? "");
        i = end + 1;
        continue;
      }
      // Otherwise treat `'` as an ordinary character (lifetime, label, etc.).
      out.push("'");
      i++;
      continue;
    }
    out.push(ch ?? "");
    i++;
  }
  return out.join("");
}
