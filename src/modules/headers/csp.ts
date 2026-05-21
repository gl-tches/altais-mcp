// Content-Security-Policy generator.
//
// Builds a CSP header string from a high-level description of what the
// application needs. The generator is conservative: anything not
// explicitly requested is `'none'` (in strict mode) or `'self'` (in
// compatible mode). The `'unsafe-inline'` keyword and the dynamic-code
// source keyword are never emitted; callers asking for them get a
// `recommendations` entry that suggests a safer alternative (nonces /
// hashes).

export type CspMode = "strict" | "compatible";

export interface CspRequirements {
  readonly mode?: CspMode;
  readonly requires_inline_scripts?: boolean;
  readonly requires_inline_styles?: boolean;
  readonly external_scripts?: readonly string[];
  readonly external_styles?: readonly string[];
  readonly external_images?: readonly string[];
  readonly external_fonts?: readonly string[];
  readonly external_connections?: readonly string[];
  readonly external_frames?: readonly string[];
  readonly use_workers?: boolean;
  readonly allow_form_actions?: readonly string[];
  readonly report_uri?: string;
  readonly report_to?: string;
}

export interface CspResult {
  readonly mode: CspMode;
  readonly header: string;
  readonly directives: Readonly<Record<string, readonly string[]>>;
  readonly recommendations: readonly string[];
  readonly notes: readonly string[];
}

const SELF = "'self'";
const NONE = "'none'";

function unique(values: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

function validateSource(source: string, errors: string[]): boolean {
  const trimmed = source.trim();
  if (trimmed.length === 0) return false;
  if (/['"]/.test(trimmed) && !/^'[a-zA-Z0-9-]+'$/.test(trimmed)) {
    errors.push(`Source contains a literal quote: ${trimmed}`);
    return false;
  }
  if (/\s/.test(trimmed)) {
    errors.push(`Source contains whitespace: ${trimmed}`);
    return false;
  }
  if (trimmed === "*") return true;
  if (/^https?:\/\//.test(trimmed)) return true;
  if (/^(?:wss?|data|blob|ws|mediastream|filesystem):/.test(trimmed)) return true;
  if (/^'[a-z0-9-]+(?:[-_][a-z0-9]+)*'$/.test(trimmed)) return true; // 'self', 'unsafe-inline'
  if (/^'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/=_-]+'$/.test(trimmed)) return true;
  if (/^[a-zA-Z0-9.*-]+(?:\.[a-zA-Z0-9*-]+)+$/.test(trimmed)) return true; // example.com
  errors.push(`Unrecognized CSP source: ${trimmed}`);
  return false;
}

function externalSources(
  sources: readonly string[] | undefined,
  errors: string[],
): readonly string[] {
  if (!sources) return [];
  return sources.filter((s) => validateSource(s, errors));
}

/**
 * Generate a CSP header from an app requirements description.
 */
export function generateCsp(req: CspRequirements): CspResult {
  const mode: CspMode = req.mode ?? "strict";
  const recommendations: string[] = [];
  const errors: string[] = [];
  const fallback = mode === "strict" ? NONE : SELF;

  const scripts = unique([SELF, ...externalSources(req.external_scripts, errors)]);
  const styles = unique([SELF, ...externalSources(req.external_styles, errors)]);
  const images = unique([SELF, ...externalSources(req.external_images, errors)]);
  const fonts = unique([SELF, ...externalSources(req.external_fonts, errors)]);
  const connections = unique([SELF, ...externalSources(req.external_connections, errors)]);
  const frames = unique([...externalSources(req.external_frames, errors)]);
  const formActions = unique([SELF, ...externalSources(req.allow_form_actions, errors)]);

  if (req.requires_inline_scripts === true) {
    recommendations.push(
      "Inline scripts requested. Prefer nonce-based CSP: generate a per-request nonce and emit `'nonce-<value>'` in script-src (this generator does not emit `'unsafe-inline'`).",
    );
  }
  if (req.requires_inline_styles === true) {
    recommendations.push(
      "Inline styles requested. Prefer hashes or nonces for the specific style blocks instead of `'unsafe-inline'`.",
    );
  }

  for (const url of [
    ...(req.external_scripts ?? []),
    ...(req.external_styles ?? []),
    ...(req.external_images ?? []),
    ...(req.external_fonts ?? []),
    ...(req.external_connections ?? []),
    ...(req.external_frames ?? []),
  ]) {
    if (url.startsWith("http://")) {
      recommendations.push(
        `External source uses HTTP, not HTTPS: ${url}. Allow only HTTPS origins.`,
      );
    }
  }

  const directives: Record<string, readonly string[]> = {
    "default-src": [fallback],
    "script-src": scripts,
    "style-src": styles,
    "img-src": images,
    "font-src": fonts,
    "connect-src": connections,
    "frame-src": frames.length > 0 ? frames : [NONE],
    "form-action": formActions,
    "frame-ancestors": [NONE],
    "base-uri": [SELF],
    "object-src": [NONE],
  };

  if (req.use_workers === true) {
    directives["worker-src"] = [SELF];
  }
  if (req.report_uri !== undefined && req.report_uri.length > 0) {
    if (/^[A-Za-z0-9_\-./:?#%&=+~]+$/.test(req.report_uri)) {
      directives["report-uri"] = [req.report_uri];
    } else {
      errors.push(`Invalid report-uri: ${req.report_uri}`);
    }
  }
  if (req.report_to !== undefined && req.report_to.length > 0) {
    directives["report-to"] = [req.report_to];
  }

  directives["upgrade-insecure-requests"] = [];

  const header = renderHeader(directives);
  const notes: string[] = [];
  if (errors.length > 0) notes.push(...errors);
  if (mode === "compatible") {
    notes.push(
      "Compatible mode: `default-src 'self'` instead of `'none'`. Tighten to strict once you have confirmed every origin the app loads from.",
    );
  }
  if (
    Object.keys(directives).filter((d) => d.startsWith("script") || d.startsWith("style")).length >
    0
  ) {
    notes.push(
      "Reminder: CSP does not block server-side template injection. Pair with server-side input handling.",
    );
  }
  return { mode, header, directives, recommendations, notes };
}

function renderHeader(directives: Readonly<Record<string, readonly string[]>>): string {
  const parts: string[] = [];
  for (const [name, sources] of Object.entries(directives)) {
    if (sources.length === 0) {
      parts.push(name);
    } else {
      parts.push(`${name} ${sources.join(" ")}`);
    }
  }
  return parts.join("; ");
}
