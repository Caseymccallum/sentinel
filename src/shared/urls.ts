/**
 * URL helpers used by both the content scripts and the background worker.
 *
 * Deliberately dependency-free (`new URL` plus string work) so the content script carries
 * almost no weight, and every helper is total: an unparseable URL yields `null`/`''`
 * instead of throwing inside a page we do not control.
 */

/** Parses a URL, returning `null` rather than throwing on garbage. */
export function safeUrl(raw: string | null | undefined): URL | null {
  if (!raw) return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/** Lower-cased hostname, or `''` when the string is not a URL we can read. */
export function hostnameOf(raw: string | null | undefined): string {
  return safeUrl(raw)?.hostname.toLowerCase() ?? '';
}

/** Scheme without the colon, lower-cased, or `''`. */
export function schemeOf(raw: string | null | undefined): string {
  return safeUrl(raw)?.protocol.replace(':', '').toLowerCase() ?? '';
}

/** `scheme://host[:port]`, or `''`. */
export function originOf(raw: string | null | undefined): string {
  const parsed = safeUrl(raw);
  return parsed ? parsed.origin : '';
}

export function isSecureUrl(raw: string | null | undefined): boolean {
  return schemeOf(raw) === 'https';
}

export function isInsecureUrl(raw: string | null | undefined): boolean {
  return schemeOf(raw) === 'http';
}

/** Schemes Sentinel can sensibly analyse (everything else gets marked unsupported). */
export function isAnalysableScheme(raw: string | null | undefined): boolean {
  const scheme = schemeOf(raw);
  return scheme === 'http' || scheme === 'https';
}

/**
 * Resolves a possibly-relative reference against a base, for `form.action` and friends.
 *
 * A form with no `action` attribute submits to the document URL, which is why `baseUrl`
 * is required rather than optional: guessing here would silently mislabel a form as
 * same-origin.
 */
export function resolveAgainst(baseUrl: string, reference: string | null | undefined): string {
  const reference_ = (reference ?? '').trim();
  if (reference_ === '') return baseUrl;
  try {
    return new URL(reference_, baseUrl).href;
  } catch {
    return baseUrl;
  }
}