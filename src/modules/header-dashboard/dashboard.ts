/**
 * The Header Dashboard's knowledge base and builder (Phase 4, D-009).
 *
 * D-009 in one line: the dashboard is informational and weightless. The trust-score module
 * already *scores* the security-relevant response headers (the `headers` category); this
 * module's job is *transparency* — show every header the site sent next to the value good
 * practice recommends, so a user can read the site's actual answer rather than a summary of it.
 *
 * Two consequences are deliberate:
 *
 *   - Nothing here produces a `SignalAssessment`; nothing here can move the Trust Score.
 *   - A recommended header is only reported *absent* when the response was actually observed.
 *     `available: false` (no main document seen) renders as "did not observe" in the popup,
 *     never as nine accusations a site may not deserve (D-006).
 */

import type { HeaderDashboardReport, HeaderDashboardRow } from '../../core/types';
import type { MainDocumentObservation } from '../../shared/observation';

export interface RecommendedHeader {
  name: string;
  label: string;
  /** Plain-language recommended practice, written for the popup. */
  guidance: string;
}

/**
 * The nine security headers, in the same order the collection layer pins them
 * (`SECURITY_HEADERS` in `src/background/tab-state.ts`), so the dashboard and the analyser
 * can never disagree about what counts as a security header.
 */
export const RECOMMENDED_HEADERS: readonly RecommendedHeader[] = [
  {
    name: 'content-security-policy',
    label: 'Content Security Policy',
    guidance: "Restrict script and object sources; avoid 'unsafe-inline' and 'unsafe-eval', and set object-src 'none'.",
  },
  {
    name: 'strict-transport-security',
    label: 'HTTP Strict Transport Security',
    guidance: 'A max-age of at least one year (31536000), with the includeSubDomains directive.',
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    guidance: 'nosniff',
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    guidance: 'DENY or SAMEORIGIN, or a CSP frame-ancestors directive.',
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    guidance: 'strict-origin-when-cross-origin, or the stricter no-referrer or same-origin.',
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    guidance: 'Explicitly disable sensitive features the page does not use, e.g. camera=(), geolocation=().',
  },
  {
    name: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy',
    guidance: 'same-origin',
  },
  {
    name: 'cross-origin-embedder-policy',
    label: 'Cross-Origin-Embedder-Policy',
    guidance: 'require-corp or credentialless when the page opts into cross-origin isolation.',
  },
  {
    name: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy',
    guidance: 'same-origin or same-site for resources other sites should not embed.',
  },
];

const RECOMMENDED_NAMES = new Set(RECOMMENDED_HEADERS.map((header) => header.name));

/**
 * Builds the dashboard from the main document's observed response headers.
 *
 * Duplicate header names fold to the first value deterministically rather than rendering
 * twice. Recommended headers keep knowledge-base order whether present or not; every other
 * observed header follows, alphabetically, so the list reads the same on every visit.
 */
export function buildHeaderDashboard(mainDocument: MainDocumentObservation | null): HeaderDashboardReport {
  if (mainDocument === null) {
    return { available: false, observedCount: 0, rows: [] };
  }

  const observed = new Map<string, string>();
  for (const header of mainDocument.headers) {
    if (!observed.has(header.name)) observed.set(header.name, header.value);
  }

  const rows: HeaderDashboardRow[] = RECOMMENDED_HEADERS.map((recommended) => {
    const value = observed.get(recommended.name);
    return {
      name: recommended.name,
      label: recommended.label,
      value: value ?? '',
      present: value !== undefined,
      recommended: true,
      guidance: recommended.guidance,
    };
  });

  const rest: HeaderDashboardRow[] = [...observed.entries()]
    .filter(([name]) => !RECOMMENDED_NAMES.has(name))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => ({
      name,
      label: name,
      value,
      present: true,
      recommended: false,
      guidance: null,
    }));

  return { available: true, observedCount: observed.size, rows: [...rows, ...rest] };
}
