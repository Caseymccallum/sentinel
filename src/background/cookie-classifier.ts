/**
 * Cookie classification: raw metadata in, classified cookies and a summary out.
 *
 * Pure: no browser APIs, no I/O, an injected clock for lifetime arithmetic. The classifier
 * joins each record against the knowledge base (`src/shared/cookies.ts`) and falls back to the
 * conservative generic inference for names it does not know. Nothing here ever touches a
 * cookie value — the input records are already value-free by construction (D-007).
 */

import type {
  ClassifiedCookie,
  CookieRecord,
  CookieSummary,
} from '../core/types';
import { inferUnknownCookie, lookupCookie } from '../shared/cookies';
import { cookieKey } from './cookie-observer';

/** Stable id for popup rows and delete buttons. */
export function classifiedCookieId(record: CookieRecord): string {
  return cookieKey(record);
}

/** The arguments `chrome.cookies.remove()` needs, expressed as plain data. */
export interface CookieRemovalTarget {
  name: string;
  domain: string;
  path: string;
  storeId: string;
  secure: boolean;
}

/** Everything about a cookie except the secret `value`, which no type here can hold (D-007). */
export function removalTargetFor(record: CookieRecord): CookieRemovalTarget {
  return {
    name: record.name,
    domain: record.domain,
    path: record.path,
    storeId: record.storeId,
    secure: record.secure,
  };
}

/**
 * The URL a removal is addressed to. Cookies live on (domain, path) pairs, not origins, so
 * `chrome.cookies.remove()` needs a URL that matches both: the domain without its leading dot,
 * the cookie's own path, and a scheme consistent with the `Secure` flag.
 */
export function removalUrlFor(target: CookieRemovalTarget): string {
  const host = target.domain.startsWith('.') ? target.domain.slice(1) : target.domain;
  const path = target.path.startsWith('/') ? target.path : `/${target.path}`;
  return `${target.secure ? 'https' : 'http'}://${host}${path === '' ? '/' : path}`;
}

/** Classifies one record against the knowledge base, falling back to conservative inference. */
export function classifyCookie(record: CookieRecord): ClassifiedCookie {
  const known = lookupCookie(record.name);
  const base = {
    ...record,
    id: classifiedCookieId(record),
  };

  if (known) {
    return {
      ...base,
      known: true,
      category: known.category,
      description: known.description,
      purpose: known.purpose,
      safeToDelete: known.safeToDelete,
      setBy: known.setBy,
    };
  }

  const inference = inferUnknownCookie(record.name);
  const host = record.domain.startsWith('.') ? record.domain.slice(1) : record.domain;
  return {
    ...base,
    known: false,
    category: inference.category,
    description: inference.description,
    purpose: inference.purpose,
    safeToDelete: inference.safeToDelete,
    setBy: record.firstParty || host === '' ? 'the site itself' : host,
  };
}

const DAY_MS = 86_400_000;

/** Aggregates the classified list into the summary the TrustEngine and popup header read. */
export function summarizeCookies(cookies: readonly ClassifiedCookie[], now: number = Date.now()): CookieSummary {
  const summary: CookieSummary = {
    total: cookies.length,
    essential: 0,
    analytics: 0,
    advertising: 0,
    social: 0,
    unknown: 0,
    thirdPartyCount: 0,
    persistentCount: 0,
    longestExpirationDays: 0,
    longestExpirationName: null,
  };

  let longestDays = 0;
  let longestName: string | null = null;

  for (const cookie of cookies) {
    switch (cookie.category) {
      case 'essential': summary.essential += 1; break;
      case 'analytics': summary.analytics += 1; break;
      case 'advertising': summary.advertising += 1; break;
      case 'social': summary.social += 1; break;
      case 'preference': summary.essential += 1; break;
      case 'unknown': summary.unknown += 1; break;
    }
    if (!cookie.firstParty) summary.thirdPartyCount += 1;
    if (!cookie.session) summary.persistentCount += 1;

    if (!cookie.session && typeof cookie.expirationDate === 'number') {
      const remainingDays = Math.floor((cookie.expirationDate * 1000 - now) / DAY_MS);
      if (remainingDays > longestDays) {
        longestDays = remainingDays;
        longestName = cookie.name;
      }
    }
  }

  summary.longestExpirationDays = Math.max(0, longestDays);
  summary.longestExpirationName = longestDays > 0 ? longestName : null;
  return summary;
}

/**
 * Classifies a whole cookie list and produces its summary.
 *
 * `now` is injected so lifetime arithmetic (and the "longest-lasting" header) is deterministic
 * under test.
 */
export function classifyCookies(
  records: readonly CookieRecord[],
  now: number = Date.now(),
): { cookies: ClassifiedCookie[]; summary: CookieSummary } {
  const cookies = records.map((record) => classifyCookie(record));
  return { cookies, summary: summarizeCookies(cookies, now) };
}

/** Categories the "Delete all tracking cookies" bulk action selects. */
const TRACKING_CATEGORIES = new Set(['analytics', 'advertising', 'social']);

/** The cookies the bulk action would delete: known or inferred tracking categories, third or first party. */
export function trackingCookies(cookies: readonly ClassifiedCookie[]): ClassifiedCookie[] {
  return cookies.filter((cookie) => TRACKING_CATEGORIES.has(cookie.category));
}
