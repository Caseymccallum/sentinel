/**
 * The cookie observer: cookie *metadata* enumeration for one tab.
 *
 * SAFETY CONTRACT (D-007). The cookie observer must never store or transmit the cookie
 * value. Only metadata survives this module: the raw `browser.cookies.Cookie` object is
 * reduced to `CookieRecord` — which has no value field, only `valueLength` — in the very
 * first step (`toCookieRecord`), and everything downstream (tab state, session storage,
 * messages, the popup) therefore cannot see a value because it is not there to see. The
 * only writer API this codebase uses is `browser.cookies.remove()` in the background's
 * `MSG_COOKIE_REMOVE` handler, which is reachable only from an explicit popup button
 * click; `browser.cookies.set()` is never called anywhere in Sentinel.
 *
 * Two queries are made, mirroring the two facts the module needs:
 *
 *   1. `getAll({ url })` — the cookies that would be sent with the page's own URL
 *      (the first-party view);
 *   2. `getAll({ domain })` for each third-party origin the tracker observer detected —
 *      this is where the tracker output becomes directly useful for a second purpose: a
 *      `_fbp` that `connect.facebook.net` set while the page loaded it never appears in
 *      the page's own cookie jar, but it is exactly the tracking cookie the user should
 *      be told about.
 *
 * The API is injected (`CookieObserverDeps`) so unit tests can feed a mock cookie store,
 * including canary values that must never appear in the output.
 */

import { browser } from 'wxt/browser';
import { isThirdPartyTo } from '../core/domain';
import type { CookieRecord, CookieSameSite } from '../core/types';

/** The subset of `browser.cookies.Cookie` the observer consumes. `value` is dropped immediately. */
export interface RawCookie {
  name: string;
  domain: string;
  hostOnly?: boolean;
  path: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: string;
  session?: boolean;
  /** Unix seconds, absent for session cookies. */
  expirationDate?: number;
  storeId?: string;
  /** Read only to measure its length; never copied anywhere (see the safety contract). */
  value?: string;
}

export interface CookiesApi {
  getAll(details: { url?: string; domain?: string }): Promise<RawCookie[]>;
}

export interface CookieObserverDeps {
  cookies: CookiesApi;
  /** The tab's current URL, or `null` when the tab is gone or is a browser-internal page. */
  getTabUrl(tabId: number): Promise<string | null>;
}

/** Third-party origins queried per page, so a page with hundreds of trackers stays bounded. */
export const MAX_THIRD_PARTY_COOKIE_QUERIES = 25;

function normalizeSameSite(value: string | undefined): CookieSameSite {
  if (value === 'no_restriction' || value === 'lax' || value === 'strict') return value;
  return 'unspecified';
}

/** Stable identity of a cookie within the browser's stores, used to deduplicate merged queries. */
export function cookieKey(record: Pick<CookieRecord, 'storeId' | 'domain' | 'path' | 'name'>): string {
  return `${record.storeId}|${record.domain.toLowerCase()}|${record.path}|${record.name}`;
}

/**
 * Raw cookie -> metadata record. This function *is* the safety contract: it destructures the
 * value away and copies nothing else from it, so a record can never carry the secret.
 */
export function toCookieRecord(raw: RawCookie, pageHostname: string, observedOrigin?: string): CookieRecord {
  // SAFETY: `value` is read here only for its length, then dropped. It is never stored,
  // logged or transmitted; no downstream type even has a place to put it.
  const valueLength = typeof raw.value === 'string' ? raw.value.length : 0;

  const host = raw.domain.startsWith('.') ? raw.domain.slice(1) : raw.domain;
  const firstParty = host !== '' && !isThirdPartyTo(pageHostname, host);

  const record: CookieRecord = {
    name: raw.name,
    domain: raw.domain,
    hostOnly: raw.hostOnly === true,
    path: raw.path,
    secure: raw.secure === true,
    httpOnly: raw.httpOnly === true,
    sameSite: normalizeSameSite(raw.sameSite),
    session: raw.session !== false && raw.expirationDate === undefined,
    storeId: raw.storeId ?? '0',
    valueLength,
    firstParty,
  };
  if (raw.session === false && typeof raw.expirationDate === 'number') {
    record.expirationDate = raw.expirationDate;
  }
  if (observedOrigin !== undefined) record.observedOrigin = observedOrigin;
  return record;
}

/** Merges two enumeration passes, dropping duplicates (same store, domain, path and name). */
export function mergeCookieRecords(
  existing: readonly CookieRecord[],
  incoming: readonly CookieRecord[],
): CookieRecord[] {
  const merged = new Map<string, CookieRecord>();
  for (const record of existing) merged.set(cookieKey(record), record);
  for (const record of incoming) {
    const key = cookieKey(record);
    if (!merged.has(key)) merged.set(key, record);
  }
  return Array.from(merged.values());
}

/**
 * Enumerates cookies for a page URL plus the third-party origins the tracker observer found.
 * Pure with respect to its inputs; the API is passed in so tests can stub the cookie store.
 */
export async function observeCookies(
  pageUrl: string,
  pageHostname: string,
  thirdPartyOrigins: readonly string[],
  api: CookiesApi,
): Promise<CookieRecord[]> {
  const own = (await api.getAll({ url: pageUrl })) ?? [];
  let records: CookieRecord[] = own.map((raw) => toCookieRecord(raw, pageHostname));

  const thirdParty = thirdPartyOrigins
    .filter((origin) => origin !== '' && isThirdPartyTo(pageHostname, origin))
    .slice(0, MAX_THIRD_PARTY_COOKIE_QUERIES);

  for (const origin of thirdParty) {
    const rawCookies = (await api.getAll({ domain: origin })) ?? [];
    records = mergeCookieRecords(records, rawCookies.map((raw) => toCookieRecord(raw, pageHostname, origin)));
  }

  return records;
}

/** Default deps against the real browser APIs; tests override both halves. */
export function createCookieObserverDeps(overrides: Partial<CookieObserverDeps> = {}): CookieObserverDeps {
  return {
    cookies: {
      getAll: (details) => browser.cookies.getAll(details) as Promise<RawCookie[]>,
    },
    getTabUrl: async (tabId) => {
      try {
        const tab = (await browser.tabs.get(tabId)) as { url?: string } | undefined;
        return tab?.url ?? null;
      } catch {
        return null;
      }
    },
    ...overrides,
  };
}

/**
 * `getCookiesForTab` — the background's entry point.
 *
 * Returns the cookie records for the tab, or `null` when enumeration was impossible (the tab
 * has no URL, or the cookie API failed). `null` means "could not look", which the caller
 * records as `cookiesCollected: false` — never as "no cookies" (see D-006).
 */
export async function getCookiesForTab(
  tabId: number,
  thirdPartyOrigins: readonly string[],
  deps: CookieObserverDeps = createCookieObserverDeps(),
): Promise<CookieRecord[] | null> {
  try {
    const url = await deps.getTabUrl(tabId);
    if (url === null || url === '') return null;
    return await observeCookies(url, hostnameOf(url), thirdPartyOrigins, deps.cookies);
  } catch {
    return null;
  }
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}


