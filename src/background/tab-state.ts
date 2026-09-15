/**
 * Per-tab collection state.
 *
 * The background worker sees a page in pieces: `webRequest` delivers the response headers (and
 * the status line) for the main frame, and a content script delivers the DOM and the page's own
 * resource timings, usually a moment later. This module is the pure part of stitching those
 * pieces into the single `PageObservation` the engine scores - no browser APIs, no timers, no
 * storage - so the ordering rules can be unit-tested without a browser.
 *
 * Two rules are worth stating outright, because getting either wrong would misinform the user:
 *
 *   1. **A report belongs to one URL.** A content script's report is only accepted while it
 *      describes the URL the tab is currently on. A stale report from the previous page would
 *      otherwise be scored against the new one (tabs navigate; messages do not have to be prompt).
 *   2. **Missing is not clean.** Until a content script answers, `resourcesCollected` is `false`
 *      and `dom` is `null`, which makes the analysers report `measured: null` rather than
 *      "no trackers, no forms". The popup renders that as "still analysing".
 */

import { parseUrl, toStoredUrl } from '../core/domain';
import type { CookieRecord, ScanResult } from '../core/types';
import { mergeCookieRecords } from './cookie-observer';
import type { ContentReport } from '../shared/messages';
import type {
  HeaderEntry,
  MainDocumentObservation,
  PageObservation,
  TlsObservation,
} from '../shared/observation';

/** The response facts `webRequest.onHeadersReceived` hands us for the main frame. */
export interface HeaderObservationInput {
  url: string;
  statusCode: number | null;
  statusLine: string | null;
  serverIp: string | null;
  fromCache: boolean;
  headers: HeaderEntry[];
  tls: TlsObservation | null;
}

export interface TabState {
  tabId: number;
  /** The URL the tab was last seen on; the identity a report must match. */
  url: string;
  startedAt: number;
  updatedAt: number;
  mainDocument: MainDocumentObservation | null;
  /** The most recent content-script report, once it matches this tab's URL. */
  report: ContentReport | null;
  /**
   * Cookie metadata collected for this tab (never values — D-007). `null` until the observer
   * has run, which is what makes `cookiesCollected` honest in the built observation.
   */
  cookies: CookieRecord[] | null;
  /** Observation id, stable across the several times one page is scored. */
  observationId: string;
  /**
   * True once this observation's scan was recorded into the domain profile (D-008: at most one
   * record per observation, however many times the page is re-scored).
   */
  profileRecorded: boolean;
  /** When the page was last scored. */
  scannedAt: number | null;
  result: ScanResult | null;
}

/** Storage key for a tab's session record. Session storage is dropped when the browser closes. */
export function sessionKey(tabId: number): string {
  return `sentinel:tab:${tabId}`;
}

/** True for the two schemes Sentinel analyses; anything else gets an `unsupported` answer. */
export function isAnalysableUrl(url: string | null | undefined): boolean {
  const scheme = parseUrl(url ?? '').scheme;
  return scheme === 'http' || scheme === 'https';
}

export function createTabState(tabId: number, url: string, observationId: string, now: number): TabState {
  return {
    tabId,
    url,
    startedAt: now,
    updatedAt: now,
    mainDocument: null,
    report: null,
    cookies: null,
    observationId,
    profileRecorded: false,
    scannedAt: null,
    result: null,
  };
}

/**
 * Folds an enumeration pass into the state, merging (not replacing) so the page-URL pass and
 * the third-party pass both survive. A navigation resets the state (and its cookies) because
 * the previous page's cookies would be misattributed to the new one.
 */
export function applyCookieRecords(state: TabState, records: readonly CookieRecord[], now: number): TabState {
  return {
    ...state,
    cookies: mergeCookieRecords(state.cookies ?? [], records),
    updatedAt: now,
  };
}

/** Origin + path, so a report survives a changed query string or fragment. */
function normalise(url: string): string {
  return toStoredUrl(url) || url;
}

/**
 * Folds a main-frame response into the state.
 *
 * A response for a different URL means the tab navigated, so the state restarts on the new URL:
 * keeping the previous page's headers would misattribute them to the page the user is on now.
 */
export function applyHeaderObservation(
  state: TabState,
  input: HeaderObservationInput,
  observationId: string,
  now: number,
): TabState {
  const navigated = normalise(state.url) !== normalise(input.url);
  const base = navigated ? createTabState(state.tabId, input.url, observationId, now) : state;

  return {
    ...base,
    url: input.url,
    updatedAt: now,
    mainDocument: {
      url: input.url,
      statusCode: input.statusCode,
      statusLine: input.statusLine,
      serverIp: input.serverIp,
      fromCache: input.fromCache,
      headers: input.headers,
      tls: input.tls,
    },
  };
}

/**
 * Folds a content-script report into the state, when it describes this tab's current URL.
 *
 * A stale report leaves the state untouched: the alternative - scoring the old page's DOM against
 * the new page's URL - would attribute findings to the wrong site, which is worse than reporting
 * nothing at all.
 */
export function applyContentReport(state: TabState, report: ContentReport, now: number): TabState {
  if (normalise(state.url) !== normalise(report.url)) return state;
  return { ...state, report, updatedAt: now };
}

/** True when the content script has answered for the URL the tab is on. */
export function hasContentReport(state: TabState): boolean {
  return state.report !== null && normalise(state.report.url) === normalise(state.url);
}
/**
 * The headers Sentinel promises to look at, in the order the popup's drill-down shows them.
 *
 * These are kept *in addition to* every other response header, not instead of them. Keeping only
 * this list would be cheaper, but it would make "no Permissions-Policy was sent" and "no
 * Cross-Origin-Resource-Policy was sent" indistinguishable from "Sentinel did not keep that
 * header" - and the analysers report absent headers as findings. A missing measurement must never
 * be dressed up as a finding, so the whole response is carried (capped).
 */
export const SECURITY_HEADERS: readonly string[] = [
  'content-security-policy',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
  'strict-transport-security',
  'x-content-type-options',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
];

/**
 * Normalises a response header list: lower-cased names, security headers first, capped.
 *
 * Ordering is cosmetic (the analysers read by name) but it is made deterministic here: the security
 * headers appear in the order `SECURITY_HEADERS` declares, and everything else keeps the order the
 * server sent it. Stable ordering keeps the popup's evidence list readable, and putting the
 * promised headers at the front means a capped list still contains them.
 */
export function selectResponseHeaders(
  headers: readonly { name: string; value?: string }[] | undefined,
  maxEntries: number,
  maxValueLength: number,
): HeaderEntry[] {
  const rank = new Map(SECURITY_HEADERS.map((name, index) => [name, index]));
  const priority: HeaderEntry[] = [];
  const rest: HeaderEntry[] = [];

  for (const header of headers ?? []) {
    const name = header.name.trim().toLowerCase();
    const value = (header.value ?? '').slice(0, maxValueLength);
    if (name === '' || value === '') continue;
    const entry: HeaderEntry = { name, value };
    if (rank.has(name)) priority.push(entry);
    else rest.push(entry);
  }

  priority.sort((a, b) => (rank.get(a.name) ?? 0) - (rank.get(b.name) ?? 0));
  return [...priority, ...rest].slice(0, maxEntries);
}

/**
 * Builds the observation to score right now.
 *
 * Called once as soon as the response headers are known (so the popup can render connection and
 * header findings immediately) and again when the content script answers (so tracker and form
 * findings arrive without the user having to reopen anything).
 */
export function buildObservation(state: TabState, now: number): PageObservation {
  const page = parseUrl(state.url);
  const report = hasContentReport(state) ? state.report : null;

  const warnings: string[] = [];
  if (state.mainDocument === null) {
    warnings.push('Sentinel did not observe this page load, so the connection and header checks were skipped.');
  }
  if (report === null) {
    warnings.push('The page report has not arrived yet, so tracker and form checks are still running.');
  }

  return {
    observationId: state.observationId,
    tabId: state.tabId,
    frameId: 0,
    url: state.url,
    hostname: page.hostname || state.url,
    origin: page.origin,
    startedAt: state.startedAt,
    updatedAt: now,
    mainDocument: state.mainDocument,
    // Phase 1 collects no request records in the background: `webRequest` request listeners would
    // add permission surface for data the page's own resource timings already carry (see D-001),
    // and `buildAnalysisContext` folds `resourceTimings` into the request summary.
    requests: [],
    requestsTruncated: false,
    dom: report?.dom ?? null,
    resourceTimings: report?.resourceTimings ?? [],
    // `false` until a report arrives: "nobody looked" must never read as "nobody was contacted".
    resourcesCollected: report !== null && report.resourcesCollected,
    // Cookie metadata rides along only when the observer actually ran; `cookies: []` with
    // `cookiesCollected: true` is a real "no cookies apply to this page".
    cookies: state.cookies ?? [],
    cookiesCollected: state.cookies !== null,
    warnings,
  };
}