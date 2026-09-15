/**
 * Raw observation shapes.
 *
 * The background service worker observes traffic the page *already* made (via
 * `webRequest`) and a content script inspects the DOM. Both feed a `PageObservation`,
 * which is the only input to analysis. Nothing here contains verdicts — scoring is
 * deliberately separated from collection so every measurement is auditable.
 */

import type { CertificateFacts, CookieRecord } from '../core/types';

/** Normalised resource kinds (mapped from the browser's `ResourceType`). */
export type RequestKind =
  | 'main_frame'
  | 'sub_frame'
  | 'script'
  | 'stylesheet'
  | 'image'
  | 'font'
  | 'xmlhttprequest'
  | 'media'
  | 'websocket'
  /** `<a ping>` and `navigator.sendBeacon()` — the browser reports both as `ping`. sentinel-allow-local-only */
  | 'ping'
  | 'other';

export interface HeaderEntry {
  /** Lower-case header name. */
  name: string;
  value: string;
}

export type TlsState = 'secure' | 'insecure' | 'broken' | 'unknown';
export type TlsSource = 'event-security-info' | 'get-security-info' | 'none';

export interface TlsObservation {
  state: TlsState;
  /** Negotiated protocol when the browser exposes it; `null` when it does not. */
  protocol: string | null;
  source: TlsSource;
  certificate: CertificateFacts | null;
}

/** The top-level document: the only request whose headers Sentinel scores today. */
export interface MainDocumentObservation {
  url: string;
  statusCode: number | null;
  statusLine: string | null;
  serverIp: string | null;
  fromCache: boolean;
  /** Response headers, lower-cased names, duplicates preserved. */
  headers: HeaderEntry[];
  /** Non-null once the response is complete; `null` while still loading. */
  tls: TlsObservation | null;
}

export interface RequestRecord {
  requestId: string;
  url: string;
  hostname: string;
  /** True when the hostname is on a different registrable domain than the page. */
  thirdParty: boolean;
  kind: RequestKind;
  /** Hostname of the initiator when the browser reports a parseable one. */
  initiatorHostname: string | null;
  statusCode: number | null;
  fromCache: boolean;
  /** Effective URL after redirects, when it differs from the requested URL. */
  redirectedTo?: string;
}

export interface FormInputReport {
  type: string;
  name: string;
  hasAutocomplete: boolean;
  /** `autocomplete="off"` on a password field is a red flag, not a fix. */
  autocomplete: string | null;
}

export interface FormReport {
  /** Lower-cased action URL, or `null` when the form has no action attribute. */
  actionUrl: string | null;
  actionHostname: string | null;
  method: string;
  /** True when the form (or an ancestor) is inside a cross-origin iframe. */
  inCrossOriginFrame: boolean;
  /** True when the form is nested inside another form. */
  isNested: boolean;
  isThirdPartyAction: boolean;
  isInsecureAction: boolean;
  hasPasswordField: boolean;
  hasHiddenPasswordField: boolean;
  hasFileInput: boolean;
  hasAutocompleteDisabled: boolean;
  /** Total number of `autocomplete="off"` inputs on the form. */
  autocompleteOffCount: number;
  inputCount: number;
  inputs: FormInputReport[];
}

export interface IframeReport {
  src: string | null;
  hostname: string | null;
  isThirdParty: boolean;
  isInsecure: boolean;
  hasSandbox: boolean;
  sandboxTokens: string[];
  allowTokens: string[];
  /** True when the iframe has credentials-capable sandbox tokens enabled. */
  allowsSameOrigin: boolean;
  allowsTopNavigation: boolean;
  allowsPopups: boolean;
  allowsForms: boolean;
  title: string | null;
  visible: boolean;
}

export interface ScriptReport {
  src: string | null;
  hostname: string | null;
  isThirdParty: boolean;
  isInsecure: boolean;
  hasIntegrity: boolean;
  isAsync: boolean;
  isDefer: boolean;
  isModule: boolean;
  /** Number of `eval`/`new Function`/string-timer calls detected statically in inline script text. */
  inlineEvalSignals: number;
}

/** What the content script could see in the DOM. */
export interface DomReport {
  url: string;
  collectedAt: number;
  /** True when the page's own CSP would have blocked inline scripts (best-effort static read). */
  documentHasCspMeta: boolean;
  forms: FormReport[];
  iframes: IframeReport[];
  scripts: ScriptReport[];
  /** `http:` resources referenced from an `https:` page, deduplicated. */
  mixedContentUrls: string[];
  /** Speculative connections: `link[rel=prefetch|preload|preconnect|dns-prefetch]`. */
  speculativeUrls: string[];
  dnsPrefetchHosts: string[];
  /** Number of `<a ping="...">` links, which report clicks to a third party. */
  pingAttributeCount: number;
  inlineEventHandlerCount: number;
  inlineScriptCount: number;
  /** Element ids/names that commonly receive sensitive data. */
  sensitiveFieldNames: string[];
  passwordFieldCount: number;
  /** True when the top-level document is framed by another origin. */
  isFramed: boolean;
  targetBlankWithoutNoopener: number;
  notes: string[];
}

/**
 * One entry from the Performance API's resource timing buffer, as the content script read
 * it. `hostname`, `origin` and `thirdParty` are resolved by the collector rather than by an
 * analyser, so that "third party" cannot mean two different things in two files (see D-001).
 */
export interface ResourceTimingRecord {
  /** Absolute URL of the resource. */
  url: string;
  /** Lower-case hostname, or `''` when the URL could not be parsed. */
  hostname: string;
  /** Lower-case scheme-qualified origin, or `''` when the URL could not be parsed. */
  origin: string;
  /** `initiatorType` as the browser reported it (`script`, `img`, `fetch`, ...). */
  initiatorType: string;
  /** Transfer size in bytes when the browser exposes it; `null` when it does not. */
  transferSize: number | null;
  /** Duration in milliseconds, rounded. */
  durationMs: number;
  /** True when the resource sits on a different registrable domain than the page. */
  thirdParty: boolean;
}

/** Everything Sentinel observed about one page load. */
export interface PageObservation {
  /** Stable id assigned when the observation started. */
  observationId: string;
  tabId: number;
  /** Frame id of the top-level document (always 0 for a tab's main frame). */
  frameId: number;
  /** The top-level URL. */
  url: string;
  hostname: string;
  origin: string;
  /** Monotonic-ish start time of the navigation. */
  startedAt: number;
  updatedAt: number;
  mainDocument: MainDocumentObservation | null;
  requests: RequestRecord[];
  /** True when the request list hit the collection cap. */
  requestsTruncated: boolean;
  dom: DomReport | null;
  /**
   * Resource timings read from the Performance API by the content script, mapped onto the
   * same shape as `requests`. This is where tracker detection comes from (see D-001): the
   * page's own resource timings are an observation, not a filtering decision.
   */
  resourceTimings?: ResourceTimingRecord[];
  /**
   * `false` when the content script had not answered yet, or could not run at all
   * (browser-internal pages, extension pages). Empty `requests`/`resourceTimings` is
   * ambiguous on its own: "the page contacted nobody" and "nobody looked" are different
   * facts, and only the analysers can tell them apart with this flag. Analysers must report
   * `measured: null` when it is `false` rather than reporting a clean result.
   * Absent means `true`, so hand-built fixtures keep their original meaning.
   */
  resourcesCollected?: boolean;
  /**
   * Cookie *metadata* for this tab (never values — see D-007 and `CookieRecord`), collected by
   * the background's cookie observer: once for the page URL at `tabs.onUpdated(complete)`, and
   * again for the third-party origins the tracker observer detected once the content script
   * reports. Empty with `cookiesCollected === true` is a real "no cookies apply here".
   */
  cookies?: CookieRecord[];
  /**
   * `false`/absent when cookies were not enumerated (module disabled, non-analysable page, or
   * the observer has not run yet). Mirrors `resourcesCollected`: the cookie signals must report
   * `measured: null` rather than "no cookies" when this is false, because "nobody looked" and
   * "no cookies exist" are different facts (D-006).
   */
  cookiesCollected?: boolean;
  /** Why parts of the observation are missing (shown in the popup). */
  warnings: string[];
}

export const MAX_TRACKED_REQUESTS = 400;
export const MAX_HEADER_ENTRIES = 120;
export const MAX_HEADER_VALUE_LENGTH = 2048;