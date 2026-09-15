/**
 * Analysis context: the single, immutable input to every signal analyser.
 *
 * The background worker collects a raw `PageObservation`; this module turns it into the
 * indexed, classified shape that analysers want (case-insensitive headers, third-party
 * partitioning, tracker hits). Doing it once here means every analyser agrees on what
 * "third party" and "same header" mean, and each analyser stays a small pure function.
 */

import { classifyTracker, type TrackerMatch } from './trackers';
import { mergeRequests } from './collect';
import { isThirdPartyTo, parseUrl, type ParsedUrl } from '../core/domain';
import type { ModuleId, SignalAssessment } from '../core/types';
import {
  type DomReport,
  type HeaderEntry,
  type PageObservation,
  type RequestKind,
  type RequestRecord,
} from './observation';

export interface HeaderIndex {
  /** First value for a lower-case header name, or `null`. */
  get(name: string): string | null;
  /** Every value for a header name, in the order received. */
  getAll(name: string): string[];
  has(name: string): boolean;
  /** All header names present, lower-cased and deduplicated. */
  names(): string[];
  readonly count: number;
  readonly entries: readonly HeaderEntry[];
}

/** Case-insensitive header access with duplicate preservation. */
export function buildHeaderIndex(headers: readonly HeaderEntry[] | undefined): HeaderIndex {
  const map = new Map<string, string[]>();
  for (const entry of headers ?? []) {
    const name = entry.name.trim().toLowerCase();
    if (name === '') continue;
    const bucket = map.get(name);
    if (bucket) bucket.push(entry.value);
    else map.set(name, [entry.value]);
  }

  return {
    get(name) {
      const values = map.get(name.toLowerCase());
      return values && values.length > 0 ? (values[0] as string) : null;
    },
    getAll(name) {
      return map.get(name.toLowerCase()) ?? [];
    },
    has(name) {
      return map.has(name.toLowerCase());
    },
    names() {
      return Array.from(map.keys());
    },
    get count() {
      return map.size;
    },
    entries: headers ?? [],
  };
}

export interface TrackerHit {
  hostname: string;
  match: TrackerMatch;
  requestCount: number;
  kinds: RequestKind[];
  /** True when the tracker host is not on the page's registrable domain. */
  thirdParty: boolean;
}

export interface RequestSummary {
  total: number;
  firstPartyRequests: number;
  thirdPartyRequests: number;
  /** Distinct third-party hostnames, sorted for stable output. */
  thirdPartyHosts: string[];
  firstPartyHosts: string[];
  trackers: TrackerHit[];
  trackerRequests: number;
  /** Requests for `http://` subresources from a secure page (mixed content candidates). */
  insecureSubresources: RequestRecord[];
  /** `ping` requests: `<a ping>` and `sendBeacon`. */
  beaconRequests: RequestRecord[];
  countsByKind: Record<RequestKind, number>;
  truncated: boolean;
}

const ALL_KINDS: readonly RequestKind[] = [
  'main_frame',
  'sub_frame',
  'script',
  'stylesheet',
  'image',
  'font',
  'xmlhttprequest',
  'media',
  'websocket',
  'ping',
  'other',
];

/** Partitions the observed requests into first/third party and recognises trackers. */
export function summarizeRequests(requests: readonly RequestRecord[], pageHostname: string): RequestSummary {
  const thirdPartyHosts = new Set<string>();
  const firstPartyHosts = new Set<string>();
  const trackerHits = new Map<string, TrackerHit>();
  const insecureSubresources: RequestRecord[] = [];
  const beaconRequests: RequestRecord[] = [];
  const countsByKind: Record<RequestKind, number> = Object.fromEntries(
    ALL_KINDS.map((kind) => [kind, 0]),
  ) as Record<RequestKind, number>;

  let firstPartyRequests = 0;
  let thirdPartyRequests = 0;
  let trackerRequests = 0;

  for (const request of requests) {
    const { hostname, kind } = request;
    countsByKind[kind] = (countsByKind[kind] ?? 0) + 1;

    const thirdParty = hostname === '' ? false : isThirdPartyTo(pageHostname, hostname);
    if (thirdParty) {
      thirdPartyRequests += 1;
      thirdPartyHosts.add(hostname);
    } else {
      firstPartyRequests += 1;
      if (hostname !== '') firstPartyHosts.add(hostname);
    }

    if (kind === 'ping') beaconRequests.push(request);

    if (kind !== 'main_frame' && request.url.startsWith('http://')) {
      insecureSubresources.push(request);
    }

    const match = classifyTracker(hostname);
    if (match) {
      trackerRequests += 1;
      const existing = trackerHits.get(hostname);
      if (existing) {
        existing.requestCount += 1;
        if (!existing.kinds.includes(kind)) existing.kinds.push(kind);
      } else {
        trackerHits.set(hostname, {
          hostname,
          match,
          requestCount: 1,
          kinds: [kind],
          thirdParty,
        });
      }
    }
  }

  return {
    total: requests.length,
    firstPartyRequests,
    thirdPartyRequests,
    thirdPartyHosts: Array.from(thirdPartyHosts).sort(),
    firstPartyHosts: Array.from(firstPartyHosts).sort(),
    trackers: Array.from(trackerHits.values()).sort((a, b) => b.requestCount - a.requestCount),
    trackerRequests,
    insecureSubresources,
    beaconRequests,
    countsByKind,
    truncated: false,
  };
}

/** Everything an analyser is allowed to look at. */
export interface AnalysisContext {
  observation: PageObservation;
  /** Parsed top-level URL (hostname, scheme, origin, site domain). */
  page: ParsedUrl;
  headers: HeaderIndex;
  requests: RequestSummary;
  dom: DomReport | null;
  /** Injected clock so tests are deterministic. */
  now: number;
}

/** A pluggable group of related signals, owned by exactly one module. */
export interface SignalAnalyzer {
  /** Diagnostics name, e.g. `connection`. */
  id: string;
  moduleId: ModuleId;
  /** Pure: same context in, same assessments out. Must never perform I/O. */
  analyze(context: AnalysisContext): SignalAssessment[];
}

/** Builds the analysis context from a raw observation. Pure and synchronous. */
export function buildAnalysisContext(observation: PageObservation, now: number = Date.now()): AnalysisContext {
  const page = parseUrl(observation.url);
  const headers = buildHeaderIndex(observation.mainDocument?.headers);
  // D-001: the page's own resource timings are the source of truth for third-party detection,
  // and they arrive as timings rather than request records. Folding them in here - once - means
  // every analyser sees one consistent request list and no caller can double-count by mistake.
  const requests = summarizeRequests(
    mergeRequests(observation.requests, observation.resourceTimings),
    page.hostname || observation.hostname,
  );
  requests.truncated = observation.requestsTruncated;

  return {
    observation,
    page,
    headers,
    requests,
    dom: observation.dom,
    now,
  };
}

/** True when the page's resource timings were collected (as opposed to "nobody looked"). */
export function resourcesCollected(context: AnalysisContext): boolean {
  return context.observation.resourcesCollected !== false;
}

/**
 * True when Sentinel observed *anything* about this page load: the response, the DOM, or at
 * least one request.
 *
 * This is weaker than `resourcesCollected` and answers a different question. `resourcesCollected
 * === false` means "the content script has not answered yet"; this returning `false` means "there
 * is nothing here at all" - the tab was already loaded when Sentinel started, or the page is one
 * it cannot see into. Signals that would otherwise report a clean result for an empty
 * observation (no trackers, no forms, no frames) must report `measured: null` in that case: an
 * absence of evidence is not evidence of a clean page.
 */
export function pageObserved(context: AnalysisContext): boolean {
  return (
    context.observation.mainDocument !== null ||
    context.observation.dom !== null ||
    context.requests.total > 0
  );
}

/** Convenience for analysers: response headers exist only once the document responded. */
export function hasResponseHeaders(context: AnalysisContext): boolean {
  return context.observation.mainDocument !== null && context.headers.count > 0;
}
