/**
 * Tracker observation from the page's own resource timings.
 *
 * See D-001 in `docs/ARCHITECTURE.md`: Sentinel reads what the page actually fetched rather
 * than installing a request filter, so there is no `declarativeNetRequest`, no extra
 * permission and no blocklist to keep in sync with the network.
 *
 * `performance.getEntriesByType('resource')` reports every subresource the page loaded once
 * it has finished loading, including the ones a ruleset would have missed: hosts reached
 * from inline scripts, dynamically inserted tags, CSS `url()` values and XHR beacons. It
 * cannot report what a *blocked* request would have been - which is exactly the trade-off
 * D-001 makes deliberately, because Sentinel never blocks.
 *
 * Nothing here reads page content, storage or input; the only input is the timing buffer.
 */

import { hostnameOf, isSecureUrl, originOf } from '../shared/urls';
import type { ResourceTimingRecord } from '../shared/observation';

/** The slice of `PerformanceResourceTiming` this collector needs (fake-able in tests). */
export interface PerformanceEntryLike {
  name: string;
  initiatorType?: string;
  transferSize?: number;
  duration?: number;
}

/**
 * Performance buffers are per-document and unbounded in hostile pages, so the collector
 * caps what it will carry into the analysis. 500 entries covers real sites comfortably;
 * beyond that the marginal host is almost certainly an ad auction loop.
 */
export const MAX_RESOURCE_ENTRIES = 500;

function toRecord(entry: PerformanceEntryLike, pageHostname: string): ResourceTimingRecord | null {
  const hostname = hostnameOf(entry.name);
  if (hostname === '') return null;

  return {
    url: entry.name,
    hostname,
    origin: originOf(entry.name),
    initiatorType: entry.initiatorType ?? 'other',
    transferSize: typeof entry.transferSize === 'number' ? entry.transferSize : null,
    durationMs: Math.round(typeof entry.duration === 'number' ? entry.duration : 0),
    thirdParty: hostname !== pageHostname,
  };
}

/**
 * Converts raw performance entries into analysable records.
 *
 * The navigation entry is dropped: the main document is already observed by the background
 * worker through `webRequest`, and counting it twice would inflate every request total.
 * Duplicate URLs are collapsed (the same analytics script loaded once per frame reports
 * once per frame) while keeping the first occurrence's timing.
 */
export function collectResourceTimings(
  entries: readonly PerformanceEntryLike[],
  pageHostname: string,
): { records: ResourceTimingRecord[]; truncated: boolean } {
  const seen = new Set<string>();
  const records: ResourceTimingRecord[] = [];
  let truncated = false;

  for (const entry of entries) {
    if (entry.name === '' || entry.initiatorType === 'navigation') continue;
    if (seen.has(entry.name)) continue;
    seen.add(entry.name);

    if (records.length >= MAX_RESOURCE_ENTRIES) {
      truncated = true;
      break;
    }

    const record = toRecord(entry, pageHostname);
    if (record) records.push(record);
  }

  return { records, truncated };
}

/**
 * Distinct third-party origins the page contacted, sorted for stable output.
 *
 * Origin (scheme + host + port) rather than hostname, because `https://cdn.example.com` and
 * `http://cdn.example.com` are materially different disclosures to the user.
 */
export function thirdPartyOrigins(
  records: readonly ResourceTimingRecord[],
  pageOrigin: string,
): string[] {
  const origins = new Set<string>();
  for (const record of records) {
    if (!record.thirdParty) continue;
    const origin = record.origin || originOf(record.url);
    if (origin === '' || origin === pageOrigin) continue;
    origins.add(origin);
  }
  return Array.from(origins).sort();
}

/** True when a record is an insecure subresource loaded from a secure page (mixed content). */
export function isMixedContent(record: ResourceTimingRecord, pageScheme: string): boolean {
  return pageScheme === 'https' && !isSecureUrl(record.url) && record.url.startsWith('http://');
}