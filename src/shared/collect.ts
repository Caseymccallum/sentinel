/**
 * Turning raw observations into analysable ones.
 *
 * Phase 1 has two collectors: the background service worker observes the main document over
 * `webRequest`, and a content script reads the page's own `performance` buffer. D-001 makes the
 * Performance API the source of truth for third-party detection, but `AnalysisContext.requests`
 * is what every analyser reads, so the timings have to land in the same shape.
 *
 * That conversion happens here, once, as a pure function: `buildAnalysisContext` folds the
 * timings into the request summary, so no analyser has to know which collector produced a
 * record and no caller can double-count by folding them a second time.
 *
 * `performance` reports an `initiatorType`, not the browser's `ResourceType`, so the mapping
 * below is deliberately conservative: anything ambiguous becomes `other` rather than guessing a
 * kind that would change how a finding reads.
 */

import type { RequestKind, RequestRecord, ResourceTimingRecord } from './observation';

const KIND_BY_INITIATOR: Readonly<Record<string, RequestKind>> = {
  navigation: 'main_frame',
  iframe: 'sub_frame',
  script: 'script',
  link: 'stylesheet',
  img: 'image',
  image: 'image',
  imageset: 'image',
  input: 'image',
  'video-poster': 'image',
  fetch: 'xmlhttprequest',
  xmlhttprequest: 'xmlhttprequest',
  beacon: 'ping',
  ping: 'ping',
  audio: 'media',
  video: 'media',
  track: 'media',
};

/** Normalises an `initiatorType` into Sentinel's request vocabulary. */
export function requestKindForInitiatorType(initiatorType: string | null | undefined): RequestKind {
  const key = (initiatorType ?? '').trim().toLowerCase();
  if (key === '') return 'other';
  return KIND_BY_INITIATOR[key] ?? 'other';
}

/**
 * One `ResourceTimingRecord` as a `RequestRecord`.
 *
 * `requestId` is synthesised and prefixed `perf-` so a record that came from the page's own
 * timing buffer is identifiable in evidence, which is where the two collectors disagree.
 * `statusCode` and `fromCache` are genuinely unknown here - the Performance API does not report
 * them - so they are `null`/`false` rather than a made-up success.
 */
export function requestRecordFromTiming(record: ResourceTimingRecord, index = 0): RequestRecord {
  return {
    requestId: `perf-${index}-${record.hostname}`,
    url: record.url,
    hostname: record.hostname,
    thirdParty: record.thirdParty,
    kind: requestKindForInitiatorType(record.initiatorType),
    initiatorHostname: null,
    statusCode: null,
    fromCache: false,
  };
}

/**
 * Folds a content script's resource timings into request records, in the order the page
 * fetched them. Unparseable entries (`hostname === ''`) are dropped: a record with no host
 * cannot be classified as first- or third-party, so it would only skew the counts.
 */
export function requestsFromResourceTimings(
  timings: readonly ResourceTimingRecord[] | undefined,
): RequestRecord[] {
  if (!timings || timings.length === 0) return [];
  const records: RequestRecord[] = [];
  for (const timing of timings) {
    if (timing.hostname === '' || timing.url === '') continue;
    records.push(requestRecordFromTiming(timing, records.length));
  }
  return records;
}

/** Every request Sentinel knows about: the background's records plus the page's own timings. */
export function mergeRequests(
  requests: readonly RequestRecord[] | undefined,
  timings: readonly ResourceTimingRecord[] | undefined,
): RequestRecord[] {
  const merged = [...(requests ?? [])];
  merged.push(...requestsFromResourceTimings(timings));
  return merged;
}