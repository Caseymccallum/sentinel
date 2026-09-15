/**
 * Resource-timing → request-record mapping tests.
 *
 * `performance` reports an `initiatorType`, which is not the browser's `ResourceType`. The
 * mapping has to be predictable, and it has to be honest about what it does not know: a timing
 * record carries no status code and no cache state, so those arrive as `null`/`false` rather than
 * as a made-up success that an analyser might later trust.
 */

import { describe, expect, it } from 'vitest';
import { mergeRequests, requestKindForInitiatorType, requestRecordFromTiming, requestsFromResourceTimings } from './collect';
import type { ResourceTimingRecord } from './observation';

function timing(overrides: Partial<ResourceTimingRecord> = {}): ResourceTimingRecord {
  return {
    url: 'https://cdn.example.net/app.js',
    hostname: 'cdn.example.net',
    origin: 'https://cdn.example.net',
    initiatorType: 'script',
    transferSize: 1200,
    durationMs: 30,
    thirdParty: true,
    ...overrides,
  };
}

describe('requestKindForInitiatorType', () => {
  it('maps the initiator types a browser actually reports', () => {
    expect(requestKindForInitiatorType('script')).toBe('script');
    expect(requestKindForInitiatorType('link')).toBe('stylesheet');
    expect(requestKindForInitiatorType('img')).toBe('image');
    expect(requestKindForInitiatorType('image')).toBe('image');
    expect(requestKindForInitiatorType('fetch')).toBe('xmlhttprequest');
    expect(requestKindForInitiatorType('xmlhttprequest')).toBe('xmlhttprequest');
    expect(requestKindForInitiatorType('beacon')).toBe('ping');
    expect(requestKindForInitiatorType('iframe')).toBe('sub_frame');
    expect(requestKindForInitiatorType('navigation')).toBe('main_frame');
    expect(requestKindForInitiatorType('video')).toBe('media');
  });

  it('falls back to `other` instead of guessing a kind that would change a finding', () => {
    expect(requestKindForInitiatorType('css')).toBe('other');
    expect(requestKindForInitiatorType('object')).toBe('other');
    expect(requestKindForInitiatorType('')).toBe('other');
    expect(requestKindForInitiatorType(null)).toBe('other');
    expect(requestKindForInitiatorType(undefined)).toBe('other');
  });

  it('is case- and whitespace-insensitive', () => {
    expect(requestKindForInitiatorType('  SCRIPT ')).toBe('script');
  });
});

describe('requestsFromResourceTimings', () => {
  it('carries the facts a timing record has, and leaves the rest unknown', () => {
    const [record] = requestsFromResourceTimings([timing()]);

    expect(record).toMatchObject({
      url: 'https://cdn.example.net/app.js',
      hostname: 'cdn.example.net',
      thirdParty: true,
      kind: 'script',
      initiatorHostname: null,
      statusCode: null,
      fromCache: false,
    });
    expect(record?.requestId).toContain('perf-');
  });

  it('keeps document order and numbers each record', () => {
    const records = requestsFromResourceTimings([
      timing({ url: 'https://a.example.net/1.js', hostname: 'a.example.net' }),
      timing({ url: 'https://b.example.net/2.js', hostname: 'b.example.net' }),
    ]);

    expect(records.map((record) => record.requestId)).toEqual(['perf-0-a.example.net', 'perf-1-b.example.net']);
    expect(records.map((record) => record.hostname)).toEqual(['a.example.net', 'b.example.net']);
  });

  it('drops entries with no hostname, which cannot be classified as first- or third-party', () => {
    const records = requestsFromResourceTimings([
      timing({ url: 'data:image/png;base64,AAAA', hostname: '', origin: 'null' }),
      timing(),
      timing({ url: '', hostname: '', origin: '' }),
    ]);

    expect(records).toHaveLength(1);
    expect(records[0]?.hostname).toBe('cdn.example.net');
  });

  it('handles a missing or empty timing list without inventing a request', () => {
    expect(requestsFromResourceTimings(undefined)).toEqual([]);
    expect(requestsFromResourceTimings([])).toEqual([]);
  });
});

describe('mergeRequests', () => {
  it('appends timings after the background own records, so provenance stays readable', () => {
    const merged = mergeRequests(
      [
        {
          requestId: 'req-1',
          url: 'https://shop.example.com/',
          hostname: 'shop.example.com',
          thirdParty: false,
          kind: 'main_frame',
          initiatorHostname: null,
          statusCode: 200,
          fromCache: false,
        },
      ],
      [timing()],
    );

    expect(merged.map((record) => record.kind)).toEqual(['main_frame', 'script']);
    expect(merged).toHaveLength(2);
  });

  it('tolerates either side being missing', () => {
    expect(mergeRequests(undefined, [timing()])).toHaveLength(1);
    expect(mergeRequests([], undefined)).toEqual([]);
    expect(mergeRequests(undefined, undefined)).toEqual([]);
  });

  it('does not fold the same timing list twice', () => {
    const timings = [timing()];
    expect(mergeRequests(undefined, timings)).toHaveLength(1);
    expect(requestRecordFromTiming(timings[0] as ResourceTimingRecord, 0).kind).toBe('script');
  });
});