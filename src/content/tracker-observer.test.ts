/**
 * Tracker observer tests.
 *
 * D-001 makes `performance.getEntriesByType('resource')` the source of truth for third-party
 * detection, so this file is about the rules that decide what reaches the analysers: the navigation
 * entry is dropped (the background observes the document), duplicate URLs are collapsed, the buffer
 * is capped, and "third party" is decided once here rather than twice in two analysers.
 */

import { describe, expect, it } from 'vitest';
import {
  MAX_RESOURCE_ENTRIES,
  collectResourceTimings,
  isMixedContent,
  thirdPartyOrigins,
  type PerformanceEntryLike,
} from './tracker-observer';

const PAGE_HOST = 'shop.example.com';

function entry(name: string, initiatorType = 'script', overrides: Partial<PerformanceEntryLike> = {}): PerformanceEntryLike {
  return { name, initiatorType, transferSize: 1000, duration: 21.7, ...overrides };
}

describe('collectResourceTimings', () => {
  it('maps a timing entry onto a record, rounding the duration and keeping the transfer size', () => {
    const { records, truncated } = collectResourceTimings(
      [entry('https://cdn.example.net/app.js', 'script', { transferSize: 2048, duration: 12.6 })],
      PAGE_HOST,
    );

    expect(truncated).toBe(false);
    expect(records).toEqual([
      {
        url: 'https://cdn.example.net/app.js',
        hostname: 'cdn.example.net',
        origin: 'https://cdn.example.net',
        initiatorType: 'script',
        transferSize: 2048,
        durationMs: 13,
        thirdParty: true,
      },
    ]);
  });

  it('marks a same-host resource as first-party', () => {
    const { records } = collectResourceTimings([entry('https://shop.example.com/app.js')], PAGE_HOST);
    expect(records[0]?.thirdParty).toBe(false);
  });

  it('drops the navigation entry, which the background already observes', () => {
    const { records } = collectResourceTimings(
      [
        entry('https://shop.example.com/checkout', 'navigation'),
        entry('https://shop.example.com/app.js'),
      ],
      PAGE_HOST,
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.url).toBe('https://shop.example.com/app.js');
  });

  it('collapses duplicate URLs, keeping the first occurrence', () => {
    const { records } = collectResourceTimings(
      [
        entry('https://cdn.example.net/app.js', 'script', { duration: 10 }),
        entry('https://cdn.example.net/app.js', 'script', { duration: 99 }),
        entry('https://cdn.example.net/app.js', 'fetch', { duration: 50 }),
      ],
      PAGE_HOST,
    );

    expect(records).toHaveLength(1);
    expect(records[0]?.durationMs).toBe(10);
  });

  it('skips entries with no URL, because they cannot be classified', () => {
    const { records } = collectResourceTimings([entry(''), entry('https://cdn.example.net/app.js')], PAGE_HOST);
    expect(records).toHaveLength(1);
  });

  it('tolerates a missing initiator type and a missing transfer size', () => {
    const { records } = collectResourceTimings(
      [{ name: 'https://cdn.example.net/app.js' }],
      PAGE_HOST,
    );

    expect(records[0]?.initiatorType).toBe('other');
    expect(records[0]?.transferSize).toBeNull();
    expect(records[0]?.durationMs).toBe(0);
  });

  it('caps the buffer and says so, rather than letting a hostile page bloat the report', () => {
    const entries = Array.from({ length: MAX_RESOURCE_ENTRIES + 25 }, (_, index) =>
      entry(`https://cdn.example.net/asset-${index}.js`),
    );
    const { records, truncated } = collectResourceTimings(entries, PAGE_HOST);

    expect(records).toHaveLength(MAX_RESOURCE_ENTRIES);
    expect(truncated).toBe(true);
  });

  it('returns nothing for an empty buffer without claiming it was truncated', () => {
    expect(collectResourceTimings([], PAGE_HOST)).toEqual({ records: [], truncated: false });
  });
});

describe('thirdPartyOrigins', () => {
  it('lists distinct third-party origins, sorted, and never the page itself', () => {
    const { records } = collectResourceTimings(
      [
        entry('https://cdn.example.net/app.js'),
        entry('https://cdn.example.net/style.css', 'link'),
        entry('https://other.example.org/pixel.gif', 'img'),
        entry('https://shop.example.com/own.js'),
      ],
      PAGE_HOST,
    );

    expect(thirdPartyOrigins(records, 'https://shop.example.com')).toEqual([
      'https://cdn.example.net',
      'https://other.example.org',
    ]);
  });

  it('treats the same host on a different scheme as a different origin', () => {
    const { records } = collectResourceTimings(
      [entry('https://cdn.example.net/a.js'), entry('http://cdn.example.net/b.js')],
      PAGE_HOST,
    );

    expect(thirdPartyOrigins(records, 'https://shop.example.com')).toEqual([
      'http://cdn.example.net',
      'https://cdn.example.net',
    ]);
  });

  it('returns nothing when the page contacted only its own origin', () => {
    const { records } = collectResourceTimings([entry('https://shop.example.com/own.js')], PAGE_HOST);
    expect(thirdPartyOrigins(records, 'https://shop.example.com')).toEqual([]);
  });
});

describe('isMixedContent', () => {
  it('is true only for an HTTP resource on an HTTPS page', () => {
    const { records } = collectResourceTimings(
      [entry('http://cdn.example.net/a.js'), entry('https://cdn.example.net/b.js')],
      PAGE_HOST,
    );

    expect(isMixedContent(records[0]!, 'https')).toBe(true);
    expect(isMixedContent(records[1]!, 'https')).toBe(false);
    // On an HTTP page every resource is insecure, so mixed content is not a distinguishable fact.
    expect(isMixedContent(records[0]!, 'http')).toBe(false);
  });
});