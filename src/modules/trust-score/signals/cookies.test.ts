/**
 * Cookie signal tests (Task 2.6.4).
 *
 * The five verdicts the brief names are each pinned: zero cookies measures clean
 * (COOKIES_NONE_OR_ESSENTIAL), one or two tracking cookies are a mild finding
 * (COOKIES_TRACKING_PRESENT), three or more are heavy (COOKIES_TRACKING_HEAVY), third-party
 * cookies are their own finding (COOKIES_THIRD_PARTY_PRESENT), a year-plus lifetime is
 * COOKIES_LONG_PERSISTENCE — and "cookies were not collected" stays `measured: null`, never a
 * clean bill (D-006).
 */

import { describe, expect, it } from 'vitest';
import { buildAnalysisContext } from '../../../shared/analysis';
import type { PageObservation } from '../../../shared/observation';
import type { CookieRecord } from '../../../core/types';
import { cookieAnalyzer, LONG_PERSISTENCE_DAYS } from './cookies';

const NOW = 1_700_000_000_000;
const DAY = 86_400_000;

function record(overrides: Partial<CookieRecord> = {}): CookieRecord {
  return {
    name: 'theme',
    domain: 'shop.example.com',
    hostOnly: true,
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'lax',
    session: true,
    storeId: '0',
    valueLength: 0,
    firstParty: true,
    ...overrides,
  };
}

function observation(overrides: Partial<PageObservation> = {}): PageObservation {
  return {
    observationId: 'obs-1',
    tabId: 7,
    frameId: 0,
    url: 'https://shop.example.com/',
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 900,
    updatedAt: NOW,
    mainDocument: {
      url: 'https://shop.example.com/',
      statusCode: 200,
      statusLine: 'HTTP/1.1 200 OK',
      serverIp: null,
      fromCache: false,
      headers: [],
      tls: null,
    },
    requests: [],
    requestsTruncated: false,
    resourcesCollected: true,
    dom: null,
    warnings: [],
    ...overrides,
  };
}

function run(context: ReturnType<typeof buildAnalysisContext>) {
  const byId = new Map(cookieAnalyzer.analyze(context).map((a) => [a.signalId, a]));
  return {
    tracking: byId.get('cookies.tracking'),
    thirdParty: byId.get('cookies.third-party'),
    persistence: byId.get('cookies.persistence'),
  };
}

describe('cookieAnalyzer', () => {
  it('emits all three signals', () => {
    const result = run(buildAnalysisContext(observation({ cookies: [], cookiesCollected: true }), NOW));
    expect(result.tracking).toBeDefined();
    expect(result.thirdParty).toBeDefined();
    expect(result.persistence).toBeDefined();
  });

  it('reports COOKIES_NONE_OR_ESSENTIAL for zero cookies', () => {
    const result = run(buildAnalysisContext(observation({ cookies: [], cookiesCollected: true }), NOW));

    expect(result.tracking?.measured).toBe(100);
    expect(result.tracking?.detail).toContain('essential');
    // No third-party cookies, nothing long-lived: the other two signals are clean too.
    expect(result.thirdParty?.measured).toBe(100);
    expect(result.persistence?.measured).toBe(100);
  });

  it('reports COOKIES_TRACKING_PRESENT for one tracking cookie (mild)', () => {
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: [
            record({ name: '_ga', domain: '.google-analytics.com', firstParty: false }),
            record({ name: 'csrftoken' }),
          ],
        }),
        NOW,
      ),
    );

    expect(result.tracking?.measured).toBe(75);
    expect(result.tracking?.detail).toContain('1 tracking cookie');
    // The plain-language line the brief asks for.
    expect(result.tracking?.detail).toContain('_ga from Google Analytics');
    expect(result.tracking?.detail).toContain('is used for analytics');
  });

  it('reports COOKIES_TRACKING_PRESENT for two tracking cookies (still mild)', () => {
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: [
            record({ name: '_ga', domain: '.google-analytics.com', firstParty: false }),
            record({ name: '_fbp', domain: '.facebook.com', firstParty: false }),
          ],
        }),
        NOW,
      ),
    );

    expect(result.tracking?.measured).toBe(75);
  });

  it('reports COOKIES_TRACKING_HEAVY for six tracking cookies (strong negative)', () => {
    const trackingNames = ['_ga', '_gid', '_fbp', 'fr', '_uetvid', 'ajs_anonymous_id'];
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: trackingNames.map((name, index) =>
            record({
              name,
              domain: `.vendor${index}.com`,
              firstParty: false,
              session: false,
              expirationDate: (NOW + 30 * DAY) / 1000,
            }),
          ),
        }),
        NOW,
      ),
    );

    expect(result.tracking?.measured).toBeLessThanOrEqual(60);
    expect(result.tracking?.measured).toBeGreaterThanOrEqual(0);
    expect(result.tracking?.detail).toContain('6 tracking cookies detected');
  });

  it('reports COOKIES_THIRD_PARTY_PRESENT when third-party cookies exist', () => {
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: [
            record({ name: 'local', firstParty: true }),
            record({ name: '_ga', domain: '.google-analytics.com', firstParty: false }),
            record({ name: '_fbp', domain: '.facebook.com', firstParty: false }),
          ],
        }),
        NOW,
      ),
    );

    expect(result.thirdParty?.measured).toBeLessThan(100);
    expect(result.thirdParty?.detail).toContain('2 third-party cookies');
    // The tracking signal still measures the mild deduction alongside.
    expect(result.tracking?.measured).toBe(75);
  });

  it('reports COOKIES_LONG_PERSISTENCE for a cookie that outlives a year', () => {
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: [
            record({ name: 'local', firstParty: true }),
            record({
              name: '_ga',
              domain: '.google-analytics.com',
              firstParty: false,
              session: false,
              expirationDate: (NOW + (LONG_PERSISTENCE_DAYS + 1) * DAY) / 1000,
            }),
          ],
        }),
        NOW,
      ),
    );

    expect(result.persistence?.measured).toBe(75);
    expect(result.persistence?.detail).toContain('_ga');
    expect(result.persistence?.detail).toContain('366 days');
  });

  it('keeps a year-long cookie just under the persistence finding', () => {
    const result = run(
      buildAnalysisContext(
        observation({
          cookiesCollected: true,
          cookies: [
            record({ name: '_ga', session: false, expirationDate: (NOW + LONG_PERSISTENCE_DAYS * DAY) / 1000 }),
          ],
        }),
        NOW,
      ),
    );

    expect(result.persistence?.measured).toBe(100);
  });

  it('reports measured null for every signal when cookies were never collected', () => {
    const result = run(buildAnalysisContext(observation({ cookies: undefined, cookiesCollected: false }), NOW));

    expect(result.tracking?.measured).toBeNull();
    expect(result.thirdParty?.measured).toBeNull();
    expect(result.persistence?.measured).toBeNull();
    expect(result.tracking?.confidence).toBe('unavailable');
  });
});


