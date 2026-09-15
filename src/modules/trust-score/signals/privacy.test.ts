/**
 * Privacy signal tests.
 *
 * Four signals, all fed by what the content script saw the page fetch. The interesting cases are
 * the three different ways a measurement can be absent, which must never be confused with each
 * other or with a clean result:
 *
 *   - the page load was never observed at all (`pageObserved` false) -> `measured: null`;
 *   - the content script had not answered yet (`resourcesCollected: false`) -> `measured: null`;
 *   - the page was observed and contacted nobody -> `measured: 100`, because that is a fact.
 */

import { describe, expect, it } from 'vitest';
import { privacyAnalyzer } from './privacy';
import { buildAnalysisContext } from '../../../shared/analysis';
import type { SignalAssessment } from '../../../core/types';
import type {
  DomReport,
  HeaderEntry,
  PageObservation,
  RequestRecord,
  ResourceTimingRecord,
} from '../../../shared/observation';

const NOW = 1_700_000_000_000;
const URL = 'https://shop.example.com/checkout';

function domReport(overrides: Partial<DomReport> = {}): DomReport {
  return {
    url: URL,
    collectedAt: NOW - 500,
    documentHasCspMeta: false,
    forms: [],
    iframes: [],
    scripts: [],
    mixedContentUrls: [],
    speculativeUrls: [],
    dnsPrefetchHosts: [],
    pingAttributeCount: 0,
    inlineEventHandlerCount: 0,
    inlineScriptCount: 0,
    sensitiveFieldNames: [],
    passwordFieldCount: 0,
    isFramed: false,
    targetBlankWithoutNoopener: 0,
    notes: [],
    ...overrides,
  };
}

/** A resource-timing record as the content script would report it. */
function timing(hostname: string, initiatorType = 'script', path = '/tag.js'): ResourceTimingRecord {
  return {
    url: `https://${hostname}${path}`,
    hostname,
    origin: `https://${hostname}`,
    initiatorType,
    transferSize: 1200,
    durationMs: 30,
    thirdParty: hostname !== 'shop.example.com',
  };
}

function entries(headers: Record<string, string>): HeaderEntry[] {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

interface AnalyzeOptions {
  timings?: ResourceTimingRecord[];
  requests?: RequestRecord[];
  headers?: Record<string, string>;
  dom?: DomReport | null;
  /** `false` simulates a content script that has not answered yet. */
  resourcesCollected?: boolean;
  /** `false` simulates a page load Sentinel never saw (nothing at all was observed). */
  observed?: boolean;
  url?: string;
}

function analyze(options: AnalyzeOptions = {}): Record<string, SignalAssessment> {
  const url = options.url ?? URL;
  const observed = options.observed !== false;
  const observation: PageObservation = {
    observationId: 'obs-1',
    tabId: 1,
    frameId: 0,
    url,
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 1000,
    updatedAt: NOW,
    mainDocument: observed
      ? {
          url,
          statusCode: 200,
          statusLine: 'HTTP/1.1 200 OK',
          serverIp: '203.0.113.7',
          fromCache: false,
          headers: entries(options.headers ?? {}),
          tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
        }
      : null,
    requests: options.requests ?? [],
    requestsTruncated: false,
    resourceTimings: options.timings ?? [],
    resourcesCollected: options.resourcesCollected ?? observed,
    dom: options.dom === undefined ? domReport() : options.dom,
    warnings: [],
  };

  const assessments = privacyAnalyzer.analyze(buildAnalysisContext(observation, NOW));
  return Object.fromEntries(assessments.map((assessment) => [assessment.signalId, assessment]));
}

describe('privacyAnalyzer', () => {
  it('reports the four declared privacy signals and nothing else', () => {
    expect(Object.keys(analyze()).sort()).toEqual([
      'privacy.background-beacons',
      'privacy.referrer-leakage',
      'privacy.third-party-surface',
      'privacy.trackers',
    ]);
  });

  describe('privacy.trackers', () => {
    it('names the trackers it found and charges each category differently', () => {
      const results = analyze({
        timings: [
          timing('www.google-analytics.com'),
          timing('connect.facebook.net', 'script', '/fbevents.js'),
        ],
      });
      const trackers = results['privacy.trackers'];

      // 12 (analytics) + 16 (social): past the point where the popup can call it a rounding error.
      expect(trackers?.measured).toBe(72);
      expect(trackers?.confidence).toBe('high');
      expect(trackers?.detail).toContain('2 known tracker hosts');
      expect(trackers?.detail).toContain('Google Analytics (analytics)');
      expect(trackers?.detail).toContain('Meta Pixel (social)');
      expect(trackers?.evidence.some((row) => row.value.includes('Meta'))).toBe(true);
    });

    it('charges more for a host the page keeps going back to', () => {
      const once = analyze({ timings: [timing('static.hotjar.com')] });
      const repeatedly = analyze({
        timings: [
          timing('static.hotjar.com', 'script', '/a.js'),
          timing('static.hotjar.com', 'script', '/b.js'),
        ],
      });

      // 20 for session recording, +3 for contacting the host more than once.
      expect(once['privacy.trackers']?.measured).toBe(80);
      expect(repeatedly['privacy.trackers']?.measured).toBe(77);
    });

    it('still counts a tracker on the page own domain, but never calls it third-party', () => {
      // The page itself is served from google-analytics.com, so its own tag is first-party.
      // `summarizeRequests` derives third-party-ness from the hostnames, not from the record's
      // own flag, so this is exactly the case that proves the distinction is kept.
      const firstPartyTracking: ResourceTimingRecord = {
        url: 'https://www.google-analytics.com/analytics.js',
        hostname: 'www.google-analytics.com',
        origin: 'https://www.google-analytics.com',
        initiatorType: 'script',
        transferSize: 1200,
        durationMs: 30,
        thirdParty: false,
      };
      const results = analyze({ url: 'https://www.google-analytics.com/', timings: [firstPartyTracking] });
      const trackers = results['privacy.trackers'];

      // 12 for an analytics tag, and a first-party tag is still a tag.
      expect(trackers?.measured).toBe(88);
      expect(trackers?.evidence).toContainEqual({
        label: 'Third-party hosts among them',
        value: '0 of 1',
      });
    });

    it('says nothing at all was contacted when the page loaded only its own resources', () => {
      const results = analyze({ timings: [timing('shop.example.com', 'link', '/style.css')] });
      expect(results['privacy.trackers']?.measured).toBe(100);
      expect(results['privacy.trackers']?.detail).toContain('came from a known tracker');
    });

    it('reports unmeasured - not clean - while the content script is still running', () => {
      const results = analyze({ timings: [], resourcesCollected: false });

      expect(results['privacy.trackers']?.measured).toBeNull();
      expect(results['privacy.trackers']?.confidence).toBe('unavailable');
      expect(results['privacy.third-party-surface']?.measured).toBeNull();
      expect(results['privacy.trackers']?.detail).toContain('had not been collected');
    });

    it('reports unmeasured when the page load was never observed at all', () => {
      const results = analyze({ observed: false, dom: null });

      for (const signalId of Object.keys(results)) {
        expect(results[signalId]?.measured, signalId).toBeNull();
      }
    });
  });

  describe('privacy.third-party-surface', () => {
    it('charges four points per distinct third-party host', () => {
      const results = analyze({
        timings: [timing('cdn.example.net'), timing('fonts.example.org'), timing('api.example.io')],
      });

      expect(results['privacy.third-party-surface']?.measured).toBe(88);
      expect(results['privacy.third-party-surface']?.evidence).toContainEqual({
        label: 'Distinct third-party hosts',
        value: '3',
      });
    });

    it('hits the floor once a page contacts a lot of hosts', () => {
      const timings = Array.from({ length: 30 }, (_, index) => timing(`host${index}.example${index}.net`));
      expect(analyze({ timings })['privacy.third-party-surface']?.measured).toBe(0);
    });

    it('counts each host once, however many resources it serves', () => {
      const results = analyze({
        timings: [timing('cdn.example.net', 'script', '/a.js'), timing('cdn.example.net', 'link', '/b.css')],
      });

      expect(results['privacy.third-party-surface']?.measured).toBe(96);
      expect(results['privacy.third-party-surface']?.evidence).toContainEqual({
        label: 'Third-party requests',
        value: '2',
      });
    });
  });

  it('measures a clean page as clean rather than as unmeasured', () => {
    const results = analyze({ headers: { 'referrer-policy': 'no-referrer' } });

    expect(results['privacy.trackers']?.measured).toBe(100);
    expect(results['privacy.third-party-surface']?.measured).toBe(100);
    expect(results['privacy.referrer-leakage']?.measured).toBe(100);
    expect(results['privacy.background-beacons']?.measured).toBe(100);
    expect(results['privacy.trackers']?.detail).toContain('nothing on this page reported your visit elsewhere');
  });

  describe('privacy.referrer-leakage', () => {
    const thirdParty = [timing('cdn.example.net')];

    it('treats no-referrer as no leakage and unsafe-url as full-URL leakage', () => {
      const safe = analyze({ timings: thirdParty, headers: { 'referrer-policy': 'no-referrer' } });
      const unsafe = analyze({ timings: thirdParty, headers: { 'referrer-policy': 'unsafe-url' } });

      expect(safe['privacy.referrer-leakage']?.measured).toBe(100);
      expect(unsafe['privacy.referrer-leakage']?.measured).toBe(70);
      expect(unsafe['privacy.referrer-leakage']?.detail).toContain('full URL of this page');
    });

    it('charges a little for origin-only policies and more when no policy was sent', () => {
      const originOnly = analyze({
        timings: thirdParty,
        headers: { 'referrer-policy': 'strict-origin-when-cross-origin' },
      });
      // Headers were captured - they just did not include a Referrer-Policy, which is the
      // "absent" case rather than the "never captured" case.
      const absent = analyze({ timings: thirdParty, headers: { 'x-content-type-options': 'nosniff' } });

      expect(originOnly['privacy.referrer-leakage']?.measured).toBe(94);
      expect(absent['privacy.referrer-leakage']?.measured).toBe(86);
      expect(absent['privacy.referrer-leakage']?.evidence).toContainEqual({
        label: 'Referrer-Policy',
        value: 'absent',
      });
    });

    it('does not charge for a permissive policy when there is nobody to leak to', () => {
      const results = analyze({
        timings: [timing('shop.example.com', 'link', '/style.css')],
        headers: { 'referrer-policy': 'unsafe-url' },
      });

      expect(results['privacy.referrer-leakage']?.measured).toBe(100);
      expect(results['privacy.referrer-leakage']?.detail).toContain('nowhere for the URL to leak');
    });

    it('is unmeasured when the response headers were never captured', () => {
      const results = analyze({ observed: false, timings: thirdParty, dom: null });
      expect(results['privacy.referrer-leakage']?.measured).toBeNull();
    });
  });

  describe('privacy.background-beacons', () => {
    it('charges for ping/sendBeacon requests', () => {
      const results = analyze({
        requests: [
          {
            requestId: 'req-1',
            url: 'https://collect.example.net/ping',
            hostname: 'collect.example.net',
            thirdParty: true,
            kind: 'ping',
            initiatorHostname: 'shop.example.com',
            statusCode: 204,
            fromCache: false,
          },
        ],
      });

      expect(results['privacy.background-beacons']?.measured).toBe(85);
      expect(results['privacy.background-beacons']?.detail).toContain('beacon request');
    });

    it('charges for ping attributes, speculative loads and DNS prefetch hints', () => {
      const results = analyze({
        dom: domReport({
          pingAttributeCount: 2,
          speculativeUrls: ['https://cdn.example.net/preload.js'],
          dnsPrefetchHosts: ['tracker.example.org'],
        }),
      });

      // 30 (2 x ping) + 4 (speculative) + 3 (dns-prefetch)
      expect(results['privacy.background-beacons']?.measured).toBe(63);
      expect(results['privacy.background-beacons']?.detail).toContain('2 links with a ping attribute');
    });
  });
});