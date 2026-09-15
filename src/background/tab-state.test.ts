/**
 * Tab state tests.
 *
 * This is the ordering logic between two asynchronous collectors, so the tests are about the
 * cases that would misinform a user rather than about arithmetic:
 *
 *   - a report for a page the tab has already left must not be scored against the new page;
 *   - a response header list must arrive with the security headers it promises, and must not lose
 *     the headers the "absent header" findings are drawn from;
 *   - a page with no report yet must be reported as *unmeasured*, never as clean (D-006).
 */

import { describe, expect, it } from 'vitest';
import {
  SECURITY_HEADERS,
  applyContentReport,
  applyHeaderObservation,
  buildObservation,
  createTabState,
  hasContentReport,
  isAnalysableUrl,
  selectResponseHeaders,
  sessionKey,
  type TabState,
} from './tab-state';
import type { ContentReport } from '../shared/messages';

const NOW = 1_700_000_000_000;
const URL = 'https://shop.example.com/checkout?token=secret';

function state(overrides: Partial<TabState> = {}): TabState {
  return { ...createTabState(7, URL, 'obs-1', NOW - 500), ...overrides };
}

function report(overrides: Partial<ContentReport> = {}): ContentReport {
  return {
    type: 'sentinel:report',
    url: URL,
    dom: null,
    resourceTimings: [],
    resourcesCollected: true,
    ...overrides,
  };
}

describe('sessionKey', () => {
  it('namespaces the tab id so nothing else can collide with it', () => {
    expect(sessionKey(7)).toBe('sentinel:tab:7');
    expect(sessionKey(1)).not.toBe(sessionKey(2));
  });
});

describe('isAnalysableUrl', () => {
  it('accepts web pages and rejects everything else', () => {
    expect(isAnalysableUrl('https://shop.example.com/')).toBe(true);
    expect(isAnalysableUrl('http://shop.example.com/')).toBe(true);
    expect(isAnalysableUrl('chrome://extensions')).toBe(false);
    expect(isAnalysableUrl('about:blank')).toBe(false);
    expect(isAnalysableUrl('file:///c:/tmp/page.html')).toBe(false);
    expect(isAnalysableUrl('')).toBe(false);
    expect(isAnalysableUrl(null)).toBe(false);
  });
});

describe('selectResponseHeaders', () => {
  it('lower-cases names, puts the promised security headers first and keeps the rest', () => {
    const headers = selectResponseHeaders(
      [
        { name: 'Server', value: 'nginx/1.25.3' },
        { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
        { name: 'X-Powered-By', value: 'Express' },
        { name: 'content-security-policy', value: "default-src 'self'" },
      ],
      120,
      2048,
    );

    expect(headers.slice(0, 2).map((header) => header.name)).toEqual([
      'content-security-policy',
      'strict-transport-security',
    ]);
    // The banners survive: `headers.information-leakage` reads exactly these.
    expect(headers.map((header) => header.name)).toContain('server');
    expect(headers.map((header) => header.name)).toContain('x-powered-by');
  });

  it('drops nameless and valueless entries rather than reporting empty headers', () => {
    const headers = selectResponseHeaders(
      [
        { name: '', value: 'x' },
        { name: 'x-empty', value: '' },
        { name: 'ok', value: 'yes' },
      ],
      120,
      2048,
    );

    expect(headers).toEqual([{ name: 'ok', value: 'yes' }]);
  });

  it('caps the list but never loses a security header to the cap', () => {
    const many = Array.from({ length: 200 }, (_, index) => ({ name: `x-filler-${index}`, value: 'x' }));
    const headers = selectResponseHeaders(
      [...many, { name: 'strict-transport-security', value: 'max-age=1' }],
      SECURITY_HEADERS.length + 2,
      2048,
    );

    expect(headers).toHaveLength(SECURITY_HEADERS.length + 2);
    expect(headers.some((header) => header.name === 'strict-transport-security')).toBe(true);
  });

  it('truncates an over-long header value instead of carrying it', () => {
    const headers = selectResponseHeaders([{ name: 'x-long', value: 'a'.repeat(5000) }], 120, 64);
    expect(headers[0]?.value).toHaveLength(64);
  });

  it('tolerates a missing header list', () => {
    expect(selectResponseHeaders(undefined, 120, 2048)).toEqual([]);
  });
});
describe('applyHeaderObservation', () => {
  it('stores the response on the tab it belongs to', () => {
    const next = applyHeaderObservation(
      state(),
      {
        url: URL,
        statusCode: 200,
        statusLine: 'HTTP/1.1 200 OK',
        serverIp: '203.0.113.7',
        fromCache: false,
        headers: [{ name: 'strict-transport-security', value: 'max-age=31536000' }],
        tls: null,
      },
      'obs-1',
      NOW,
    );

    expect(next.mainDocument?.statusCode).toBe(200);
    expect(next.mainDocument?.headers).toHaveLength(1);
    expect(next.startedAt).toBe(NOW - 500);
    expect(next.updatedAt).toBe(NOW);
  });

  it('restarts on the new URL when the tab has navigated, so findings are not misattributed', () => {
    const withOldReport = applyContentReport(state(), report(), NOW);
    expect(hasContentReport(withOldReport)).toBe(true);

    const next = applyHeaderObservation(
      withOldReport,
      {
        url: 'https://other.example.net/',
        statusCode: 200,
        statusLine: 'HTTP/1.1 200 OK',
        serverIp: null,
        fromCache: false,
        headers: [],
        tls: null,
      },
      'obs-2',
      NOW + 100,
    );

    expect(next.url).toBe('https://other.example.net/');
    expect(next.report).toBeNull();
    expect(next.observationId).toBe('obs-2');
    expect(next.result).toBeNull();
  });

  it('keeps the report when only the query string changed', () => {
    const withReport = applyContentReport(state(), report(), NOW);
    const next = applyHeaderObservation(
      withReport,
      {
        url: 'https://shop.example.com/checkout?token=other',
        statusCode: 200,
        statusLine: 'HTTP/1.1 200 OK',
        serverIp: null,
        fromCache: false,
        headers: [],
        tls: null,
      },
      'obs-1',
      NOW + 50,
    );

    // Origin + path still match, so the report is still about this page.
    expect(next.report).not.toBeNull();
    expect(hasContentReport(next)).toBe(true);
  });
});

describe('applyContentReport', () => {
  it('accepts a report for the current page', () => {
    const next = applyContentReport(state(), report(), NOW);
    expect(hasContentReport(next)).toBe(true);
    expect(next.updatedAt).toBe(NOW);
  });

  it('ignores a report from a page the tab has already left', () => {
    const before = state();
    const after = applyContentReport(before, report({ url: 'https://old.example.net/' }), NOW);

    expect(after).toBe(before);
    expect(hasContentReport(after)).toBe(false);
  });

  it('accepts a report whose fragment differs, because that is still the same document', () => {
    const next = applyContentReport(state(), report({ url: `${URL}#step-two` }), NOW);
    expect(hasContentReport(next)).toBe(true);
  });
});
describe('buildObservation', () => {
  const headerInput = {
    url: URL,
    statusCode: 200,
    statusLine: 'HTTP/1.1 200 OK',
    serverIp: '203.0.113.7',
    fromCache: false,
    headers: [{ name: 'content-security-policy', value: "default-src 'self'" }],
    tls: null,
  };

  it('reports the page as unmeasured before the content script answers', () => {
    const withHeaders = applyHeaderObservation(state(), headerInput, 'obs-1', NOW);
    const observation = buildObservation(withHeaders, NOW);

    expect(observation.resourcesCollected).toBe(false);
    expect(observation.dom).toBeNull();
    expect(observation.resourceTimings).toEqual([]);
    expect(observation.warnings.join(' ')).toContain('still running');
    // The response itself is already known, which is what lets the popup show a score at once.
    expect(observation.mainDocument?.statusCode).toBe(200);
  });

  it('carries the report once it arrives, and says so', () => {
    const withReport = applyContentReport(
      applyHeaderObservation(state(), headerInput, 'obs-1', NOW),
      report({
        resourcesCollected: true,
        resourceTimings: [
          {
            url: 'https://www.google-analytics.com/analytics.js',
            hostname: 'www.google-analytics.com',
            origin: 'https://www.google-analytics.com',
            initiatorType: 'script',
            transferSize: 100,
            durationMs: 5,
            thirdParty: true,
          },
        ],
      }),
      NOW + 200,
    );
    const observation = buildObservation(withReport, NOW + 200);

    expect(observation.resourcesCollected).toBe(true);
    expect(observation.resourceTimings).toHaveLength(1);
    expect(observation.warnings).toEqual([]);
    expect(observation.hostname).toBe('shop.example.com');
    expect(observation.origin).toBe('https://shop.example.com');
  });

  it('refuses to claim resources were collected when the content script could not read them', () => {
    const withReport = applyContentReport(
      state(),
      report({ resourcesCollected: false, resourceTimings: [] }),
      NOW,
    );

    expect(buildObservation(withReport, NOW).resourcesCollected).toBe(false);
  });

  it('warns that nothing was observed when the response was never seen', () => {
    const observation = buildObservation(state(), NOW);

    expect(observation.mainDocument).toBeNull();
    expect(observation.resourcesCollected).toBe(false);
    expect(observation.warnings.join(' ')).toContain('did not observe this page load');
  });

  it('keeps the real URL in the observation so reports can be matched to the page', () => {
    // `TrustEngine` strips the query string before *storing* the URL; the observation itself keeps
    // it, because that is what a content-script report is matched against.
    const observation = buildObservation(state(), NOW);
    expect(observation.url).toBe(URL);
    expect(observation.observationId).toBe('obs-1');
    expect(observation.frameId).toBe(0);
    expect(observation.tabId).toBe(7);
  });
});