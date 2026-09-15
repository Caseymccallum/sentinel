/**
 * Response-hardening signal tests.
 *
 * Seven signals cover the headers a site uses to protect the page and its visitors. Two
 * things matter here: a missing header is only ever scored when Sentinel actually saw the
 * response (otherwise the signal reports `measured: null`, never an accusation), and a
 * header that is present but weak - a CSP full of `unsafe-inline`, `max-age=0` on HSTS,
 * `Permissions-Policy: *` - is scored as a real problem rather than a pass.
 */

import { describe, expect, it } from 'vitest';
import { headerAnalyzer } from './headers';
import { buildAnalysisContext } from '../../../shared/analysis';
import type { SignalAssessment } from '../../../core/types';
import type { DomReport, HeaderEntry, PageObservation } from '../../../shared/observation';

const NOW = 1_700_000_000_000;

function domReport(overrides: Partial<DomReport> = {}): DomReport {
  return {
    url: 'https://shop.example.com/',
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

function entries(headers: Record<string, string>): HeaderEntry[] {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

interface AnalyzeOptions {
  /** True when the page carries a `<meta http-equiv="Content-Security-Policy">`. */
  metaCsp?: boolean;
  /** False simulates a document served before Sentinel was listening (no headers at all). */
  headersCaptured?: boolean;
}

/**
 * A response Sentinel definitely captured. Using this as the default means "this header is
 * absent" tests exercise a real observation with a real header list, instead of the separate
 * "headers were never captured" path (which reports everything as unmeasurable).
 */
const DEFAULT_HEADERS: Record<string, string> = { 'x-content-type-options': 'nosniff' };

function analyze(headers: Record<string, string> = DEFAULT_HEADERS, options: AnalyzeOptions = {}): SignalAssessment[] {
  const url = 'https://shop.example.com/checkout';
  const observation: PageObservation = {
    observationId: 'obs-1',
    tabId: 1,
    frameId: 0,
    url,
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 1000,
    updatedAt: NOW,
    mainDocument: {
      url,
      statusCode: 200,
      statusLine: 'HTTP/1.1 200 OK',
      serverIp: '203.0.113.7',
      fromCache: false,
      headers: options.headersCaptured === false ? [] : entries(headers),
      tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
    },
    requests: [],
    requestsTruncated: false,
    dom: domReport({ documentHasCspMeta: options.metaCsp === true }),
    warnings: [],
  };

  return headerAnalyzer.analyze(buildAnalysisContext(observation, NOW));
}

function byId(assessments: readonly SignalAssessment[], signalId: string): SignalAssessment {
  const found = assessments.find((entry) => entry.signalId === signalId);
  if (!found) throw new Error(`no assessment for ${signalId}`);
  return found;
}

function only(
  signalId: string,
  headers: Record<string, string> = DEFAULT_HEADERS,
  options: AnalyzeOptions = {},
): SignalAssessment {
  return byId(analyze(headers, options), signalId);
}

/** The signal inventory, so the table below can be checked at a glance. */
const SIGNAL_IDS = [
  'headers.csp',
  'headers.frame-ancestors',
  'headers.content-type-protection',
  'headers.referrer-policy',
  'headers.permissions-policy',
  'headers.information-leakage',
  'headers.cross-origin-policy',
] as const;

describe('headerAnalyzer', () => {
  it('reports all seven hardening signals in order', () => {
    expect(analyze().map((entry) => entry.signalId)).toEqual([...SIGNAL_IDS]);
    expect(headerAnalyzer.id).toBe('headers');
    expect(headerAnalyzer.moduleId).toBe('trust-score');
  });

  it('reports every signal as unmeasurable when the response headers never arrived', () => {
    const assessments = analyze({ 'strict-transport-security': 'max-age=63072000' }, { headersCaptured: false });

    expect(assessments).toHaveLength(SIGNAL_IDS.length);
    for (const assessment of assessments) {
      expect(assessment.measured).toBeNull();
      expect(assessment.confidence).toBe('unavailable');
      expect(assessment.detail).toContain('were not captured');
    }
  });
});
describe('headers.csp', () => {
  it('flags a page that sends no policy at all', () => {
    const assessment = only('headers.csp');

    expect(assessment.measured).toBe(0);
    expect(assessment.confidence).toBe('high');
    expect(assessment.detail).toContain('No Content Security Policy was sent');
    expect(assessment.remediation).toBeDefined();
    expect(assessment.evidence).toContainEqual({ label: 'Content-Security-Policy', value: 'absent' });
  });

  it('notes that a meta-only policy is weaker than a header', () => {
    const assessment = only('headers.csp', { 'x-content-type-options': 'nosniff' }, { metaCsp: true });

    expect(assessment.measured).toBe(0);
    expect(assessment.confidence).toBe('medium');
    expect(assessment.detail).toContain('meta');
    expect(assessment.evidence).toContainEqual({ label: 'Meta CSP present', value: 'yes (weaker than a header)' });
  });

  it('credits a strict policy', () => {
    const assessment = only('headers.csp', { 'content-security-policy': "default-src 'self'; object-src 'none'" });

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toContain('does not permit inline or eval-based scripts');
  });

  it('reads directives whatever case they are written in', () => {
    const assessment = only('headers.csp', { 'content-security-policy': "SCRIPT-SRC 'self'; OBJECT-SRC 'none'" });

    expect(assessment.measured).toBe(100);
  });

  const cases: [string, string, number][] = [
    ['inline scripts are allowed', "script-src 'self' 'unsafe-inline'; object-src 'none'", 65],
    ['eval is allowed', "script-src 'self' 'unsafe-eval'; object-src 'none'", 70],
    ['any host may serve scripts', "default-src *; object-src 'none'", 80],
    ['there is no script-src or default-src fallback', "img-src 'self'", 67],
    ['every weakness is present', "default-src * 'unsafe-inline' 'unsafe-eval'", 7],
  ];

  it.each(cases)('scores a policy where %s', (_label, policy, expected) => {
    const assessment = only('headers.csp', { 'content-security-policy': policy });

    expect(assessment.measured).toBe(expected);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.detail).toContain('leaves gaps');
  });

  it('carries the policy and its directives into the evidence', () => {
    const policy = "default-src 'self'; object-src 'none'";
    const assessment = only('headers.csp', { 'content-security-policy': policy });

    expect(assessment.evidence).toContainEqual({ label: 'Content-Security-Policy', value: policy });
    expect(assessment.evidence).toContainEqual({ label: 'object-src', value: "'none'" });
    expect(assessment.evidence).toContainEqual({ label: 'Directive count', value: '2' });
  });
});
describe('headers.frame-ancestors', () => {
  it('flags a page that can be framed by anyone', () => {
    const assessment = only('headers.frame-ancestors');

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.detail).toContain('another site can embed this page');
    expect(assessment.evidence).toContainEqual({ label: 'X-Frame-Options', value: 'absent' });
  });

  const xfoCases: [string, number][] = [
    ['DENY', 100],
    ['SAMEORIGIN', 90],
    ['ALLOW-FROM https://partner.example', 60],
    ['nonsense', 40],
    ['DENY, SAMEORIGIN', 100],
  ];

  it.each(xfoCases)('scores X-Frame-Options: %s at %i', (value, expected) => {
    expect(only('headers.frame-ancestors', { 'x-frame-options': value }).measured).toBe(expected);
  });

  const cspCases: [string, number][] = [
    ["frame-ancestors 'none'", 100],
    ["frame-ancestors 'self'", 90],
    ['frame-ancestors https://partner.example', 60],
    ['frame-ancestors *', 30],
  ];

  it.each(cspCases)('scores a CSP %s at %i', (directive, expected) => {
    expect(only('headers.frame-ancestors', { 'content-security-policy': directive }).measured).toBe(expected);
  });

  it('takes the stronger of the two headers rather than the weaker', () => {
    const assessment = only('headers.frame-ancestors', {
      'x-frame-options': 'DENY',
      'content-security-policy': 'frame-ancestors *',
    });

    expect(assessment.measured).toBe(100);
    expect(assessment.detail).toContain('cannot be framed by other origins');
  });

  it('treats an empty frame-ancestors directive as no protection', () => {
    const assessment = only('headers.frame-ancestors', { 'content-security-policy': 'frame-ancestors' });

    expect(assessment.measured).toBe(0);
    expect(assessment.detail).toContain('can still be framed');
  });

  it('prefers frame-ancestors in its advice', () => {
    expect(only('headers.frame-ancestors', { 'x-frame-options': 'SAMEORIGIN' }).remediation).toContain(
      "frame-ancestors 'none'",
    );
  });
});
describe('headers.content-type-protection', () => {
  it('credits nosniff', () => {
    const assessment = only('headers.content-type-protection', { 'x-content-type-options': 'nosniff' });

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toContain('will not guess a different type');
  });

  it('accepts nosniff whatever case it is written in', () => {
    expect(only('headers.content-type-protection', { 'x-content-type-options': 'NOSNIFF' }).measured).toBe(100);
  });

  it('flags a missing nosniff', () => {
    const assessment = only('headers.content-type-protection', { 'referrer-policy': 'no-referrer' });

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.evidence).toContainEqual({ label: 'X-Content-Type-Options', value: 'absent' });
  });

  it('flags a header that is present but wrong', () => {
    const assessment = only('headers.content-type-protection', { 'x-content-type-options': 'max-age=0' });

    expect(assessment.measured).toBe(0);
    expect(assessment.detail).toContain('missing');
  });
});

describe('headers.referrer-policy', () => {
  const cases: [string, number][] = [
    ['no-referrer', 100],
    ['same-origin', 100],
    ['strict-origin', 100],
    ['strict-origin-when-cross-origin', 100],
    ['origin', 75],
    ['origin-when-cross-origin', 75],
    ['no-referrer-when-downgrade', 40],
    ['unsafe-url', 0],
    ['a value no browser defines', 30],
  ];

  it.each(cases)('scores %s at %i', (policy, expected) => {
    expect(only('headers.referrer-policy', { 'referrer-policy': policy }).measured).toBe(expected);
  });

  it('treats a missing policy as the browser default, not a disaster', () => {
    const assessment = only('headers.referrer-policy');

    expect(assessment.measured).toBe(60);
    expect(assessment.detail).toContain('strict-origin-when-cross-origin');
    expect(assessment.remediation).toBeDefined();
    expect(assessment.evidence).toContainEqual({ label: 'Referrer-Policy', value: 'absent' });
  });

  it('reads only the first value of a list', () => {
    expect(only('headers.referrer-policy', { 'referrer-policy': 'origin, unsafe-url' }).measured).toBe(75);
  });

  it('accepts a policy written in a different case', () => {
    expect(only('headers.referrer-policy', { 'referrer-policy': 'NO-REFERRER' }).measured).toBe(100);
  });

  it('never asks for a fix when the policy is already strict', () => {
    expect(only('headers.referrer-policy', { 'referrer-policy': 'no-referrer' }).remediation).toBeUndefined();
    expect(only('headers.referrer-policy', { 'referrer-policy': 'unsafe-url' }).remediation).toBeDefined();
  });
});
describe('headers.permissions-policy', () => {
  it('notes a missing policy without pretending it is a catastrophe', () => {
    const assessment = only('headers.permissions-policy');

    expect(assessment.measured).toBe(60);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.evidence).toContainEqual({ label: 'Permissions-Policy', value: 'absent' });
  });

  it('credits a policy that restricts several features', () => {
    const assessment = only('headers.permissions-policy', {
      'permissions-policy': 'geolocation=(self), camera=(), microphone=()',
    });

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toContain('restricts 3 browser features');
  });

  it('marks down a policy that covers only one feature', () => {
    const assessment = only('headers.permissions-policy', { 'permissions-policy': 'geolocation=(self)' });

    expect(assessment.measured).toBe(85);
    expect(assessment.detail).toContain('only a couple of features');
  });

  it('treats a wildcard as an opening rather than a restriction', () => {
    const assessment = only('headers.permissions-policy', {
      'permissions-policy': 'geolocation=*, camera=*, microphone=*',
    });

    expect(assessment.measured).toBe(60);
    expect(assessment.detail).toContain('wildcards');
    expect(assessment.evidence).toContainEqual({ label: 'Wildcards', value: '3' });
  });
});

describe('headers.information-leakage', () => {
  it('credits a server that says nothing about itself', () => {
    const assessment = only('headers.information-leakage', { 'x-content-type-options': 'nosniff' });

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
    expect(assessment.detail).toContain('No server or framework banner headers were sent');
  });

  it('marks down a banner that publishes an exact version', () => {
    const assessment = only('headers.information-leakage', { server: 'nginx/1.25.3' });

    expect(assessment.measured).toBe(60);
    expect(assessment.detail).toContain('Exact version numbers');
    expect(assessment.evidence).toContainEqual({ label: 'server', value: 'nginx/1.25.3' });
  });

  it('marks down a banner that only names the stack', () => {
    const assessment = only('headers.information-leakage', { 'x-powered-by': 'Express' });

    expect(assessment.measured).toBe(85);
    expect(assessment.detail).toContain('reveal the stack');
  });

  it('stacks the deductions when several banners are sent', () => {
    const both = only('headers.information-leakage', {
      server: 'Apache/2.4.58',
      'x-powered-by': 'PHP/8.3.2',
    });
    const mixed = only('headers.information-leakage', { server: 'Apache/2.4.58', 'x-powered-by': 'PHP' });

    expect(both.measured).toBe(20);
    expect(mixed.measured).toBe(45);
  });
});

describe('headers.cross-origin-policy', () => {
  it('flags a page that is not fenced off at all', () => {
    const assessment = only('headers.cross-origin-policy');

    expect(assessment.measured).toBe(0);
    expect(assessment.remediation).toBeDefined();
    expect(assessment.detail).toContain('not fenced off');
    expect(assessment.evidence).toContainEqual({ label: 'Cross-Origin-Embedder-Policy', value: 'absent' });
  });

  it('credits full isolation', () => {
    const assessment = only('headers.cross-origin-policy', {
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
    });

    expect(assessment.measured).toBe(100);
    expect(assessment.remediation).toBeUndefined();
  });

  it('scores partial isolation honestly', () => {
    const relaxedResource = only('headers.cross-origin-policy', {
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'cross-origin',
    });
    const resourceOnly = only('headers.cross-origin-policy', { 'cross-origin-resource-policy': 'same-site' });
    const popupsOnly = only('headers.cross-origin-policy', {
      'cross-origin-opener-policy': 'same-origin-allow-popups',
    });

    expect(relaxedResource.measured).toBe(70);
    expect(resourceOnly.measured).toBe(50);
    expect(popupsOnly.measured).toBe(30);
  });

  it('does not score the embedder policy, but still reports it', () => {
    const assessment = only('headers.cross-origin-policy', {
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
      'cross-origin-embedder-policy': 'require-corp',
    });

    expect(assessment.measured).toBe(100);
    expect(assessment.evidence).toContainEqual({ label: 'Cross-Origin-Embedder-Policy', value: 'require-corp' });
  });
});