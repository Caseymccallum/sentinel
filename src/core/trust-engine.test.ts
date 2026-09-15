/**
 * TrustEngine tests.
 *
 * The engine is the seam between collection and everything the user sees, so these tests
 * cover both halves: a real end-to-end run over the trust-score analysers, and the failure
 * modes that must never blank a report (a disabled module, an analyser that throws, a
 * signal the scoring model has never heard of, a duplicated signal id).
 */

import { describe, expect, it } from 'vitest';
import { TRUST_SCORE_ANALYZERS } from '../modules/trust-score/signals';
import { buildAnalysisContext, type SignalAnalyzer } from '../shared/analysis';
import type { DomReport, IframeReport, PageObservation, RequestRecord } from '../shared/observation';
import type { Confidence, ModuleId, SignalAssessment } from './types';
import { TrustEngine, summarizeObservation } from './trust-engine';

const NOW = 1_700_000_000_000;

/** A response that should score well, so failures point at the engine and not the model. */
const HARDENED_HEADERS = [
  { name: 'content-security-policy', value: "default-src 'self'; object-src 'none'; frame-ancestors 'none'" },
  { name: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains' },
  { name: 'referrer-policy', value: 'strict-origin-when-cross-origin' },
  { name: 'x-content-type-options', value: 'nosniff' },
  { name: 'cross-origin-opener-policy', value: 'same-origin' },
  { name: 'cross-origin-resource-policy', value: 'same-origin' },
];

function requestRecord(hostname: string, kind: RequestRecord['kind'], thirdParty: boolean): RequestRecord {
  return {
    requestId: `req-${hostname}-${kind}`,
    url: `https://${hostname}/${kind}`,
    hostname,
    thirdParty,
    kind,
    initiatorHostname: thirdParty ? 'shop.example.com' : null,
    statusCode: 200,
    fromCache: false,
  };
}

function iframeReport(hostname: string): IframeReport {
  return {
    src: `https://${hostname}/embed`,
    hostname,
    isThirdParty: true,
    isInsecure: false,
    hasSandbox: true,
    sandboxTokens: ['allow-scripts'],
    allowTokens: [],
    allowsSameOrigin: false,
    allowsTopNavigation: false,
    allowsPopups: false,
    allowsForms: false,
    title: 'Advert',
    visible: true,
  };
}

function domReport(overrides: Partial<DomReport> = {}): DomReport {
  return {
    url: 'https://shop.example.com/checkout',
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

function observation(overrides: Partial<PageObservation> = {}): PageObservation {
  return {
    observationId: 'obs-1',
    tabId: 7,
    frameId: 0,
    url: 'https://shop.example.com/checkout?token=secret#step-two',
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 1_500,
    updatedAt: NOW - 100,
    mainDocument: {
      url: 'https://shop.example.com/checkout?token=secret',
      statusCode: 200,
      statusLine: 'HTTP/1.1 200 OK',
      serverIp: '203.0.113.7',
      fromCache: false,
      headers: HARDENED_HEADERS,
      tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
    },
    requests: [
      requestRecord('shop.example.com', 'main_frame', false),
      requestRecord('cdn.example.com', 'script', false),
      requestRecord('ads.third-party.test', 'sub_frame', true),
    ],
    requestsTruncated: false,
    dom: domReport(),
    warnings: [],
    ...overrides,
  };
}

function syntheticAssessment(
  signalId: string,
  measured: number | null,
  confidence: Confidence = 'high',
): SignalAssessment {
  return { signalId, title: signalId, measured, confidence, detail: `${signalId} detail`, evidence: [] };
}

function fakeAnalyzer(
  id: string,
  assessments: readonly SignalAssessment[],
  options: { moduleId?: ModuleId; failWith?: string } = {},
): SignalAnalyzer {
  return {
    id,
    moduleId: options.moduleId ?? 'trust-score',
    analyze() {
      if (options.failWith) throw new Error(options.failWith);
      return [...assessments];
    },
  };
}

function engine(analyzers: readonly SignalAnalyzer[]): TrustEngine {
  return new TrustEngine({ analyzers, clock: () => NOW });
}

describe('TrustEngine.run', () => {
  it('scores a real observation with the trust-score analysers', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(observation(), { now: NOW });

    expect(result.score).not.toBeNull();
    expect(result.score?.value).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(11);
    expect(result.findings.map((finding) => finding.signalId)).toContain('headers.csp');
    expect(result.findings.every((finding) => finding.impact <= finding.maxImpact)).toBe(true);
    expect(result.explanation.insufficientData).toBe(false);
    expect(result.explanation.headline).not.toBe('');
  });

  it('keeps query strings and fragments out of the stored result', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(observation(), { now: NOW });

    expect(result.url).toBe('https://shop.example.com/checkout');
    expect(result.domain).toBe('example.com');
    expect(result.origin).toBe('https://shop.example.com');
    expect(result.isSecureContext).toBe(true);
    expect(result.durationMs).toBe(1500);
  });

  it('reuses a scan id the caller already assigned', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(observation(), { scanId: 'scan-abc', now: NOW });
    expect(result.scanId).toBe('scan-abc');

    const generated = engine(TRUST_SCORE_ANALYZERS).run(observation(), { now: NOW });
    expect(generated.scanId).not.toBe('');
    expect(generated.scanId).not.toBe('scan-abc');
  });

  it('reports every module and whether it ran', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(observation(), { now: NOW });

    expect(result.modules.map((module) => module.id)).toEqual([
      'trust-score',
      'header-dashboard',
      'cookie-transparency',
      'change-monitor',
      'extension-auditor',
    ]);
    expect(result.modules[0]).toMatchObject({ id: 'trust-score', enabled: true, state: 'active', ran: true });
    // Phase 2: the cookie analyser is registered too, so two modules ran. The cookie signals
    // report `measured: null` for this hand-built observation (cookies were never collected),
    // which is exactly what D-006 requires.
    expect(result.modules[2]).toMatchObject({
      id: 'cookie-transparency',
      enabled: true,
      state: 'active',
      ran: true,
    });
    // Phase 4: the header dashboard now runs with the scan (D-009) — it produces the
    // popup's display data, though none of it can enter the score.
    expect(result.modules[1]).toMatchObject({ id: 'header-dashboard', enabled: true, state: 'active', ran: true });
    // The extension auditor is browser-scoped (D-010), not part of any page scan, so it
    // reports enabled-but-not-ran here.
    expect(result.modules[4]).toMatchObject({ id: 'extension-auditor', enabled: true, state: 'active', ran: false });
    expect(result.modules.filter((module) => module.ran)).toHaveLength(3);
  });

  it('exposes analyser ids in registration order', () => {
    expect(engine(TRUST_SCORE_ANALYZERS).analyzerIds()).toEqual([
      'connection',
      'headers',
      'privacy',
      'hygiene',
      'cookies',
    ]);
  });

  it('skips modules the user switched off', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(observation(), {
      enabledModules: ['change-monitor'],
      now: NOW,
    });

    expect(result.findings).toEqual([]);
    expect(result.score).toBeNull();
    expect(result.explanation.insufficientData).toBe(true);
    expect(result.modules.find((module) => module.id === 'trust-score')).toMatchObject({
      enabled: false,
      ran: false,
    });
  });

  it('keeps the other checks when one analyser throws', () => {
    const result = engine([
      fakeAnalyzer('healthy', [syntheticAssessment('connection.https', 100)]),
      fakeAnalyzer('broken', [], { moduleId: 'header-dashboard', failWith: 'boom' }),
    ]).run(observation(), { now: NOW });

    expect(result.warnings.some((warning) => warning.includes('boom'))).toBe(true);
    expect(result.modules[0]).toMatchObject({ id: 'trust-score', ran: true });
    // The failing analyser was registered under header-dashboard, and its error is reported
    // there — but the module itself still ran (D-009: the dashboard data was built).
    expect(result.modules[1]).toMatchObject({ id: 'header-dashboard', ran: true, error: 'boom' });
    expect(result.score?.value).toBe(100);
  });

  it('keeps the first measurement when two analysers report the same signal', () => {
    const result = engine([
      fakeAnalyzer('first', [syntheticAssessment('connection.https', 100)]),
      fakeAnalyzer('second', [syntheticAssessment('connection.https', 0)]),
    ]).run(observation(), { now: NOW });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.measured).toBe(100);
    expect(result.warnings.some((warning) => warning.includes('reported by both'))).toBe(true);
  });

  it('warns about a signal the scoring model does not know', () => {
    const result = engine([
      fakeAnalyzer('ghost', [syntheticAssessment('nope.unknown', 0)]),
      fakeAnalyzer('real', [syntheticAssessment('connection.https', 100)]),
    ]).run(observation(), { now: NOW });

    expect(result.warnings.some((warning) => warning.includes('not part of scoring model'))).toBe(true);
    expect(result.findings.map((finding) => finding.signalId)).toEqual(['connection.https']);
  });

  it('skips an analyser that claims an unknown module', () => {
    const result = engine([
      fakeAnalyzer('stray', [syntheticAssessment('connection.https', 100)], {
        moduleId: 'ghost-module' as ModuleId,
      }),
    ]).run(observation(), { now: NOW });

    expect(result.findings).toEqual([]);
    expect(result.warnings.some((warning) => warning.includes('unknown module'))).toBe(true);
  });

  it('carries observation warnings into the result', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(
      observation({ warnings: ['Headers were captured late.'] }),
      { now: NOW },
    );

    expect(result.warnings).toContain('Headers were captured late.');
  });

  it('penalises nothing when the page was never observed', () => {
    const result = engine(TRUST_SCORE_ANALYZERS).run(
      observation({ mainDocument: null, requests: [], dom: null }),
      { now: NOW },
    );

    expect(result.score).toBeNull();
    expect(result.findings.every((finding) => finding.impact === 0)).toBe(true);
    expect(result.explanation.insufficientData).toBe(true);
    expect(result.explanation.coverageNote).toBeNull();
    expect(result.explanation.caveats.length).toBeGreaterThan(0);
  });
});
