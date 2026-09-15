/**
 * ExplanationBuilder tests.
 *
 * The explanation is the half of the product a user actually reads, and it is derived
 * entirely from `Finding` and `CategoryScore` objects - never from its own measurements.
 * These tests pin down the wording rules the popup depends on: which reasons appear, in
 * which order, what an unmeasurable check looks like, and what the reader sees when there is
 * nothing to report at all.
 *
 * Strings containing typographic characters (the minus sign in "-45 of 45 points") are
 * matched with escapes so the assertions cannot be broken by an editor re-encoding the file.
 */

import { describe, expect, it } from 'vitest';
import { ExplanationBuilder, gradeForValue } from './explanation-builder';
import { SIGNALS, ScoringModel, scoreToGrade } from './scoring-model';
import type {
  CategoryScore,
  Confidence,
  Finding,
  ObservationSummary,
  SignalAssessment,
  TrustScore,
} from './types';

/** U+2212 MINUS SIGN, used by `scoreEffect`. */
const MINUS = '\u2212';

const model = new ScoringModel();
const builder = new ExplanationBuilder();

function assessment(
  signalId: string,
  measured: number | null,
  confidence: Confidence = 'high',
): SignalAssessment {
  return { signalId, title: signalId, measured, confidence, detail: `${signalId} detail`, evidence: [] };
}

/** Every signal the model knows about, at the same quality. */
function allSignals(measured: number | null): SignalAssessment[] {
  return SIGNALS.map((signal) => assessment(signal.id, measured));
}

function findingsOf(assessments: readonly SignalAssessment[]): Finding[] {
  return model.toFindings(assessments).findings;
}

function categoriesOf(score: TrustScore | null): CategoryScore[] {
  return score?.categories ?? [];
}

function observationSummary(overrides: Partial<ObservationSummary> = {}): ObservationSummary {
  return {
    observed: true,
    scheme: 'https',
    statusCode: 200,
    statusLine: 'HTTP/1.1 200 OK',
    serverIp: '203.0.113.7',
    fromCache: false,
    tls: { state: 'secure', protocol: 'TLSv1.3', source: 'get-security-info', certificate: null },
    headerCount: 6,
    requestCount: 12,
    thirdPartyHostCount: 2,
    trackerCount: 1,
    domReportAvailable: true,
    resourcesCollected: true,
    frameCount: 0,
    notes: [],
    ...overrides,
  };
}

describe('severityCounts', () => {
  it('counts only the findings that were actually measured', () => {
    const findings = findingsOf([
      assessment('connection.https', 0),
      assessment('connection.hsts', 0),
      assessment('headers.csp', 100),
      assessment('connection.tls-strength', null, 'unavailable'),
      assessment('privacy.trackers', null, 'unavailable'),
    ]);

    expect(builder.severityCounts(findings)).toEqual({ info: 1, low: 0, medium: 0, high: 0, critical: 2 });
  });

  it('returns zeroes for an empty finding list', () => {
    expect(builder.severityCounts([])).toEqual({ info: 0, low: 0, medium: 0, high: 0, critical: 0 });
  });

  it('does not let a severity floor turn an unmeasured signal into a problem', () => {
    const findings = findingsOf([assessment('privacy.trackers', null, 'unavailable')]);

    expect(findings[0]?.severity).toBe('info');
    expect(builder.severityCounts(findings).low).toBe(0);
  });
});

describe('build without a score', () => {
  it('says plainly that there is nothing to explain yet', () => {
    const findings = findingsOf([assessment('connection.https', null, 'unavailable')]);
    const explanation = builder.build(null, findings, [], observationSummary({ notes: ['Header capture was late.'] }));

    expect(explanation.headline).toBe('Not enough information yet');
    expect(explanation.insufficientData).toBe(true);
    expect(explanation.summary).toContain('Open or reload the page');
    expect(explanation.breakdown).toEqual([]);
    expect(explanation.highlights).toEqual([]);
    expect(explanation.strengths).toEqual([]);
    expect(explanation.coverageNote).toBeNull();
    expect(explanation.caveats).toHaveLength(2);
    expect(explanation.caveats[0]).toContain('could not be checked');
    expect(explanation.caveats[0]).toContain('connection.https detail');
    expect(explanation.caveats[1]).toBe('Header capture was late.');
  });
});

describe('build with a score', () => {
  it('renders a clean bill of health when every check measured perfectly', () => {
    const score = model.score(allSignals(100));
    const findings = findingsOf(allSignals(100));
    const explanation = builder.build(score, findings, categoriesOf(score));

    expect(explanation.headline).toContain('Trustworthy (A+)');
    expect(explanation.insufficientData).toBe(false);
    expect(explanation.summary).toContain('Sentinel gives this page 100/100 (A+).');
    expect(explanation.summary).toContain('Every check Sentinel could run came back clean.');
    expect(explanation.highlights).toEqual([]);
    expect(explanation.caveats).toEqual([]);
    expect(explanation.coverageNote).toBeNull();
    expect(explanation.strengths).toHaveLength(SIGNALS.length);
    expect(explanation.strengths).toContain('connection.https: connection.https detail');
    expect(explanation.severityCounts).toEqual({
      info: SIGNALS.length,
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    });
  });

  it('leads with the worst findings, worst first and capped at three', () => {
    const score = model.score(allSignals(0));
    const explanation = builder.build(score, findingsOf(allSignals(0)), categoriesOf(score));

    expect(explanation.headline).toContain('(F)');
    expect(explanation.summary).toContain('Sentinel gives this page 0/100 (F).');
    expect(explanation.summary).toContain(`${SIGNALS.length - 1} findings rated serious or critical.`);
    expect(explanation.highlights).toHaveLength(3);
    expect(explanation.highlights[0]).toBe('connection.https detail.');
    expect(explanation.highlights[1]).toBe('cookies.tracking detail.');
    expect(explanation.highlights[2]).toBe('privacy.trackers detail.');
    expect(explanation.strengths).toEqual([]);
    // `headers.cross-origin-policy` caps its severity at `low`, so one signal never reads as serious.
    expect(explanation.severityCounts.critical).toBe(SIGNALS.length - 1);
    expect(explanation.severityCounts.low).toBe(1);
    expect(explanation.breakdown).toHaveLength(5);
  });

  it('explains exactly how much of the model the score rests on', () => {
    const assessments = [assessment('connection.https', 0), assessment('headers.csp', 0)];
    const score = model.score(assessments);
    const explanation = builder.build(score, findingsOf(assessments), categoriesOf(score));

    expect(explanation.summary).toContain('Sentinel gives this page 20/100 (F).');
    expect(explanation.summary).toContain('Most important: connection.https detail.');
    expect(explanation.summary).toContain('2 findings rated serious or critical.');
    expect(explanation.coverageNote).toBe(
      'This score rests on 40% of the model\'s weight: no usable data for Privacy exposure, Page hygiene and Cookie transparency. ' +
        'It covers Connection security and Response hardening. That gap is in Sentinel\'s view, not a fault in the page.',
    );
    expect(explanation.highlights).toEqual(['connection.https detail.', 'headers.csp detail.']);
    expect(explanation.severityCounts).toEqual({ info: 0, low: 0, medium: 0, high: 0, critical: 2 });
  });

  it('describes each category, including the ones it could not measure', () => {
    const assessments = [assessment('connection.https', 0), assessment('headers.csp', 0)];
    const score = model.score(assessments);
    const explanation = builder.build(score, findingsOf(assessments), categoriesOf(score));

    expect(explanation.breakdown).toHaveLength(5);
    expect(explanation.breakdown[0]).toContain('55/100');
    expect(explanation.breakdown[0]).toContain('model weight 20%');
    expect(explanation.breakdown[0]).toContain('50% of this score');
    expect(explanation.breakdown[1]).toContain('75/100');
    expect(explanation.breakdown[2]).toContain('not measurable');
    expect(explanation.breakdown[3]).toContain('not measurable');
    expect(explanation.breakdown[4]).toContain('Cookie transparency');
    expect(explanation.breakdown[4]).toContain('not measurable');
  });

  it('explains an unmeasurable check as a caveat rather than a deduction', () => {
    const assessments = [assessment('connection.https', 100), assessment('headers.csp', null, 'unavailable')];
    const score = model.score(assessments);
    const explanation = builder.build(
      score,
      findingsOf(assessments),
      categoriesOf(score),
      observationSummary({ notes: ['No page report arrived from the content script.'] }),
    );

    expect(explanation.caveats).toHaveLength(2);
    expect(explanation.caveats[0]).toContain('headers.csp could not be checked');
    expect(explanation.caveats[1]).toBe('No page report arrived from the content script.');
    expect(explanation.summary).toContain('Every check Sentinel could run came back clean.');
  });

  it('renders a "no issues" explanation when there are no findings at all', () => {
    const score = model.score(allSignals(100));
    const explanation = builder.build(score, [], [], undefined);

    expect(explanation.summary).toBe(
      'Sentinel gives this page 100/100 (A+). Every check Sentinel could run came back clean.',
    );
    expect(explanation.highlights).toEqual([]);
    expect(explanation.strengths).toEqual([]);
    expect(explanation.caveats).toEqual([]);
    expect(explanation.breakdown).toEqual([]);
    expect(explanation.coverageNote).toBeNull();
    expect(explanation.insufficientData).toBe(false);
  });

  it('names the weakest area when nothing is serious enough to lead with', () => {
    const assessments = [
      assessment('headers.cross-origin-policy', 0),
      assessment('headers.csp', 100),
    ];
    const score = model.score(assessments);
    const explanation = builder.build(score, findingsOf(assessments), categoriesOf(score));

    expect(explanation.severityCounts).toEqual({ info: 1, low: 1, medium: 0, high: 0, critical: 0 });
    expect(explanation.summary).toContain('The weakest area is response hardening at 88/100.');
    expect(explanation.summary).not.toContain('rated serious or critical');
  });

  it('produces the same explanation whatever order the analysers reported in', () => {
    const forward = [assessment('connection.https', 0), assessment('headers.csp', 0)];
    const backward = [assessment('headers.csp', 0), assessment('connection.https', 0)];

    const firstScore = model.score(forward);
    const secondScore = model.score(backward);
    const first = builder.build(firstScore, findingsOf(forward), categoriesOf(firstScore));
    const second = builder.build(secondScore, findingsOf(backward), categoriesOf(secondScore));

    expect(second).toEqual(first);
  });
});