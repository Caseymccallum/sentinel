/**
 * ScoringModel tests.
 *
 * The model owns every number the user ever sees: weights, impact budgets, severities and
 * grade thresholds. If the expectations in this file are wrong, the Trust Score is wrong -
 * so the tests cover the model's *invariants* (weights sum to 1, every category has exactly
 * 100 points of budget, ids are unique) as well as hand-computed arithmetic for a few
 * examples that a human can check on paper.
 *
 * Deliberately absent: assertions on the exact weight of each category. Weights are a
 * product decision (see `docs/ARCHITECTURE.md`) and rebalancing them should not require
 * rewriting the arithmetic tests, only re-reading them.
 */

import { describe, expect, it } from 'vitest';
import {
  CATEGORIES,
  CONFIDENCE_MULTIPLIER,
  MODEL_VERSION,
  SCORE_CAPS,
  SEVERITY_ORDER,
  SIGNALS,
  ScoringModel,
  applyScoreCaps,
  categoryMaxImpact,
  categoryStatus,
  getCategory,
  getSignal,
  highestSeverity,
  impactFor,
  impactFraction,
  scoreToGrade,
  severityFor,
  signalsForCategory,
  validateScoringModel,
} from './scoring-model';
import type { Confidence, Grade, SignalAssessment } from './types';

const model = new ScoringModel();

function assessment(
  signalId: string,
  measured: number | null,
  confidence: Confidence = 'high',
): SignalAssessment {
  return { signalId, title: signalId, measured, confidence, detail: `${signalId} detail`, evidence: [] };
}

/** Every signal the model knows about, measured at the same quality. */
function allSignals(measured: number | null): SignalAssessment[] {
  return SIGNALS.map((signal) => assessment(signal.id, measured));
}

describe('model tables', () => {
  it('passes its own validation rules', () => {
    const report = validateScoringModel();

    expect(report.weightTotal).toBe(1);
    expect(report.categoryImpacts).toEqual({
      connection: 100,
      headers: 100,
      privacy: 100,
      hygiene: 100,
      cookies: 100,
    });
  });

  it('declares five weighted categories across the two active modules', () => {
    expect(CATEGORIES.map((category) => category.id)).toEqual([
      'connection',
      'headers',
      'privacy',
      'hygiene',
      'cookies',
    ]);
    expect(CATEGORIES.filter((category) => category.moduleId === 'trust-score')).toHaveLength(4);
    expect(CATEGORIES.filter((category) => category.moduleId === 'cookie-transparency')).toHaveLength(1);
    expect(CATEGORIES.every((category) => category.weight > 0 && category.weight < 1)).toBe(true);
    expect(Math.round(CATEGORIES.reduce((total, category) => total + category.weight, 0) * 100)).toBe(100);
  });

  it('keeps signal ids unique, rationalised and inside a known category', () => {
    const ids = SIGNALS.map((signal) => signal.id);

    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.length).toBeGreaterThanOrEqual(19);
    expect(SIGNALS.every((signal) => getCategory(signal.categoryId) !== undefined)).toBe(true);
    expect(SIGNALS.every((signal) => signal.rationale.length > 20)).toBe(true);
    expect(SIGNALS.every((signal) => signal.maxImpact > 0 && signal.maxImpact <= 100)).toBe(true);
    expect(getSignal('connection.https')?.maxImpact).toBe(45);
    expect(getSignal('connection.https')?.categoryId).toBe('connection');
    expect(getSignal('nope.missing')).toBeUndefined();
    expect(getCategory('nope.missing')).toBeUndefined();
  });

  it('gives every category exactly 100 points of budget', () => {
    for (const category of CATEGORIES) {
      expect(categoryMaxImpact(category.id)).toBe(100);
      expect(signalsForCategory(category.id).length).toBeGreaterThan(0);
    }

    expect(signalsForCategory('does-not-exist')).toEqual([]);
    expect(categoryMaxImpact('does-not-exist')).toBe(0);
  });

  it('never places a severity floor above its cap', () => {
    for (const signal of SIGNALS) {
      if (signal.severityFloor && signal.severityCap) {
        expect(SEVERITY_ORDER.indexOf(signal.severityFloor)).toBeLessThanOrEqual(
          SEVERITY_ORDER.indexOf(signal.severityCap),
        );
      }
    }
  });

  it('names a model version and a severity order', () => {
    expect(MODEL_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(SEVERITY_ORDER).toEqual(['info', 'low', 'medium', 'high', 'critical']);
    expect(CONFIDENCE_MULTIPLIER).toEqual({ unavailable: 0, low: 0.5, medium: 0.8, high: 1 });
  });

  it('exposes the same tables through the class', () => {
    expect(model.version).toBe(MODEL_VERSION);
    expect(model.categories).toBe(CATEGORIES);
    expect(model.signals).toBe(SIGNALS);
  });
});

describe('impactFraction', () => {
  it('turns quality into the share of the budget to remove', () => {
    expect(impactFraction(100)).toBe(0);
    expect(impactFraction(75)).toBe(0.25);
    expect(impactFraction(50)).toBe(0.5);
    expect(impactFraction(0)).toBe(1);
  });

  it('treats an unmeasured signal as no impact and clamps nonsense', () => {
    expect(impactFraction(null)).toBe(0);
    expect(impactFraction(-40)).toBe(1);
    expect(impactFraction(400)).toBe(0);
  });
});

describe('severityFor', () => {
  it('maps the share of available impact onto a severity', () => {
    expect(severityFor(0)).toBe('info');
    expect(severityFor(0.1)).toBe('low');
    expect(severityFor(0.24)).toBe('low');
    expect(severityFor(0.25)).toBe('medium');
    expect(severityFor(0.49)).toBe('medium');
    expect(severityFor(0.5)).toBe('high');
    expect(severityFor(0.74)).toBe('high');
    expect(severityFor(0.75)).toBe('critical');
    expect(severityFor(1)).toBe('critical');
  });

  it('applies a floor and a cap from the signal definition', () => {
    const frameAncestors = getSignal('headers.frame-ancestors');
    const crossOrigin = getSignal('headers.cross-origin-policy');
    const trackers = getSignal('privacy.trackers');

    expect(severityFor(0.1, frameAncestors)).toBe('medium');
    expect(severityFor(1, frameAncestors)).toBe('critical');
    expect(severityFor(0.9, crossOrigin)).toBe('low');
    expect(severityFor(0.05, trackers)).toBe('low');
  });

  it('never applies a floor to a finding that removed no points', () => {
    const passwordForms = getSignal('hygiene.password-forms');
    const trackers = getSignal('privacy.trackers');

    expect(passwordForms?.severityFloor).toBe('high');
    expect(severityFor(0, passwordForms)).toBe('info');
    expect(severityFor(0, trackers)).toBe('info');
    expect(severityFor(-1, passwordForms)).toBe('info');
  });
});

describe('impactFor', () => {
  it('removes nothing for a signal that was not measured or is unknown', () => {
    expect(impactFor('connection.https', null, 'high')).toBe(0);
    expect(impactFor('not.a.signal', 0, 'high')).toBe(0);
  });

  it('removes the whole budget at quality 0 and nothing at quality 100', () => {
    expect(impactFor('connection.https', 0, 'high')).toBe(45);
    expect(impactFor('connection.https', 100, 'high')).toBe(0);
    expect(impactFor('connection.https', 50, 'high')).toBe(22.5);
  });

  it('scales the impact by how sure the analyser is', () => {
    expect(impactFor('connection.https', 0, 'low')).toBe(22.5);
    expect(impactFor('connection.https', 0, 'medium')).toBe(36);
    expect(impactFor('connection.https', 0, 'unavailable')).toBe(0);
  });

  it('clamps out-of-range measurements', () => {
    expect(impactFor('connection.https', -40, 'high')).toBe(45);
    expect(impactFor('connection.https', 400, 'high')).toBe(0);
  });
});

describe('ScoringModel.toFindings', () => {
  it('attaches category, module, severity and impact metadata', () => {
    const { findings, unknownSignalIds } = model.toFindings([assessment('headers.csp', 0)]);

    expect(unknownSignalIds).toEqual([]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      signalId: 'headers.csp',
      title: 'headers.csp',
      categoryId: 'headers',
      moduleId: 'trust-score',
      measured: 0,
      maxImpact: 25,
      impact: 25,
      severity: 'critical',
    });
  });

  it('reports unknown signal ids instead of scoring them', () => {
    const { findings, unknownSignalIds } = model.toFindings([
      assessment('ghost.signal', 0),
      assessment('connection.https', 100),
    ]);

    expect(unknownSignalIds).toEqual(['ghost.signal']);
    expect(findings.map((finding) => finding.signalId)).toEqual(['connection.https']);
  });

  it('sorts the worst findings first, then by severity, then by id', () => {
    const { findings } = model.toFindings([
      assessment('headers.csp', 100),
      assessment('connection.https', 0),
      assessment('connection.hsts', 0),
      assessment('privacy.trackers', 0),
    ]);

    expect(findings.map((finding) => finding.signalId)).toEqual([
      'connection.https',
      'privacy.trackers',
      'connection.hsts',
      'headers.csp',
    ]);
    expect(findings[0]?.impact).toBe(45);
    expect(findings[3]?.impact).toBe(0);
  });

  it('never accuses a signal it could not measure', () => {
    const { findings } = model.toFindings([assessment('connection.tls-strength', null, 'unavailable')]);

    expect(findings[0]).toMatchObject({ measured: null, impact: 0, severity: 'info', confidence: 'unavailable' });
  });

  it('keeps the analyser evidence intact', () => {
    const withEvidence: SignalAssessment = {
      ...assessment('connection.hsts', 0),
      evidence: [{ label: 'Strict-Transport-Security', value: 'absent' }],
      remediation: 'Send HSTS.',
    };
    const { findings } = model.toFindings([withEvidence]);

    expect(findings[0]?.evidence).toEqual([{ label: 'Strict-Transport-Security', value: 'absent' }]);
    expect(findings[0]?.remediation).toBe('Send HSTS.');
  });
});

describe('ScoringModel.score', () => {
  it('returns null when nothing could be measured', () => {
    expect(model.score([])).toBeNull();
    expect(model.score([assessment('connection.https', null)])).toBeNull();
    expect(model.score([assessment('connection.https', 100)])).not.toBeNull();
  });

  it('scores a category as 100 minus the points its signals removed', () => {
    const score = model.score(
      [
        assessment('connection.https', 0),
        assessment('connection.tls-strength', 100),
        assessment('connection.certificate', 100),
        assessment('connection.hsts', 0),
      ],
      { enabledCategories: ['connection'] },
    );

    expect(score).not.toBeNull();
    expect(score?.categories).toHaveLength(1);
    expect(score?.categories[0]).toMatchObject({
      categoryId: 'connection',
      moduleId: 'trust-score',
      // 100 - 45 (https) - 15 (hsts). The category itself is never capped: only the composite is.
      score: 40,
      effectiveWeight: 1,
      status: 'high',
    });
    // The composite is capped at 20 because `connection.https` measured zero (see `SCORE_CAPS`).
    expect(score?.value).toBe(20);
    expect(score?.grade).toBe('F');
    expect(score?.modelVersion).toBe(MODEL_VERSION);
  });

  it('renormalises weights across the categories that produced a measurement', () => {
    const score = model.score([assessment('connection.https', 0), assessment('headers.csp', 0)]);
    const categories = score?.categories ?? [];

    expect(categories.map((category) => category.categoryId)).toEqual([
      'connection',
      'headers',
      'privacy',
      'hygiene',
      'cookies',
    ]);
    expect(categories[0]?.score).toBe(55);
    expect(categories[1]?.score).toBe(75);
    expect(categories[2]?.score).toBeNull();
    expect(categories[0]?.effectiveWeight).toBeCloseTo(0.5, 6);
    expect(categories[1]?.effectiveWeight).toBeCloseTo(0.5, 6);
    // Unweighted this would be 65 ((55 + 75) / 2); the HTTP cap holds it at 20.
    expect(score?.value).toBe(20);
    expect(score?.coverage).toBeCloseTo(0.4, 6);
    expect(score?.partial).toBe(true);
  });

  it('reports full coverage without a partial flag when every category is measured', () => {
    const score = model.score(allSignals(100));

    expect(score?.value).toBe(100);
    expect(score?.grade).toBe('A+');
    expect(score?.coverage).toBe(1);
    expect(score?.partial).toBe(false);
    expect(score?.categories.every((category) => category.score === 100)).toBe(true);
    expect(score?.categories.every((category) => category.effectiveWeight === category.weight)).toBe(true);
  });

  it('floors the score at 0 and tops it out at 100 however the measurements arrive', () => {
    const worst = model.score(allSignals(0));

    expect(worst?.value).toBe(0);
    expect(worst?.grade).toBe('F');
    expect(worst?.coverage).toBe(1);
    expect(worst?.categories.every((category) => category.score === 0)).toBe(true);

    const clamped = model.score([assessment('connection.https', -20), assessment('headers.csp', 500)]);

    expect(clamped?.categories[0]?.score).toBe(55);
    expect(clamped?.categories[1]?.score).toBe(100);
  });

  it('honours the enabled categories and refuses to score nothing', () => {
    expect(model.score(allSignals(0), { enabledCategories: [] })).toBeNull();

    const headersOnly = model.score(allSignals(0), { enabledCategories: ['headers'] });

    expect(headersOnly?.categories.map((category) => category.categoryId)).toEqual(['headers']);
    expect(headersOnly?.value).toBe(0);
    expect(headersOnly?.coverage).toBe(0.2);
  });

  it('counts a category as unmeasured when every signal in it is unmeasured', () => {
    const score = model.score([assessment('connection.https', null), assessment('headers.csp', 0)]);

    expect(score?.categories[0]?.score).toBeNull();
    expect(score?.categories[0]?.status).toBe('info');
    expect(score?.categories[0]?.effectiveWeight).toBe(0);
    expect(score?.coverage).toBe(0.2);
    expect(score?.partial).toBe(true);
  });

  it('carries the finding list into each category, worst first', () => {
    const score = model.score(allSignals(0), { enabledCategories: ['headers'] });

    expect(score?.categories[0]?.findings).toHaveLength(7);
    expect(score?.categories[0]?.findings.map((finding) => finding.impact)).toEqual([25, 15, 12, 12, 12, 12, 12]);
    expect(score?.categories[0]?.label).toBe('Response hardening');
  });
});

describe('scoreToGrade', () => {
  it('maps the documented thresholds', () => {
    const cases: [number, Grade][] = [
      [100, 'A+'],
      [97, 'A+'],
      [96.99, 'A'],
      [93, 'A'],
      [92.99, 'A-'],
      [90, 'A-'],
      [89.99, 'B+'],
      [87, 'B+'],
      [86.99, 'B'],
      [83, 'B'],
      [82.99, 'B-'],
      [80, 'B-'],
      [79.99, 'C+'],
      [77, 'C+'],
      [76.99, 'C'],
      [73, 'C'],
      [72.99, 'C-'],
      [70, 'C-'],
      [69.99, 'D+'],
      [67, 'D+'],
      [66.99, 'D'],
      [63, 'D'],
      [62.99, 'D-'],
      [60, 'D-'],
      [59.99, 'F'],
      [0, 'F'],
    ];

    for (const [value, grade] of cases) {
      expect(scoreToGrade(value)).toBe(grade);
    }
  });

  it('clamps a nonsense value before grading it', () => {
    expect(scoreToGrade(-5)).toBe('F');
    expect(scoreToGrade(120)).toBe('A+');
    expect(scoreToGrade(Number.NaN)).toBe('F');
  });
});

describe('categoryStatus', () => {
  it('maps a category score onto a severity band', () => {
    expect(categoryStatus(null)).toBe('info');
    expect(categoryStatus(100)).toBe('info');
    expect(categoryStatus(90)).toBe('info');
    expect(categoryStatus(89.99)).toBe('low');
    expect(categoryStatus(75)).toBe('low');
    expect(categoryStatus(74.99)).toBe('medium');
    expect(categoryStatus(60)).toBe('medium');
    expect(categoryStatus(59.99)).toBe('high');
    expect(categoryStatus(40)).toBe('high');
    expect(categoryStatus(39.99)).toBe('critical');
    expect(categoryStatus(0)).toBe('critical');
  });
});

describe('highestSeverity', () => {
  it('finds the worst severity in a list, defaulting to info', () => {
    expect(highestSeverity([])).toBe('info');
    expect(highestSeverity([{ severity: 'info' }])).toBe('info');
    expect(highestSeverity([{ severity: 'low' }, { severity: 'critical' }, { severity: 'medium' }])).toBe('critical');
  });
});

describe('hard score caps', () => {
  it('declares exactly one cap, on the transport signal, with a reason the user can read', () => {
    expect(SCORE_CAPS).toHaveLength(1);
    expect(SCORE_CAPS[0]).toMatchObject({ signalId: 'connection.https', when: 'zero', cap: 20 });
    expect(SCORE_CAPS[0]?.reason.trim()).not.toBe('');
    // A cap must never outlive the signal it names.
    expect(getSignal('connection.https')).toBeDefined();
  });

  it('holds an otherwise healthy HTTP page at the ceiling instead of averaging the failure away', () => {
    const assessments: SignalAssessment[] = [
      assessment('connection.https', 0),
      assessment('connection.tls-strength', null),
      assessment('connection.certificate', null),
      assessment('connection.hsts', null),
      assessment('headers.csp', 100),
      assessment('headers.frame-ancestors', 100),
      assessment('headers.content-type-protection', 100),
      assessment('headers.referrer-policy', 100),
      assessment('headers.permissions-policy', 100),
      assessment('headers.information-leakage', 100),
      assessment('headers.cross-origin-policy', 100),
      assessment('privacy.trackers', 100),
      assessment('privacy.third-party-surface', 100),
      assessment('privacy.referrer-leakage', 100),
      assessment('privacy.background-beacons', 100),
      assessment('hygiene.mixed-content', 100),
      assessment('hygiene.password-forms', 100),
      assessment('hygiene.form-targets', 100),
      assessment('hygiene.embedded-content', 100),
    ];
    const score = model.score(assessments);

    // Without the cap this would be 89 (B+) and the unencrypted page would look respectable.
    expect(score?.value).toBe(20);
    expect(score?.grade).toBe('F');
    expect(score?.cappedBy).toEqual({
      signalId: 'connection.https',
      title: 'Encrypted transport',
      cap: 20,
      reason: expect.stringContaining('served over HTTP'),
    });
  });

  it('does not cap a secure page, and does not invent a cap when the signal was unmeasured', () => {
    const secure = model.score([assessment('connection.https', 100), assessment('headers.csp', 100)]);
    expect(secure?.cappedBy).toBeUndefined();

    const unmeasured = model.score([assessment('connection.https', null), assessment('headers.csp', 100)]);
    expect(unmeasured?.cappedBy).toBeUndefined();
    expect(unmeasured?.value).toBe(100);
  });

  it('does not report a ceiling that did not lower the number', () => {
    // Worst case everywhere: the raw score is already 0, well below the cap.
    const floor = model.score(SIGNALS.map((signal) => assessment(signal.id, 0)));
    expect(floor?.value).toBe(0);
    expect(floor?.cappedBy).toBeUndefined();
  });

  it('applies the lowest ceiling when several caps would fire, and only on a zero measurement', () => {
    const findings = model.toFindings([
      assessment('connection.https', 0),
      assessment('headers.csp', 0),
    ]).findings;

    const applied = applyScoreCaps(
      [
        { signalId: 'headers.csp', when: 'zero', cap: 35, reason: 'CSP is missing.' },
        { signalId: 'connection.https', when: 'zero', cap: 20, reason: 'HTTP.' },
      ],
      findings,
      80,
    );
    expect(applied).toMatchObject({ signalId: 'connection.https', cap: 20 });

    // A partial measurement never triggers a `zero` cap.
    const partial = model.toFindings([assessment('connection.https', 40)]).findings;
    expect(applyScoreCaps(SCORE_CAPS, partial, 90)).toBeNull();

    // A cap whose signal never reported at all is ignored rather than assumed.
    expect(applyScoreCaps(SCORE_CAPS, [], 90)).toBeNull();
  });

  it('keeps every cap inside the model: known signal, 0-100 ceiling, non-empty reason', () => {
    for (const cap of SCORE_CAPS) {
      expect(getSignal(cap.signalId), cap.signalId).toBeDefined();
      expect(cap.cap).toBeGreaterThanOrEqual(0);
      expect(cap.cap).toBeLessThanOrEqual(100);
      expect(cap.reason.trim()).not.toBe('');
    }
    expect(() => validateScoringModel()).not.toThrow();
  });
});