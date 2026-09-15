/**
 * The scoring model.
 *
 * This file is *data plus arithmetic* — no analysis logic. It declares what exists
 * (categories with weights, signals with maximum impact) and how a measurement turns
 * into points and a severity, so the numbers behind a score are always inspectable and
 * unit-testable rather than buried inside conditionals.
 *
 * Impact arithmetic
 * -----------------
 *   measured   : 0-100 quality produced by an analyser (100 = nothing wrong)
 *   confidence : how sure the analyser is; low-confidence findings move the score less
 *   impact     : points removed from the category = maxImpact × (1 - measured/100) × conf()
 *
 * Within each category `maxImpact` sums to 100, so a category can reach 0 only when
 * *every* signal in it is measured at its worst possible value.
 */

import type {
  AppliedScoreCap,
  CategoryScore,
  Confidence,
  Finding,
  Grade,
  ModuleId,
  ScoreCapDefinition,
  Severity,
  SignalAssessment,
  TrustScore,
} from './types';
import { clamp, round } from './util';

/** Bump whenever weights, impacts or thresholds change meaningfully. */
export const MODEL_VERSION = '2.0.0';

export interface CategoryDefinition {
  id: string;
  moduleId: ModuleId;
  label: string;
  description: string;
  /** Share of the overall score, 0-1. All category weights must sum to exactly 1. */
  weight: number;
}

export interface SignalDefinition {
  /** Namespaced id, e.g. `connection.https`. */
  id: string;
  categoryId: string;
  title: string;
  /** Why this signal matters, in plain language. */
  rationale: string;
  remediation?: string;
  /** Maximum points this signal can remove from its category (0-100). */
  maxImpact: number;
  /** Reported severity is never lower than this, whatever the impact. */
  severityFloor?: Severity;
  /** Reported severity is never higher than this (used for informational signals). */
  severityCap?: Severity;
}

export const CATEGORIES: readonly CategoryDefinition[] = [
  {
    id: 'connection',
    moduleId: 'trust-score',
    label: 'Connection security',
    description: 'Whether the connection is encrypted and the server certificate can be trusted.',
    weight: 0.2,
  },
  {
    id: 'headers',
    moduleId: 'trust-score',
    label: 'Response hardening',
    description: 'Security headers that tell the browser how to protect the page and its visitors.',
    weight: 0.2,
  },
  {
    id: 'privacy',
    moduleId: 'trust-score',
    label: 'Privacy exposure',
    description: 'How much of your browsing this page shares with third-party hosts.',
    weight: 0.25,
  },
  {
    id: 'hygiene',
    moduleId: 'trust-score',
    label: 'Page hygiene',
    description: 'Mixed content, unsafe form handling and other page-level weaknesses.',
    weight: 0.15,
  },
  {
    id: 'cookies',
    moduleId: 'cookie-transparency',
    label: 'Cookie transparency',
    description: 'The cookies the page and its third parties set: what they are for, who owns them and how long they last.',
    weight: 0.2,
  },
];

export const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * How much an uncertain finding is allowed to move the score. Measured values are
 * facts; classification and inference are not, so confidence scales the impact.
 */
export const CONFIDENCE_MULTIPLIER: Readonly<Record<Confidence, number>> = {
  unavailable: 0,
  low: 0.5,
  medium: 0.8,
  high: 1,
};

/** Quality (0-100) → impact fraction (0-1), where 100 quality means "nothing to remove". */
export function impactFraction(measured: number | null): number {
  if (measured === null) return 0;
  return clamp(1 - measured / 100, 0, 1);
}

/**
 * Severity derived from how much of a signal's available impact was actually used,
 * then constrained by the signal's floor and cap.
 *
 * A floor or cap only applies once a finding actually removes points. A signal that
 * measured perfectly - or that could not be measured at all - has nothing to report, so it
 * stays `info` however high its floor is; otherwise a 100/100 page would carry a headline
 * "serious finding" that cost nothing.
 */
export function severityFor(fraction: number, definition?: SignalDefinition): Severity {
  if (fraction <= 0) return 'info';

  let severity: Severity;
  if (fraction >= 0.75) severity = 'critical';
  else if (fraction >= 0.5) severity = 'high';
  else if (fraction >= 0.25) severity = 'medium';
  else severity = 'low';

  if (!definition) return severity;
  const floorIndex = definition.severityFloor ? SEVERITY_ORDER.indexOf(definition.severityFloor) : 0;
  const capIndex = definition.severityCap ? SEVERITY_ORDER.indexOf(definition.severityCap) : SEVERITY_ORDER.length - 1;
  const index = clamp(SEVERITY_ORDER.indexOf(severity), Math.min(floorIndex, capIndex), Math.max(floorIndex, capIndex));
  return SEVERITY_ORDER[index] ?? severity;
}

/** Signal inventory. The `maxImpact` values within each category sum to exactly 100. */
export const SIGNALS: readonly SignalDefinition[] = [
  // ---------------------------------------------------------------- connection (100)
  {
    id: 'connection.https',
    categoryId: 'connection',
    title: 'Encrypted transport',
    rationale:
      'Without HTTPS, anything you type or read on this page can be read or altered by devices on the network path.',
    remediation: 'Serve the site over HTTPS and redirect all HTTP requests to it.',
    maxImpact: 45,
  },
  {
    id: 'connection.tls-strength',
    categoryId: 'connection',
    title: 'TLS strength',
    rationale:
      'Old TLS versions and legacy signature algorithms have known weaknesses that make interception cheaper.',
    remediation: 'Require TLS 1.2 or newer, prefer TLS 1.3, and retire SHA-1 signed certificates.',
    maxImpact: 20,
  },
  {
    id: 'connection.certificate',
    categoryId: 'connection',
    title: 'Certificate trust',
    rationale:
      'The certificate is what proves the site is who it claims to be; an expired, self-signed or weak-key certificate breaks that proof.',
    remediation: 'Use a certificate from a publicly trusted authority and automate renewal.',
    maxImpact: 20,
  },
  {
    id: 'connection.hsts',
    categoryId: 'connection',
    title: 'Transport upgrade policy (HSTS)',
    rationale:
      'HSTS stops one unencrypted request from downgrading the whole session, which is the classic way a session cookie gets stolen.',
    remediation: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.',
    maxImpact: 15,
  },

  // ------------------------------------------------------------------- headers (100)
  {
    id: 'headers.csp',
    categoryId: 'headers',
    title: 'Content Security Policy',
    rationale:
      'CSP is the browser-enforced defence against cross-site scripting: without it, one injected script runs with full access to the page.',
    remediation: 'Publish a restrictive CSP that avoids `unsafe-inline` and `unsafe-eval`.',
    maxImpact: 25,
  },
  {
    id: 'headers.frame-ancestors',
    categoryId: 'headers',
    title: 'Clickjacking protection',
    rationale:
      'Clickjacking overlays invisible controls on a page so your clicks perform actions you never intended.',
    remediation: "Send `Content-Security-Policy: frame-ancestors 'none'` or `X-Frame-Options: DENY`.",
    maxImpact: 15,
    severityFloor: 'medium',
  },
  {
    id: 'headers.content-type-protection',
    categoryId: 'headers',
    title: 'MIME sniffing protection',
    rationale:
      'Without `nosniff` a browser may execute an uploaded file as a script even when the server calls it an image.',
    remediation: 'Send `X-Content-Type-Options: nosniff`.',
    maxImpact: 12,
  },
  {
    id: 'headers.referrer-policy',
    categoryId: 'headers',
    title: 'Referrer policy',
    rationale:
      'The default referrer policy leaks full URLs — which often contain account ids or search terms — to every third-party host.',
    remediation: 'Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.',
    maxImpact: 12,
  },
  {
    id: 'headers.permissions-policy',
    categoryId: 'headers',
    title: 'Feature permissions policy',
    rationale:
      'A permissions policy stops injected or third-party code from silently using your camera, microphone or location.',
    remediation: 'Send a `Permissions-Policy` header listing only the features the page actually needs.',
    maxImpact: 12,
  },
  {
    id: 'headers.information-leakage',
    categoryId: 'headers',
    title: 'Server disclosure',
    rationale:
      'Banner headers advertise exact server, framework and language versions, which lets an attacker target known flaws directly.',
    remediation: 'Remove or generalise `Server`, `X-Powered-By` and similar version banners.',
    maxImpact: 12,
  },
  {
    id: 'headers.cross-origin-policy',
    categoryId: 'headers',
    title: 'Cross-origin isolation',
    rationale:
      'Cross-Origin-Opener/Embedder/Resource policies fence the page off from speculative side-channel attacks and unwanted embedding.',
    remediation: 'Send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`.',
    maxImpact: 12,
    severityCap: 'low',
  },

  // ------------------------------------------------------------------- privacy (100)
  {
    id: 'privacy.trackers',
    categoryId: 'privacy',
    title: 'Third-party tracking',
    rationale:
      'Requests to known analytics and advertising hosts are how a profile of your browsing gets assembled across sites.',
    maxImpact: 40,
    severityFloor: 'low',
  },
  {
    id: 'privacy.third-party-surface',
    categoryId: 'privacy',
    title: 'Third-party surface',
    rationale:
      'Every extra host contacted is another party that learns your IP address, your user agent and the page you are reading.',
    maxImpact: 20,
  },
  {
    id: 'privacy.referrer-leakage',
    categoryId: 'privacy',
    title: 'Referrer leakage',
    rationale:
      'With a permissive referrer policy, third-party requests hand over the full URL of the page you are on.',
    maxImpact: 20,
  },
  {
    id: 'privacy.background-beacons',
    categoryId: 'privacy',
    title: 'Background beacons',
    rationale:
      'Beacons, `ping` attributes and speculative prefetches report your activity — or your likely next click — before you decide anything.',
    maxImpact: 20,
  },

  // ------------------------------------------------------------------- hygiene (100)
  {
    id: 'hygiene.mixed-content',
    categoryId: 'hygiene',
    title: 'Mixed content',
    rationale:
      'When an HTTPS page loads HTTP subresources, those pieces can be rewritten in transit even though the padlock still looks fine.',
    maxImpact: 35,
  },
  {
    id: 'hygiene.password-forms',
    categoryId: 'hygiene',
    title: 'Password handling',
    rationale:
      'Passwords sent from an unencrypted page, to another domain, or from a page that can be framed can be captured in transit.',
    maxImpact: 30,
    severityFloor: 'high',
  },
  {
    id: 'hygiene.form-targets',
    categoryId: 'hygiene',
    title: 'Form destinations',
    rationale:
      'Forms posting to third-party or unencrypted endpoints send your input somewhere the site cannot protect it.',
    maxImpact: 15,
  },
  {
    id: 'hygiene.embedded-content',
    categoryId: 'hygiene',
    title: 'Embedded content safety',
    rationale:
      "Unsandboxed third-party frames can run scripts, navigate the top window and open popups on the page's behalf.",
    maxImpact: 20,
  },

  // ------------------------------------------------------------------- cookies (100)
  {
    id: 'cookies.tracking',
    categoryId: 'cookies',
    title: 'Tracking cookies',
    rationale:
      'Cookies from analytics, advertising and social platforms are how a browsing profile is assembled across sites, and they persist long after the page is closed.',
    maxImpact: 45,
  },
  {
    id: 'cookies.third-party',
    categoryId: 'cookies',
    title: 'Third-party cookies',
    rationale:
      'A cookie set by a host other than the page you are on links that visit to everything else the same host sees you do.',
    maxImpact: 30,
  },
  {
    id: 'cookies.persistence',
    categoryId: 'cookies',
    title: 'Cookie persistence',
    rationale:
      'A cookie that lives for more than a year outlasts most privacy decisions and is usually an advertising or analytics identifier rather than a session need.',
    maxImpact: 25,
  },
];

/**
 * Hard ceilings on the composite score.
 *
 * Weights average, so a single catastrophic fact can be outvoted by twelve healthy ones. A cap
 * says the opposite: this fact invalidates the premise of the whole report, so the number is
 * not allowed above a ceiling no matter what else measured well. Only `when: 'zero'` is
 * supported today - `measured === 0`, the worst possible value for that signal - so a cap can
 * never fire on a partly-bad measurement, and it never fires when the signal was not measured
 * at all (`measured: null` removes no points and caps nothing).
 *
 * `docs/SCORING.md` section 2.2 documents the one cap below; the UI shows `cappedBy.reason`
 * next to the score, so a ceiling is never a silent adjustment.
 */
export const SCORE_CAPS: readonly (ScoreCapDefinition & { signalId: string })[] = [
  {
    signalId: 'connection.https',
    when: 'zero',
    cap: 20,
    reason:
      'This page was served over HTTP, so anything sent to it or read from it can be altered on the network path.',
  },
];

/** Lookup tables, built once at module load. */
const SIGNAL_INDEX = new Map<string, SignalDefinition>(SIGNALS.map((signal) => [signal.id, signal]));
const CATEGORY_INDEX = new Map<string, CategoryDefinition>(CATEGORIES.map((category) => [category.id, category]));
const SIGNALS_BY_CATEGORY = new Map<string, SignalDefinition[]>();
for (const signal of SIGNALS) {
  const bucket = SIGNALS_BY_CATEGORY.get(signal.categoryId);
  if (bucket) bucket.push(signal);
  else SIGNALS_BY_CATEGORY.set(signal.categoryId, [signal]);
}

export function getSignal(id: string): SignalDefinition | undefined {
  return SIGNAL_INDEX.get(id);
}

export function getCategory(id: string): CategoryDefinition | undefined {
  return CATEGORY_INDEX.get(id);
}

export function signalsForCategory(categoryId: string): readonly SignalDefinition[] {
  return SIGNALS_BY_CATEGORY.get(categoryId) ?? [];
}

/** Total points a category can remove (100 by design). */
export function categoryMaxImpact(categoryId: string): number {
  return signalsForCategory(categoryId).reduce((total, signal) => total + signal.maxImpact, 0);
}

/**
 * Points removed from a category by one measurement.
 * `measured: null` (could not be measured at all) always removes nothing; the category
 * then carries proportionally less weight instead of being marked down for silence.
 */
export function impactFor(signalId: string, measured: number | null, confidence: Confidence): number {
  const definition = SIGNAL_INDEX.get(signalId);
  if (!definition || measured === null) return 0;
  return round(definition.maxImpact * impactFraction(clamp(measured, 0, 100)) * CONFIDENCE_MULTIPLIER[confidence], 4);
}

/**
 * The cap that lowers a score, or `null` when no cap applies.
 *
 * A cap only reports itself when it actually *lowered* the number: a page that measured 0 on
 * `connection.https` and then scored 12 anyway was already below the ceiling, and saying "capped
 * at 20" about a 12 would be noise. When more than one cap fires, the lowest ceiling wins.
 */
export function applyScoreCaps(
  caps: readonly (ScoreCapDefinition & { signalId: string })[],
  findings: readonly Finding[],
  value: number,
): AppliedScoreCap | null {
  let applied: AppliedScoreCap | null = null;

  for (const cap of caps) {
    if (cap.when !== 'zero') continue;
    const finding = findings.find((candidate) => candidate.signalId === cap.signalId);
    if (!finding || finding.measured !== 0) continue;
    if (value <= cap.cap) continue;
    if (applied === null || cap.cap < applied.cap) {
      applied = {
        signalId: cap.signalId,
        // The model's title, not the analyser's: the cap is declared here, so the sentence the
        // user reads about it should be the one this file is responsible for.
        title: SIGNAL_INDEX.get(cap.signalId)?.title ?? finding.title,
        cap: cap.cap,
        reason: cap.reason,
      };
    }
  }

  return applied;
}

/**
 * Model sanity checks. The unit tests call this and fail the build if it throws, so a
 * typo in the tables above can never silently skew every score.
 */
export function validateScoringModel(): { weightTotal: number; categoryImpacts: Record<string, number> } {
  const weightTotal = round(
    CATEGORIES.reduce((total, category) => total + category.weight, 0),
    6,
  );
  if (Math.abs(weightTotal - 1) > 1e-6) {
    throw new Error(`Category weights must sum to 1, got ${weightTotal}`);
  }

  const categoryImpacts: Record<string, number> = {};
  for (const category of CATEGORIES) {
    const total = categoryMaxImpact(category.id);
    categoryImpacts[category.id] = total;
    if (signalsForCategory(category.id).length === 0) {
      throw new Error(`Category "${category.id}" has no signals`);
    }
    if (total !== 100) {
      throw new Error(`Category "${category.id}" maxImpact must sum to 100, got ${total}`);
    }
  }

  const seen = new Set<string>();
  for (const signal of SIGNALS) {
    if (seen.has(signal.id)) throw new Error(`Duplicate signal id "${signal.id}"`);
    seen.add(signal.id);
    if (!CATEGORY_INDEX.has(signal.categoryId)) {
      throw new Error(`Signal "${signal.id}" references unknown category "${signal.categoryId}"`);
    }
    if (signal.maxImpact <= 0 || signal.maxImpact > 100) {
      throw new Error(`Signal "${signal.id}" has an out-of-range maxImpact (${signal.maxImpact})`);
    }
    if (signal.severityFloor && signal.severityCap) {
      if (SEVERITY_ORDER.indexOf(signal.severityFloor) > SEVERITY_ORDER.indexOf(signal.severityCap)) {
        throw new Error(`Signal "${signal.id}" has a severity floor above its cap`);
      }
    }
  }

  // A cap that names a signal nobody declares, or a ceiling outside 0-100, would silently do
  // nothing at all - so it fails the build rather than becoming a no-op.
  const cappedSignals = new Set<string>();
  for (const cap of SCORE_CAPS) {
    if (!seen.has(cap.signalId)) {
      throw new Error(`Score cap references unknown signal "${cap.signalId}"`);
    }
    if (cappedSignals.has(cap.signalId)) {
      throw new Error(`Signal "${cap.signalId}" has more than one score cap`);
    }
    cappedSignals.add(cap.signalId);
    if (cap.cap < 0 || cap.cap > 100) {
      throw new Error(`Score cap for "${cap.signalId}" is out of range (${cap.cap})`);
    }
    if (cap.reason.trim() === '') {
      throw new Error(`Score cap for "${cap.signalId}" has no reason to show the user`);
    }
  }

  return { weightTotal, categoryImpacts };
}

export interface ScoreOptions {
  /**
   * Categories to include. Omitted = all categories in the model. Disabled modules are
   * excluded this way so their points are not silently redistributed.
   */
  enabledCategories?: readonly string[];
}

/**
 * Turns measurements into a score.
 *
 * `TrustEngine` runs the analysers; this class owns every number that ends up in front
 * of the user, which keeps the arithmetic testable in isolation.
 *
 * Category scores are computed independently (100 - Σ impact), then combined with
 * re-normalised weights across the categories that could actually be measured. A page
 * is never penalised for a signal the browser refused to expose.
 *
 * Finally the hard caps in `SCORE_CAPS` are applied: a cap is a statement that one fact
 * invalidates the rest of the report, so it is the last word on the number.
 */
export class ScoringModel {
  readonly version = MODEL_VERSION;
  readonly categories = CATEGORIES;
  readonly signals = SIGNALS;

  /** Attaches scoring metadata to raw assessments. Unknown signal ids are skipped. */
  toFindings(assessments: readonly SignalAssessment[]): { findings: Finding[]; unknownSignalIds: string[] } {
    const findings: Finding[] = [];
    const unknownSignalIds: string[] = [];

    for (const assessment of assessments) {
      const definition = SIGNAL_INDEX.get(assessment.signalId);
      if (!definition) {
        unknownSignalIds.push(assessment.signalId);
        continue;
      }
      const category = CATEGORY_INDEX.get(definition.categoryId);
      if (!category) {
        unknownSignalIds.push(assessment.signalId);
        continue;
      }
      const impact = impactFor(assessment.signalId, assessment.measured, assessment.confidence);
      findings.push({
        ...assessment,
        categoryId: definition.categoryId,
        moduleId: category.moduleId,
        severity: severityFor(definition.maxImpact === 0 ? 0 : impact / definition.maxImpact, definition),
        maxImpact: definition.maxImpact,
        impact,
      });
    }

    findings.sort(compareFindings);
    return { findings, unknownSignalIds };
  }

  /** Scores the enabled categories, or returns `null` when nothing could be measured. */
  score(assessments: readonly SignalAssessment[], options: ScoreOptions = {}): TrustScore | null {
    const { findings } = this.toFindings(assessments);
    const activeCategories = options.enabledCategories
      ? this.categories.filter((category) => options.enabledCategories?.includes(category.id))
      : this.categories;

    const findingsByCategory = new Map<string, Finding[]>();
    for (const finding of findings) {
      const bucket = findingsByCategory.get(finding.categoryId);
      if (bucket) bucket.push(finding);
      else findingsByCategory.set(finding.categoryId, [finding]);
    }

    const categoryScores: CategoryScore[] = activeCategories.map((category) => {
      const categoryFindings = findingsByCategory.get(category.id) ?? [];
      const measurable = categoryFindings.filter((finding) => finding.measured !== null);
      const score =
        measurable.length === 0
          ? null
          : round(clamp(100 - measurable.reduce((total, finding) => total + finding.impact, 0), 0, 100), 2);

      return {
        categoryId: category.id,
        moduleId: category.moduleId,
        label: category.label,
        description: category.description,
        weight: category.weight,
        effectiveWeight: 0,
        score,
        status: categoryStatus(score),
        findings: categoryFindings,
      };
    });

    const measuredWeight = categoryScores
      .filter((category) => category.score !== null)
      .reduce((total, category) => total + category.weight, 0);

    if (measuredWeight === 0) return null;

    let weightedTotal = 0;
    for (const category of categoryScores) {
      if (category.score === null) continue;
      category.effectiveWeight = round(category.weight / measuredWeight, 6);
      weightedTotal += category.score * category.effectiveWeight;
    }

    const value = round(clamp(weightedTotal, 0, 100), 0);
    const coverage = round(clamp(measuredWeight, 0, 1), 4);
    const unavailableCount = findings.filter((finding) => finding.measured === null).length;
    const unmeasuredCategories = categoryScores.filter((category) => category.score === null).length;

    // Caps come last: they are a statement about the validity of the whole report, so they
    // cannot be averaged away by the categories that measured well.
    const cappedBy = applyScoreCaps(SCORE_CAPS, findings, value);
    const finalValue = cappedBy === null ? value : Math.min(value, cappedBy.cap);

    const trustScore: TrustScore = {
      value: finalValue,
      grade: scoreToGrade(finalValue),
      categories: categoryScores,
      modelVersion: MODEL_VERSION,
      partial: unavailableCount > 0 || unmeasuredCategories > 0,
      coverage,
    };
    if (cappedBy) trustScore.cappedBy = cappedBy;
    return trustScore;
  }
}

/** Worst (most expensive) findings first, then by severity, then by signal id for stability. */
function compareFindings(a: Finding, b: Finding): number {
  if (b.impact !== a.impact) return b.impact - a.impact;
  const severityDelta = SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
  if (severityDelta !== 0) return severityDelta;
  return a.signalId.localeCompare(b.signalId);
}


/** 0-100 score → letter grade. Thresholds stay stable across model versions. */
const GRADE_THRESHOLDS: readonly { min: number; grade: Grade }[] = [
  { min: 97, grade: 'A+' },
  { min: 93, grade: 'A' },
  { min: 90, grade: 'A-' },
  { min: 87, grade: 'B+' },
  { min: 83, grade: 'B' },
  { min: 80, grade: 'B-' },
  { min: 77, grade: 'C+' },
  { min: 73, grade: 'C' },
  { min: 70, grade: 'C-' },
  { min: 67, grade: 'D+' },
  { min: 63, grade: 'D' },
  { min: 60, grade: 'D-' },
  { min: 0, grade: 'F' },
];

export function scoreToGrade(value: number): Grade {
  const score = round(clamp(value, 0, 100), 2);
  for (const threshold of GRADE_THRESHOLDS) {
    if (score >= threshold.min) return threshold.grade;
  }
  return 'F';
}

/** Where a category score sits on the severity scale (used for colour coding). */
export function categoryStatus(score: number | null): Severity {
  if (score === null) return 'info';
  if (score >= 90) return 'info';
  if (score >= 75) return 'low';
  if (score >= 60) return 'medium';
  if (score >= 40) return 'high';
  return 'critical';
}

/** Highest severity among findings, for the popup's headline state. */
export function highestSeverity(findings: readonly { severity: Severity }[]): Severity {
  let worst: Severity = 'info';
  for (const finding of findings) {
    if (SEVERITY_ORDER.indexOf(finding.severity) > SEVERITY_ORDER.indexOf(worst)) {
      worst = finding.severity;
    }
  }
  return worst;
}
