/**
 * ExplanationBuilder — the "why?" half of Sentinel.
 *
 * A score nobody can interrogate is just a number. This module turns the scoring
 * engine's output into plain language at three levels of detail:
 *
 *   1. headline + summary   — what a user reads first,
 *   2. highlights/strengths — the handful of things that actually moved the number,
 *   3. finding views        — technical detail, evidence and a fix for each signal.
 *
 * It performs no measurement of its own: every sentence is derived from a `Finding` or
 * a `CategoryScore`, so explanations can never drift away from the score.
 */

import type {
  CategoryScore,
  Confidence,
  Evidence,
  Explanation,
  Finding,
  FindingView,
  ObservationSummary,
  Severity,
  TrustScore,
} from './types';
import { SEVERITY_ORDER, scoreToGrade } from './scoring-model';
import { formatPercent, listJoin, pluralize } from './util';

export const SEVERITY_LABELS: Readonly<Record<Severity, string>> = {
  info: 'Note',
  low: 'Minor',
  medium: 'Notable',
  high: 'Serious',
  critical: 'Critical',
};

export const CONFIDENCE_LABELS: Readonly<Record<Confidence, string>> = {
  high: 'Directly observed',
  medium: 'Measured, some inference',
  low: 'Partly inferred',
  unavailable: 'Not available to extensions',
};

const EMPTY_COUNTS: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };

export class ExplanationBuilder {
  /** Severity counts across findings; unmeasured signals never count as problems. */
  severityCounts(findings: readonly Finding[]): Record<Severity, number> {
    const counts: Record<Severity, number> = { ...EMPTY_COUNTS };
    for (const finding of findings) {
      if (finding.measured === null) continue;
      counts[finding.severity] += 1;
    }
    return counts;
  }

  /** Renders one finding for the UI, including its exact effect on the score. */
  describeFinding(finding: Finding, category?: CategoryScore): FindingView {
    const categoryLabel = category?.label ?? finding.categoryId;
    return {
      signalId: finding.signalId,
      categoryId: finding.categoryId,
      categoryLabel,
      title: finding.title,
      severity: finding.severity,
      severityLabel: SEVERITY_LABELS[finding.severity],
      confidence: finding.confidence,
      confidenceLabel: CONFIDENCE_LABELS[finding.confidence],
      detail: finding.detail,
      evidence: finding.evidence,
      remediation: finding.remediation ?? null,
      measured: finding.measured,
      measuredLabel: this.measuredLabel(finding),
      impact: finding.impact,
      maxImpact: finding.maxImpact,
      scoreEffect: this.scoreEffect(finding, categoryLabel),
    };
  }

  build(
    score: TrustScore | null,
    findings: readonly Finding[],
    categories: readonly CategoryScore[] = score?.categories ?? [],
    observation?: ObservationSummary,
  ): Explanation {
    const severityCounts = this.severityCounts(findings);
    const measurable = findings.filter((finding) => finding.measured !== null);
    const unavailable = findings.filter((finding) => finding.measured === null);

    if (!score) {
      return {
        headline: 'Not enough information yet',
        summary:
          'Sentinel could not measure anything about this page. Open or reload the page so it can observe the traffic the browser already makes, then try again.',
        severityCounts,
        breakdown: [],
        highlights: [],
        strengths: [],
        caveats: this.caveats(unavailable, observation),
        coverageNote: null,
        insufficientData: true,
      };
    }

    return {
      headline: this.headline(score),
      summary: this.summary(score, this.worstCategory(categories), severityCounts, this.highlights(measurable)),
      severityCounts,
      breakdown: categories.map((category) => this.breakdownLine(category)),
      highlights: this.highlights(measurable),
      strengths: this.strengths(measurable),
      caveats: this.caveats(unavailable, observation),
      coverageNote: this.coverageNote(score, categories),
      insufficientData: false,
    };
  }

  // ---------------------------------------------------------------- internals

  private headline(score: TrustScore): string {
    switch (score.grade.charAt(0)) {
      case 'A':
        return `Trustworthy (${score.grade}) — nothing serious to fix`;
      case 'B':
        return `Broadly sound (${score.grade}) — a few things to tighten`;
      case 'C':
        return `Mixed signals (${score.grade}) — several weaknesses`;
      case 'D':
        return `Weak (${score.grade}) — important protections are missing`;
      default:
        return `Do not trust this page (${score.grade})`;
    }
  }

  private summary(
    score: TrustScore,
    worst: CategoryScore | null,
    counts: Record<Severity, number>,
    highlights: readonly string[],
  ): string {
    const serious = counts.critical + counts.high;
    const parts: string[] = [`Sentinel gives this page ${score.value}/100 (${score.grade}).`];

    const first = highlights[0];
    if (first) parts.push(`Most important: ${first}`);

    if (serious > 0) {
      parts.push(`${pluralize(serious, 'finding')} rated serious or critical.`);
    } else if (worst && worst.score !== null && worst.score < 100) {
      parts.push(`The weakest area is ${worst.label.toLowerCase()} at ${worst.score}/100.`);
    } else {
      parts.push('Every check Sentinel could run came back clean.');
    }
    return parts.join(' ');
  }

  private highlights(findings: readonly Finding[]): string[] {
    return findings
      .filter((finding) => finding.impact >= 2 && SEVERITY_ORDER.indexOf(finding.severity) >= 1)
      .slice(0, 3)
      .map((finding) => (finding.detail.endsWith('.') ? finding.detail : `${finding.detail}.`));
  }

  private strengths(findings: readonly Finding[]): string[] {
    return findings
      .filter((finding) => finding.measured === 100)
      .map((finding) => `${finding.title}: ${finding.detail}`);
  }

  private caveats(findings: readonly Finding[], observation?: ObservationSummary): string[] {
    const caveats = findings.map((finding) => `${finding.title} could not be checked — ${finding.detail}`);
    if (observation) caveats.push(...observation.notes);
    return caveats;
  }

  private breakdownLine(category: CategoryScore): string {
    const scorePart = category.score === null ? 'not measurable' : `${category.score}/100`;
    const included = category.effectiveWeight > 0 ? `, ${formatPercent(category.effectiveWeight)} of this score` : '';
    return `${category.label} — ${scorePart} (model weight ${formatPercent(category.weight)}${included})`;
  }

  private coverageNote(score: TrustScore, categories: readonly CategoryScore[]): string | null {
    if (score.coverage >= 1) return null;
    const missing = categories.filter((category) => category.score === null).map((category) => category.label);
    const measured = categories.filter((category) => category.score !== null).map((category) => category.label);

    if (missing.length === 0) {
      return `Some individual checks were unavailable, so this score rests on ${formatPercent(score.coverage)} of the model's weight.`;
    }
    if (measured.length === 0) {
      return `No usable data for ${listJoin(missing)}. That is a gap in Sentinel's view, not a fault in the page.`;
    }
    return `This score rests on ${formatPercent(score.coverage)} of the model's weight: no usable data for ${listJoin(missing)}. It covers ${listJoin(measured)}. That gap is in Sentinel's view, not a fault in the page.`;
  }

  private worstCategory(categories: readonly CategoryScore[]): CategoryScore | null {
    let worst: CategoryScore | null = null;
    for (const category of categories) {
      if (category.score === null) continue;
      if (worst === null || worst.score === null || category.score < worst.score) worst = category;
    }
    return worst;
  }

  private measuredLabel(finding: Finding): string {
    if (finding.measured === null) return 'Not measured';
    if (finding.measured === 100) return 'Everything checked out';
    return `${finding.measured}/100 for this check`;
  }

  private scoreEffect(finding: Finding, categoryLabel: string): string {
    if (finding.measured === null) return 'No effect — this check was unavailable';
    const points = Math.round(finding.impact * 10) / 10;
    if (points === 0) return 'No points deducted';
    return `−${points} of ${finding.maxImpact} possible points from ${categoryLabel}`;
  }
}

/** Convenience wrapper for previews and tests: a grade for a raw number. */
export function gradeForValue(value: number): string {
  return scoreToGrade(value);
}
