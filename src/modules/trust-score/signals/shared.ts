/**
 * Small, shared helpers for signal analysers.
 *
 * Every analyser reports a 0-100 **quality** value (100 = nothing wrong) plus the evidence
 * behind that number. These helpers keep the vocabulary identical across analysers so that
 * two people reading two different files see the same shape of output.
 */

import type { Confidence, Evidence, SignalAssessment } from '../../../core/types';
import { clamp, round } from '../../../core/util';

/** Evidence rows with empty values are dropped rather than rendered as blank lines. */
export function evidence(label: string, value: string | number | null | undefined): Evidence | null {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (text === '') return null;
  return { label, value: text };
}

/** Compacts a list of evidence rows, dropping the empty ones. */
export function evidenceList(rows: readonly (Evidence | null)[]): Evidence[] {
  return rows.filter((row): row is Evidence => row !== null);
}

/**
 * Turns deductions into a quality value. Each deduction is a number of points to remove;
 * the result never goes below 0 or above 100.
 */
export function quality(deductions: readonly number[], rounds = 0): number {
  const total = deductions.reduce((sum, value) => sum + value, 0);
  return round(clamp(100 - total, 0, 100), rounds);
}

/** A signal the browser would not let Sentinel see. Never scored, never a problem. */
export function unavailable(
  signalId: string,
  title: string,
  detail: string,
  evidence: Evidence[] = [],
): SignalAssessment {
  return { signalId, title, measured: null, confidence: 'unavailable', detail, evidence };
}

export interface AssessmentInput {
  signalId: string;
  title: string;
  measured: number | null;
  confidence: Confidence;
  detail: string;
  evidence?: Evidence[];
  remediation?: string;
}

export function assessment(input: AssessmentInput): SignalAssessment {
  const result: SignalAssessment = {
    signalId: input.signalId,
    title: input.title,
    measured: input.measured,
    confidence: input.confidence,
    detail: input.detail,
    evidence: input.evidence ?? [],
  };
  if (input.remediation) result.remediation = input.remediation;
  return result;
}

/** `2 hosts` / `1 host`, without importing the plural-aware helpers twice. */
export function countLabel(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Truncates a list for a one-sentence detail line. */
export function sampleList(items: readonly string[], max = 3): string {
  if (items.length === 0) return '';
  if (items.length <= max) return items.join(', ');
  return `${items.slice(0, max).join(', ')} and ${items.length - max} more`;
}