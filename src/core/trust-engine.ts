/**
 * TrustEngine — one observation in, one `ScanResult` out.
 *
 * The engine is deliberately dull. It builds the analysis context, runs the registered
 * analysers (catching anything that throws, so one broken signal cannot blank the report),
 * hands the measurements to `ScoringModel`, and asks `ExplanationBuilder` to put the
 * outcome into plain language. Every number in the result comes from the model and every
 * sentence from the explanation builder; the engine only decides *what was looked at*.
 *
 * Nothing here touches a browser API, storage or the network: the engine is pure apart
 * from the injected clock, which is what lets the whole scoring pipeline be unit-tested
 * against a hand-built `PageObservation`.
 */

import { buildAnalysisContext, type AnalysisContext, type SignalAnalyzer } from '../shared/analysis';
import { MAX_TRACKED_REQUESTS, type PageObservation } from '../shared/observation';
import { classifyCookies } from '../background/cookie-classifier';
import { toStoredUrl } from './domain';
import { ExplanationBuilder } from './explanation-builder';
import { MODULES } from './modules';
import { buildHeaderDashboard } from '../modules/header-dashboard/dashboard';
import { CATEGORIES, ScoringModel } from './scoring-model';
import type {
  CookieReport,
  ModuleId,
  ModuleRunStatus,
  ObservationSummary,
  ScanResult,
  SignalAssessment,
} from './types';
import { createId, round } from './util';

export interface TrustEngineOptions {
  /** Analysers to run, in order. A module with no analyser simply never reports findings. */
  analyzers: readonly SignalAnalyzer[];
  /** Replaced by tests that need different weights, impacts or a fixed model version. */
  model?: ScoringModel;
  explanations?: ExplanationBuilder;
  /** Injected clock, so scan ids and durations stay predictable under test. */
  clock?: () => number;
}

export interface RunOptions {
  /** Modules the user has switched on. Omitted means every module is allowed to run. */
  enabledModules?: readonly ModuleId[];
  /** Id to reuse, when the caller already assigned one per navigation. */
  scanId?: string;
  /** When Sentinel started watching this page load; defaults to the observation's own start. */
  startedAt?: number;
  /** Overrides the injected clock for this run. */
  now?: number;
}

export class TrustEngine {
  readonly model: ScoringModel;
  readonly explanations: ExplanationBuilder;

  private readonly analyzers: readonly SignalAnalyzer[];
  private readonly clock: () => number;

  constructor(options: TrustEngineOptions) {
    this.analyzers = options.analyzers;
    this.model = options.model ?? new ScoringModel();
    this.explanations = options.explanations ?? new ExplanationBuilder();
    this.clock = options.clock ?? (() => Date.now());
  }

  /** Analyser ids in registration order; the options page shows these as coverage. */
  analyzerIds(): string[] {
    return this.analyzers.map((analyzer) => analyzer.id);
  }

  /** Runs every enabled analyser once and reduces the outcome to a `ScanResult`. */
  run(observation: PageObservation, options: RunOptions = {}): ScanResult {
    const now = options.now ?? this.clock();
    const startedAt = options.startedAt ?? observation.startedAt;
    const enabled = new Set<ModuleId>(options.enabledModules ?? MODULES.map((module) => module.id));
    const context = buildAnalysisContext(observation, now);

    const warnings: string[] = [...observation.warnings];
    const statuses: ModuleRunStatus[] = MODULES.map((module) => ({
      id: module.id,
      enabled: enabled.has(module.id),
      state: module.state,
      ran: false,
    }));
    const statusById = new Map<ModuleId, ModuleRunStatus>(
      statuses.map((status) => [status.id, status]),
    );

    const assessments: SignalAssessment[] = [];
    /** Which analyser claimed each signal id, so a duplicate can be reported rather than merged. */
    const claimed = new Map<string, string>();

    for (const analyzer of this.analyzers) {
      const status = statusById.get(analyzer.moduleId);
      if (!status) {
        warnings.push(
          `Analyser "${analyzer.id}" belongs to unknown module "${analyzer.moduleId}" and was skipped.`,
        );
        continue;
      }
      if (!status.enabled) continue;

      try {
        const produced = analyzer.analyze(context);
        status.ran = true;
        for (const candidate of produced) {
          const owner = claimed.get(candidate.signalId);
          if (owner) {
            warnings.push(
              `Signal "${candidate.signalId}" was reported by both "${owner}" and "${analyzer.id}"; the first measurement was kept.`,
            );
            continue;
          }
          claimed.set(candidate.signalId, analyzer.id);
          assessments.push(candidate);
        }
      } catch (error) {
        status.error = errorMessage(error);
        warnings.push(`The ${analyzer.id} analyser failed (${status.error}). The other checks still ran.`);
      }
    }

    return this.finish(observation, context, assessments, statuses, enabled, warnings, {
      now,
      startedAt,
      scanId: options.scanId,
    });
  }

  /** Turns raw measurements into the scored, explained, serialisable result. */
  private finish(
    observation: PageObservation,
    context: AnalysisContext,
    assessments: readonly SignalAssessment[],
    statuses: ModuleRunStatus[],
    enabled: ReadonlySet<ModuleId>,
    warnings: string[],
    timing: { now: number; startedAt: number; scanId?: string },
  ): ScanResult {
    // `ScoringModel.score()` derives these findings internally as well. Both calls are pure,
    // cheap and fed the same assessments, which keeps the headline number and the
    // per-finding sentence describing it in step.
    const { findings, unknownSignalIds } = this.model.toFindings(assessments);
    for (const signalId of unknownSignalIds) {
      warnings.push(
        `Signal "${signalId}" is not part of scoring model ${this.model.version}; its measurement was ignored.`,
      );
    }

    const score = this.model.score(assessments, { enabledCategories: enabledCategoryIds(enabled) });
    const observationSummary = summarizeObservation(observation, context);
    const cookies = buildCookieReport(observation, timing.now);
    // The Header Dashboard (D-009) is informational: it rides on the same scan, but nothing it
    // produces can enter the score. Built whenever its module is on, even when nothing was
    // observed — `available: false` is the popup's cue to say "did not observe", not to imply gaps.
    const headers = enabled.has('header-dashboard') ? buildHeaderDashboard(observation.mainDocument) : null;
    if (headers !== null) {
      const headerStatus = statuses.find((status) => status.id === 'header-dashboard');
      if (headerStatus) headerStatus.ran = true;
    }
    const explanation = this.explanations.build(
      score,
      findings,
      score?.categories ?? [],
      observationSummary,
    );

    return {
      scanId: timing.scanId ?? createId('scan-'),
      // The Change Monitor persists this record, so query strings and fragments are dropped
      // first: they routinely carry session tokens, and Sentinel promises never to keep them.
      url: toStoredUrl(observation.url) || observation.url,
      // Profiles are keyed by registrable domain, so `www.example.com` and `shop.example.com`
      // share one history instead of fragmenting it.
      domain: context.page.siteDomain || observation.hostname,
      origin: context.page.origin || observation.origin,
      isSecureContext: context.page.isSecureContext,
      scannedAt: timing.now,
      durationMs: round(Math.max(0, timing.now - timing.startedAt), 1),
      modules: statuses,
      score,
      explanation,
      findings,
      observation: observationSummary,
      cookies,
      headers,
      warnings,
    };
  }
}

/**
 * Builds the `ScanResult`'s cookie report, or `null` when cookies were never enumerated.
 *
 * `null` — like `measured: null` for a signal — means "could not look" (module off, page not
 * analysed, observer failed), never "no cookies". The classified records carry metadata only;
 * the observer has already dropped the values by the time anything reaches the engine (D-007).
 */
function buildCookieReport(observation: PageObservation, now: number): CookieReport | null {
  if (observation.cookiesCollected !== true) return null;
  const { cookies, summary } = classifyCookies(observation.cookies ?? [], now);
  return { collected: true, cookies, summary };
}

/** Categories belonging to modules the user has switched on. */
function enabledCategoryIds(enabled: ReadonlySet<ModuleId>): string[] {
  return CATEGORIES.filter((category) => enabled.has(category.moduleId)).map((category) => category.id);
}

/**
 * The evidence trail behind "what did Sentinel actually look at": counts from the
 * observation plus plain notes about anything that was missing.
 *
 * Nothing here is a verdict. A gap in Sentinel's view is reported as a note and shows up in
 * the explanation as a caveat; it never removes points from the score.
 */
export function summarizeObservation(
  observation: PageObservation,
  context: AnalysisContext,
): ObservationSummary {
  const mainDocument = observation.mainDocument;
  const notes: string[] = [];

  if (!mainDocument) {
    notes.push('Sentinel did not observe this page load, so its response headers and connection details are unknown.');
  } else if (mainDocument.tls === null) {
    notes.push('The browser had not finished reporting the connection details for this response.');
  }
  if (mainDocument?.tls && mainDocument.tls.source === 'none') {
    notes.push('This browser does not expose negotiated TLS details to extensions.');
  }
  if (!observation.dom) {
    notes.push('No page report arrived from the content script, so checks that need the page itself were skipped.');
  }
  if (observation.resourcesCollected === false) {
    notes.push("The page's own resource timings had not been collected when this score was taken, so third-party checks are still running.");
  }
  if (observation.requestsTruncated) {
    notes.push(`Only the first ${MAX_TRACKED_REQUESTS} requests were recorded, so request counts are a lower bound.`);
  }

  return {
    observed: mainDocument !== null,
    scheme: context.page.scheme,
    statusCode: mainDocument?.statusCode ?? null,
    statusLine: mainDocument?.statusLine ?? null,
    serverIp: mainDocument?.serverIp ?? null,
    fromCache: mainDocument?.fromCache ?? false,
    tls: mainDocument?.tls ?? null,
    headerCount: context.headers.count,
    // The merged count: the background's request records plus the page's own resource timings,
    // which is the same list the privacy analysers reason about.
    requestCount: context.requests.total,
    thirdPartyHostCount: context.requests.thirdPartyHosts.length,
    trackerCount: context.requests.trackers.length,
    domReportAvailable: observation.dom !== null,
    resourcesCollected: observation.resourcesCollected !== false,
    frameCount: observation.dom?.iframes.length ?? 0,
    notes,
  };
}

/** A message worth showing the user, whatever an analyser happened to throw. */
function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message || error.name;
  if (typeof error === 'string' && error.trim() !== '') return error.trim();
  return 'unknown error';
}