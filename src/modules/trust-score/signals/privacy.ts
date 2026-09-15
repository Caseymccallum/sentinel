/**
 * Privacy signals: what the page told other people about you.
 *
 * These four signals are the reason the Phase 1 weights put privacy highest (see
 * `docs/SCORING.md` 2.1). They are also the only signals fed by the content script, which means
 * they have to be honest about a gap: when the page's resource timings were never collected,
 * every signal here reports `measured: null` rather than "no third parties found" - "nobody
 * looked" and "nobody was contacted" are different facts (see `PageObservation.resourcesCollected`).
 */

import { assessment, countLabel, evidence, evidenceList, quality, sampleList, unavailable } from './shared';
import {
  pageObserved,
  resourcesCollected,
  type AnalysisContext,
  type SignalAnalyzer,
  type TrackerHit,
} from '../../../shared/analysis';
import type { TrackerCategory } from '../../../shared/trackers';
import type { SignalAssessment } from '../../../core/types';

/**
 * Cost of one recognised tracker, by what the operator does with the data.
 *
 * Advertising and session recording are the most invasive: one profiles you across sites, the
 * other can capture what you type. An analytics pixel is still a disclosure of the page you are
 * reading, but a narrower one. Monitoring tags are cheapest of all, because an error reporter or
 * a chat widget usually serves the site you are already on.
 */
const TRACKER_COST: Readonly<Record<TrackerCategory, number>> = {
  advertising: 20,
  'session-replay': 20,
  fingerprinting: 18,
  social: 16,
  analytics: 12,
  monitoring: 8,
};

/** Chasing the same host repeatedly is a stronger signal than loading it once. */
const REPEAT_REQUEST_COST = 3;

/** How many tracker rows the drill-down carries before it summarises the rest. */
const MAX_TRACKER_EVIDENCE = 8;

function trackerCost(hit: TrackerHit): number {
  const base = TRACKER_COST[hit.match.category] ?? 8;
  return base + (hit.requestCount > 1 ? REPEAT_REQUEST_COST : 0);
}

/** "Google Analytics (analytics), Meta Pixel (social)" - vendor names first. */
function describeTrackers(hits: readonly TrackerHit[]): string {
  return hits.map((hit) => `${hit.match.name} (${hit.match.categoryLabel.toLowerCase()})`).join(', ');
}

function trackerEvidence(hits: readonly TrackerHit[]): ReturnType<typeof evidenceList> {
  const rows = hits.slice(0, MAX_TRACKER_EVIDENCE).map((hit) =>
    evidence(
      hit.match.name,
      `${hit.hostname} - ${sampleList(hit.kinds, 3)} - ${countLabel(hit.requestCount, 'request')} - ${hit.match.description}`,
    ),
  );
  if (hits.length > MAX_TRACKER_EVIDENCE) {
    rows.push(evidence('Also contacted', `${hits.length - MAX_TRACKER_EVIDENCE} more known tracker hosts`));
  }
  return evidenceList(rows);
}
function trackerAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'privacy.trackers';
  const title = 'Third-party tracking';
  const hits = context.requests.trackers;

  if (!pageObserved(context)) {
    return unavailable(
      signalId,
      title,
      'Sentinel did not observe this page load at all, so it cannot say which hosts the page contacted.',
    );
  }

  if (!resourcesCollected(context)) {
    return unavailable(
      signalId,
      title,
      "The page's own resource timings had not been collected, so Sentinel could not tell which hosts this page contacted.",
    );
  }

  const thirdPartyHits = hits.filter((hit) => hit.thirdParty);
  const total = hits.reduce((sum, hit) => sum + trackerCost(hit), 0);
  const worstCategory = hits
    .map((hit) => hit.match.category)
    .sort((a, b) => (TRACKER_COST[b] ?? 0) - (TRACKER_COST[a] ?? 0))[0];
  const worstCost = worstCategory ? (TRACKER_COST[worstCategory] ?? 0) : 0;

  if (hits.length === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail:
        context.requests.total === 0
          ? 'No resources were loaded from another host, so nothing on this page reported your visit elsewhere.'
          : `None of the ${countLabel(context.requests.total, 'resource')} this page loaded came from a known tracker.`,
      evidence: evidenceList([
        evidence('Known trackers contacted', 'none'),
        evidence('Resources seen', countLabel(context.requests.total, 'resource')),
      ]),
    });
  }

  return assessment({
    signalId,
    title,
    measured: quality([total]),
    confidence: 'high',
    detail:
      `${countLabel(hits.length, 'known tracker host')} contacted: ${describeTrackers(hits)}. ` +
      (worstCost >= 18
        ? 'Hosts in this category can build a profile of you that follows you to other sites.'
        : 'These hosts learn which pages you read.'),
    evidence: evidenceList([
      evidence('Known trackers contacted', String(hits.length)),
      evidence('Tracker requests', String(context.requests.trackerRequests)),
      evidence('Third-party hosts among them', `${thirdPartyHits.length} of ${hits.length}`),
      ...trackerEvidence(hits),
    ]),
    remediation:
      'Remove tags you do not need, self-host analytics, and load any remaining third-party scripts only after the visitor opts in.',
  });
}

function thirdPartySurfaceAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'privacy.third-party-surface';
  const title = 'Third-party surface';
  const hosts = context.requests.thirdPartyHosts;

  if (!pageObserved(context)) {
    return unavailable(
      signalId,
      title,
      'Sentinel did not observe this page load at all, so it cannot count the hosts it contacted.',
    );
  }

  if (!resourcesCollected(context)) {
    return unavailable(
      signalId,
      title,
      'Sentinel has not seen the list of hosts this page contacted yet, so it cannot count them.',
    );
  }

  // Four points a host: one extra CDN is a note, fifteen is the whole problem, and this
  // category's budget (20 points) is exhausted at five hosts.
  const deduction = hosts.length * 4;
  const insecure = hosts.filter((host) =>
    context.requests.insecureSubresources.some((request) => request.hostname === host),
  );

  return assessment({
    signalId,
    title,
    measured: quality([deduction]),
    confidence: 'high',
    detail:
      hosts.length === 0
        ? 'This page loaded everything it needed from its own domain, so no third party learned your IP address from it.'
        : `This page contacted ${countLabel(hosts.length, 'third-party host')}: ${sampleList(hosts, 5)}.`,
    evidence: evidenceList([
      evidence('Distinct third-party hosts', String(hosts.length)),
      evidence('Third-party requests', String(context.requests.thirdPartyRequests)),
      evidence('First-party requests', String(context.requests.firstPartyRequests)),
      evidence('Insecure hosts among them', insecure.length > 0 ? sampleList(insecure, 5) : null),
    ]),
    remediation:
      hosts.length === 0
        ? undefined
        : 'Self-host fonts, scripts and analytics where you can; every host you remove is one fewer party that sees your visitors.',
  });
}
/** How far a `Referrer-Policy` value lets a URL travel to a third party. */
const REFERRER_FULL_URL = new Set(['unsafe-url', 'no-referrer-when-downgrade', 'origin-when-cross-origin']);
const REFERRER_ORIGIN_ONLY = new Set(['origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']);
const REFERRER_NONE = new Set(['no-referrer']);

function referrerPolicyCost(policy: string | null): { cost: number; sentence: string } {
  const normalised = (policy ?? '').trim().toLowerCase();
  if (normalised === '') {
    return {
      cost: 14,
      sentence: 'No Referrer-Policy was sent, so the browser decides how much of the URL travels with each request.',
    };
  }
  if (REFERRER_NONE.has(normalised)) {
    return {
      cost: 0,
      sentence: 'Referrer-Policy is set to no-referrer, so no URL travels with outgoing requests.',
    };
  }
  if (REFERRER_ORIGIN_ONLY.has(normalised)) {
    return {
      cost: 6,
      sentence: `Referrer-Policy is ${normalised}, so third parties learn the site you came from but not the page.`,
    };
  }
  if (REFERRER_FULL_URL.has(normalised)) {
    return {
      cost: 30,
      sentence: `Referrer-Policy is ${normalised}, so the full URL of this page - including its path - is sent to every third party it contacts.`,
    };
  }
  return {
    cost: 14,
    sentence: `Referrer-Policy is "${policy}", which Sentinel does not recognise as a restriction on what third parties receive.`,
  };
}

function referrerLeakageAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'privacy.referrer-leakage';
  const title = 'Referrer leakage';
  const headerAvailable = context.observation.mainDocument !== null && context.headers.count > 0;

  if (!headerAvailable) {
    return unavailable(
      signalId,
      title,
      'The response headers were not captured, so Sentinel could not read the Referrer-Policy this page sends.',
    );
  }

  const policy = context.headers.get('referrer-policy');
  const { cost, sentence } = referrerPolicyCost(policy);

  if (!resourcesCollected(context)) {
    return assessment({
      signalId,
      title,
      measured: null,
      confidence: 'medium',
      detail: `${sentence} Sentinel has not seen which hosts were contacted yet, so it cannot say whether anything leaked to them.`,
      evidence: evidenceList([evidence('Referrer-Policy', policy ?? 'absent')]),
    });
  }

  // Leakage needs somebody to leak to: a page that contacts no third party sends its URL to its
  // own server and nowhere else.
  const thirdPartyHosts = context.requests.thirdPartyHosts;
  const effectiveCost = thirdPartyHosts.length === 0 ? 0 : cost;

  return assessment({
    signalId,
    title,
    measured: quality([effectiveCost]),
    confidence: 'high',
    detail:
      thirdPartyHosts.length === 0
        ? `${sentence} No third-party host was contacted, so there was nowhere for the URL to leak.`
        : `${sentence} ${countLabel(thirdPartyHosts.length, 'third-party host')} received it.`,
    evidence: evidenceList([
      evidence('Referrer-Policy', policy ?? 'absent'),
      evidence('Third-party hosts', String(thirdPartyHosts.length)),
    ]),
    remediation:
      effectiveCost === 0
        ? undefined
        : 'Send `Referrer-Policy: strict-origin-when-cross-origin`, or `no-referrer` if this page does not need referral data.',
  });
}
function backgroundBeaconsAssessment(context: AnalysisContext): SignalAssessment {
  const signalId = 'privacy.background-beacons';
  const title = 'Background beacons';
  const requestsSeen = resourcesCollected(context);
  const domAvailable = context.dom !== null;

  if (!pageObserved(context)) {
    return unavailable(
      signalId,
      title,
      'Sentinel did not observe this page load at all, so it could not look for beacons.',
    );
  }

  if (!requestsSeen && !domAvailable) {
    return unavailable(
      signalId,
      title,
      'Neither the page report nor its resource timings arrived, so Sentinel could not look for beacons.',
    );
  }

  const beacons = context.requests.beaconRequests;
  const pingAttributes = context.dom?.pingAttributeCount ?? 0;
  const speculative = context.dom?.speculativeUrls ?? [];
  const dnsPrefetch = context.dom?.dnsPrefetchHosts ?? [];

  const deductions: number[] = [];
  if (beacons.length > 0) deductions.push(Math.min(60, beacons.length * 15));
  if (pingAttributes > 0) deductions.push(Math.min(45, pingAttributes * 15));
  if (speculative.length > 0) deductions.push(Math.min(20, speculative.length * 4));
  if (dnsPrefetch.length > 0) deductions.push(Math.min(15, dnsPrefetch.length * 3));

  const silent: string[] = [];
  if (beacons.length > 0) silent.push(`${countLabel(beacons.length, 'beacon request')} (ping or sendBeacon)`);
  if (pingAttributes > 0) silent.push(`${countLabel(pingAttributes, 'link')} with a ping attribute`);
  if (speculative.length > 0) silent.push(`${countLabel(speculative.length, 'speculative load')}`);
  if (dnsPrefetch.length > 0) {
    silent.push(`${countLabel(dnsPrefetch.length, 'DNS prefetch')} for ${sampleList(dnsPrefetch, 3)}`);
  }

  return assessment({
    signalId,
    title,
    measured: quality(deductions),
    confidence: domAvailable && requestsSeen ? 'high' : 'medium',
    detail:
      silent.length === 0
        ? 'Nothing on this page reported activity in the background: no beacons, no ping links and no speculative connections.'
        : `This page reports activity in the background: ${silent.join('; ')}.`,
    evidence: evidenceList([
      evidence('Beacon requests', String(beacons.length)),
      evidence('Ping attributes', String(pingAttributes)),
      evidence('Speculative loads', String(speculative.length)),
      evidence('DNS prefetch hosts', dnsPrefetch.length > 0 ? sampleList(dnsPrefetch, 5) : 'none'),
    ]),
    remediation:
      deductions.length === 0
        ? undefined
        : 'Drop the `<a ping>` attributes, sendBeacon calls and speculative prefetch/preconnect hints the page does not need.',
  });
}

export const privacyAnalyzer: SignalAnalyzer = {
  id: 'privacy',
  moduleId: 'trust-score',

  analyze(context) {
    return [
      trackerAssessment(context),
      thirdPartySurfaceAssessment(context),
      referrerLeakageAssessment(context),
      backgroundBeaconsAssessment(context),
    ];
  },
};