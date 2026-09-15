/**
 * Cookie signals: what the page and its third parties planted in the cookie store.
 *
 * These are the Cookie Transparency module's scoring signals, fed by the background's cookie
 * observer (`src/background/cookie-observer.ts`). They follow the same honesty rules as every
 * other analyser: when cookies were not collected (`cookiesCollected === false` — module off,
 * unanalysable page, or the observer has not run), every signal here reports `measured: null`
 * rather than "no cookies" (D-006); a run that found only essential or unknown cookies measures
 * 100 (D-007's third justification: reading cookies is the module's function, not a finding).
 *
 * The three signals map onto the brief's five verdicts:
 *
 *   cookies.tracking     -> COOKIES_NONE_OR_ESSENTIAL | COOKIES_TRACKING_PRESENT | COOKIES_TRACKING_HEAVY
 *   cookies.third-party  -> COOKIES_THIRD_PARTY_PRESENT (evidence) | clean when none
 *   cookies.persistence  -> COOKIES_LONG_PERSISTENCE (evidence) | clean when none
 */

import { assessment, countLabel, evidence, evidenceList, quality, unavailable } from './shared';
import type { AnalysisContext, SignalAnalyzer } from '../../../shared/analysis';
import type { ClassifiedCookie, CookieSummary, SignalAssessment } from '../../../core/types';
import { classifyCookies } from '../../../background/cookie-classifier';

const DAY_MS = 86_400_000;
/** The threshold the brief sets for COOKIES_LONG_PERSISTENCE: more than a year. */
export const LONG_PERSISTENCE_DAYS = 365;

/** Cost curve for the tracking-count signal: 1–2 tracking cookies are mild, 3+ is heavy. */
function trackingQuality(trackingCount: number): number {
  if (trackingCount === 0) return 100;
  if (trackingCount <= 2) return 75;
  return quality([Math.max(10, 60 - 6 * (trackingCount - 3))]);
}

function thirdPartyQuality(thirdPartyCount: number): number {
  if (thirdPartyCount === 0) return 100;
  return Math.max(20, 80 - 10 * (thirdPartyCount - 1));
}

/** "Session cookie" or "expires in N days", for evidence rows and the detail sentences. */
export function cookieLifetimeLabel(cookie: ClassifiedCookie, now: number = Date.now()): string {
  if (cookie.session) return 'session cookie';
  if (typeof cookie.expirationDate !== 'number') return 'no expiry reported';
  const days = Math.max(0, Math.round((cookie.expirationDate * 1000 - now) / DAY_MS));
  return days === 1 ? 'expires in 1 day' : `expires in ${days} days`;
}

function trackingBreakdown(summary: CookieSummary): string {
  return [
    `${summary.advertising} advertising`,
    `${summary.analytics} analytics`,
    `${summary.social} social`,
  ].join(', ');
}

/**
 * "_fbp from Meta lasts 90 days and is used for advertising" — the plain-language highlight
 * the brief asks each tracking-cookie finding to carry. Picks the longest-lasting known
 * tracking cookie so the sentence names the most consequential example.
 */
function notableTrackingLine(cookies: readonly ClassifiedCookie[], now: number): string | null {
  const known = cookies
    .filter((cookie) => cookie.known && cookie.category !== 'essential' && cookie.category !== 'unknown')
    .sort((a, b) => (b.expirationDate ?? 0) - (a.expirationDate ?? 0));
  const cookie = known[0];
  if (!cookie) return null;
  const lifetime = cookie.session
    ? 'lasts for the session'
    : typeof cookie.expirationDate === 'number'
      ? `lasts ${Math.max(1, Math.round((cookie.expirationDate * 1000 - now) / DAY_MS))} days`
      : 'has no reported expiry';
  return `${cookie.name} from ${cookie.setBy} ${lifetime} and is used for ${cookie.category}`;
}

function trackingAssessment(cookies: readonly ClassifiedCookie[], summary: CookieSummary, now: number): SignalAssessment {
  const signalId = 'cookies.tracking';
  const title = 'Tracking cookies';
  const trackingCount = summary.analytics + summary.advertising + summary.social;

  const rows = [
    evidence('Tracking cookies', String(trackingCount)),
    evidence('Advertising', String(summary.advertising)),
    evidence('Analytics', String(summary.analytics)),
    evidence('Social', String(summary.social)),
    evidence('Essential or unknown', String(summary.total - trackingCount)),
  ];

  if (trackingCount === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail: `No tracking cookies were set: all ${countLabel(summary.total, 'cookie')} on this page are essential or of unknown purpose.`,
      evidence: evidenceList(rows),
    });
  }

  const notable = notableTrackingLine(cookies, now);
  return assessment({
    signalId,
    title,
    measured: trackingQuality(trackingCount),
    confidence: 'high',
    detail:
      `${countLabel(trackingCount, 'tracking cookie')} detected (${trackingBreakdown(summary)}).` +
      (notable === null ? '' : ` ${notable}.`),
    evidence: evidenceList([
      ...rows,
      ...cookies
        .filter((cookie) => cookie.category !== 'essential' && cookie.category !== 'unknown')
        .slice(0, 6)
        .map((cookie) =>
          evidence(`${cookie.name} (${cookie.setBy})`, `${cookie.category} - ${cookieLifetimeLabel(cookie, now)} - ${cookie.description}`),
        ),
    ]),
  });
}

function thirdPartyAssessment(cookies: readonly ClassifiedCookie[], summary: CookieSummary, now: number): SignalAssessment {
  const signalId = 'cookies.third-party';
  const title = 'Third-party cookies';

  if (summary.thirdPartyCount === 0) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail: 'Every cookie on this page is set by the site you are visiting; no third party planted one.',
      evidence: evidenceList([evidence('Third-party cookies', 'none')]),
    });
  }

  const setters = Array.from(new Set(cookies.filter((cookie) => !cookie.firstParty).map((cookie) => cookie.setBy)));
  return assessment({
    signalId,
    title,
    measured: thirdPartyQuality(summary.thirdPartyCount),
    confidence: 'high',
    detail: `${countLabel(summary.thirdPartyCount, 'third-party cookie')} detected, set by ${setters.slice(0, 4).join(', ')}${setters.length > 4 ? ` and ${setters.length - 4} more` : ''}.`,
    evidence: evidenceList([
      evidence('Third-party cookies', String(summary.thirdPartyCount)),
      evidence('Setters', setters.join(', ')),
      ...cookies
        .filter((cookie) => !cookie.firstParty)
        .slice(0, 6)
        .map((cookie) => evidence(cookie.name, `${cookie.setBy} - ${cookie.domain} - ${cookieLifetimeLabel(cookie, now)}`)),
    ]),
  });
}

function persistenceAssessment(summary: CookieSummary): SignalAssessment {
  const signalId = 'cookies.persistence';
  const title = 'Cookie persistence';

  if (summary.longestExpirationDays <= LONG_PERSISTENCE_DAYS) {
    return assessment({
      signalId,
      title,
      measured: 100,
      confidence: 'high',
      detail:
        summary.persistentCount === 0
          ? 'Every cookie on this page is a session cookie that disappears when the browser closes.'
          : `No cookie outlives a year; the longest lasts ${countLabel(summary.longestExpirationDays, 'day')}.`,
      evidence: evidenceList([
        evidence('Session cookies', String(summary.total - summary.persistentCount)),
        evidence('Persistent cookies', String(summary.persistentCount)),
        evidence(
          'Longest lifetime',
          summary.longestExpirationDays > 0
            ? `${summary.longestExpirationName} - ${summary.longestExpirationDays} days`
            : 'none expire',
        ),
      ]),
    });
  }

  return assessment({
    signalId,
    title,
    measured: 75,
    confidence: 'high',
    detail: `${summary.longestExpirationName} lasts ${countLabel(summary.longestExpirationDays, 'day')}, which is longer than a year and typical of a cross-site identifier.`,
    evidence: evidenceList([
      evidence('Persistent cookies', String(summary.persistentCount)),
      evidence('Longest lifetime', `${summary.longestExpirationName} - ${summary.longestExpirationDays} days`),
    ]),
  });
}

function cookieAssessments(context: AnalysisContext): SignalAssessment[] {
  if (context.observation.cookiesCollected !== true) {
    const reason = 'Cookie analysis is switched off in settings, or the cookie store has not been read for this page yet.';
    return [
      unavailable('cookies.tracking', 'Tracking cookies', reason),
      unavailable('cookies.third-party', 'Third-party cookies', reason),
      unavailable('cookies.persistence', 'Cookie persistence', reason),
    ];
  }

  const records = context.observation.cookies ?? [];
  const { cookies, summary } = classifyCookies(records, context.now);
  return [
    trackingAssessment(cookies, summary, context.now),
    thirdPartyAssessment(cookies, summary, context.now),
    persistenceAssessment(summary),
  ];
}

export const cookieAnalyzer: SignalAnalyzer = {
  id: 'cookies',
  moduleId: 'cookie-transparency',

  analyze(context) {
    return cookieAssessments(context);
  },
};


