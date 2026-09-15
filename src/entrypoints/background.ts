/**
 * The background service worker: Sentinel's only always-on component.
 *
 * It observes (never interferes) and it orchestrates. The whole pipeline is:
 *
 *   webRequest.onHeadersReceived(main_frame)  -> per-tab response headers + status line
 *   tabs.onUpdated(status === 'complete')     -> score what is known *now*, publish it
 *                                             -> ask the content script for a page report
 *   runtime.onMessage(MSG_REPORT)             -> fold the report in, score again, publish
 *   runtime.onMessage(MSG_GET_SCORE)          -> answer the popup immediately, from storage
 *   tabs.onRemoved                            -> forget the tab
 *
 * Three properties matter here, and each is a deliberate choice rather than an accident:
 *
 *   1. **The popup is never blocked.** A score is published as soon as the response headers are
 *      known, with the tracker and form checks reported as still running, and replaced by a fuller
 *      score when the content script answers (`MSG_SCORE_UPDATED` tells an open popup to redraw).
 *   2. **Nothing is inferred from silence.** Until a content script reports, `resourcesCollected`
 *      is `false`, so the analysers say "not measured" instead of "clean" (see D-006).
 *   3. **The worker never makes a request.** It reads headers of requests the page already made,
 *      through a listener filtered to `main_frame`. `check-local-only` enforces the rest.
 *
 * Scores live in `browser.storage.session`, keyed by tab id, so they are gone when the browser
 * closes: this is per-tab state, not history.
 */

import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import { MAX_HEADER_ENTRIES, MAX_HEADER_VALUE_LENGTH, type HeaderEntry } from '../shared/observation';
import {
  MSG_COLLECT,
  MSG_FORGET_ALL_PROFILES,
  MSG_FORGET_SITE,
  MSG_GET_EXTENSION_AUDIT,
  MSG_LIST_PROFILES,
  MSG_SCORE,
  MSG_SCORE_UPDATED,
  isContentReport,
  isCookieRemovalRequest,
  isExtensionAuditRequest,
  isForgetProfileRequest,
  isForgetAllProfilesRequest,
  isForgetSiteRequest,
  isListProfilesRequest,
  isRescanRequest,
  isScoreRequest,
  type ExtensionAuditResponse,
  type ForgetAllProfilesResponse,
  type ForgetSiteResponse,
  type ListProfilesResponse,
  type ScoreResponse,
} from '../shared/messages';
import { defaultSettings, isModuleEnabled, loadSettings, type SentinelSettings } from '../shared/settings';
import { mergeRequests } from '../shared/collect';
import { summarizeRequests } from '../shared/analysis';
import { getSiteDomain, parseUrl } from '../core/domain';
import {
  applyContentReport,
  applyCookieRecords,
  applyHeaderObservation,
  buildObservation,
  createTabState,
  isAnalysableUrl,
  selectResponseHeaders,
  sessionKey,
  type TabState,
} from '../background/tab-state';
import { getCookiesForTab, createCookieObserverDeps } from '../background/cookie-observer';
import { removalUrlFor } from '../background/cookie-classifier';
import { DomainProfileStore, summarizeProfile } from '../core/domain-profile';
import { createBrowserProfileAdapter } from '../storage/profile-adapter';
import { auditExtensions, type AuditableExtension } from '../modules/extension-auditor/auditor';
import { TRUST_SCORE_ANALYZERS } from '../modules/trust-score/signals';
import { TrustEngine } from '../core/trust-engine';
import { createId } from '../core/util';

type ScanResult = NonNullable<TabState['result']>;

const engine = new TrustEngine({ analyzers: TRUST_SCORE_ANALYZERS });

/** Remembers what has been collected per tab, so a header event and a report can be joined. */
const states = new Map<number, TabState>();

/** Module toggles, cached between scans and refreshed at startup and on rescan requests. */
let settings: SentinelSettings = defaultSettings();
const cookieObserverDeps = createCookieObserverDeps();
/** Per-domain history, persisted through the storage adapter (D-008). */
const profiles = new DomainProfileStore(createBrowserProfileAdapter());

/**
 * Serialises scoring per tab. The content script reports more than once per page and the popup
 * can trigger rescans; two concurrent `scoreTab` runs for one tab would race their
 * `states.set`/`writeState` and let a stale digest overwrite a fresh one.
 */
const scoreQueues = new Map<number, Promise<unknown>>();

function enqueueScore<T>(tabId: number, task: () => Promise<T>): Promise<T> {
  const previous = scoreQueues.get(tabId) ?? Promise.resolve();
  const run = previous.then(task, task);
  scoreQueues.set(tabId, run.then(() => undefined, () => undefined));
  return run;
}

/** Observation ids already recorded into a domain profile, per tab (D-008: one record each). */
const recordedObservations = new Map<number, Set<string>>();

function recordedObservationIds(tabId: number): Set<string> {
  let ids = recordedObservations.get(tabId);
  if (!ids) {
    ids = new Set();
    recordedObservations.set(tabId, ids);
  }
  return ids;
}

/** True when the Change Monitor module is switched on (D-008: off means nothing is recorded). */
function changeMonitorEnabled(): boolean {
  return isModuleEnabled(settings, 'change-monitor');
}

/**
 * True when the Cookie Transparency module is switched on (D-007): when it is off, no
 * `chrome.cookies.getAll()` call is made at all and no cookie signal enters the score.
 */
function cookiesEnabled(): boolean {
  return isModuleEnabled(settings, 'cookie-transparency');
}

/** The tab a popup message is about: the named tab, or the active one. */
async function resolveTargetTabId(tabId: number | undefined): Promise<number | null> {
  if (typeof tabId === 'number') return tabId;
  try {
    const [active] = await browser.tabs.query({ active: true, currentWindow: true });
    return typeof active?.id === 'number' ? active.id : null;
  } catch {
    return null;
  }
}

/**
 * Third-party origins the tracker observer detected on this page, collapsed to registrable
 * domains so one vendor with several hosts is queried once. This is where the tracker output
 * becomes directly useful a second time: those origins are exactly where a page's third-party
 * cookies live.
 */
function thirdPartyOriginsFor(state: TabState): string[] {
  if (!state.report) return [];
  const page = parseUrl(state.url);
  const summary = summarizeRequests(mergeRequests([], state.report.resourceTimings), page.hostname || state.url);
  const domains = new Set<string>();
  for (const host of summary.thirdPartyHosts) {
    const domain = getSiteDomain(host);
    if (domain !== '') domains.add(domain);
  }
  return Array.from(domains);
}

/**
 * (Re-)enumerates cookie metadata for a tab and folds it into its state.
 *
 * No-op when the module is disabled — this is the gate that keeps the D-007 promise that
 * switching the module off means the cookie API is never called.
 */
async function refreshCookiesForTab(tabId: number): Promise<void> {
  const state = states.get(tabId);
  if (!state || !cookiesEnabled()) return;
  const records = await getCookiesForTab(tabId, thirdPartyOriginsFor(state), cookieObserverDeps);
  if (records !== null) {
    states.set(tabId, applyCookieRecords(state, records, Date.now()));
  }
}

/** Reads a session record, tolerating a storage failure by treating the tab as unmeasured. */
async function readState(tabId: number): Promise<TabState | null> {
  try {
    const key = sessionKey(tabId);
    const stored = (await browser.storage.session.get(key)) as Record<string, TabState | undefined>;
    return stored[key] ?? null;
  } catch {
    return null;
  }
}

/** Writes a session record. A quota or permission failure is not worth breaking a page over. */
async function writeState(state: TabState): Promise<void> {
  try {
    await browser.storage.session.set({ [sessionKey(state.tabId)]: state });
  } catch {
    // The in-memory map still holds the state, so the popup answer stays correct this session.
  }
}

/** The in-memory state for a tab, rehydrating from session storage after the worker restarts. */
async function loadState(tabId: number, url: string, now: number): Promise<TabState> {
  const cached = states.get(tabId);
  if (cached) return cached;
  const stored = await readState(tabId);
  // A stored record for a different URL belongs to a page the tab has already left.
  if (stored && (stored.url === url || url === '')) {
    states.set(tabId, stored);
    return stored;
  }
  const fresh = createTabState(tabId, url, createId('obs-'), now);
  states.set(tabId, fresh);
  return fresh;
}
/**
 * Scores the tab's current state, stores it and tells any open popup.
 *
 * This is the only place a score is written or broadcast, so the popup can never see a number that
 * storage would disagree with.
 */
async function scoreTab(tabId: number, now: number): Promise<ScanResult | null> {
  // Serialized per tab: interleaved reports must not race their state writes or their
  // profile records (D-008).
  return enqueueScore(tabId, () => scoreTabNow(tabId, now));
}

async function scoreTabNow(tabId: number, now: number): Promise<ScanResult | null> {
  const state = states.get(tabId);
  if (!state) return null;

  const observation = buildObservation(state, now);
  // Module off means module off: no cookie signal, and no stale cookie data from an earlier
  // scan, whatever the state happens to still hold.
  if (!cookiesEnabled()) {
    observation.cookies = [];
    observation.cookiesCollected = false;
  }
  const result = engine.run(observation, {
    startedAt: state.startedAt,
    now,
    enabledModules: settings.enabledModules,
  });

  // D-008: record fully observed scans into the domain's profile, once per observation. A
  // partial score (headers only) is a real answer for the popup but would pollute history with
  // phantom "headers disappeared" changes caused by Sentinel's own timing. The content script
  // reports more than once per page, so re-scores of an already-recorded observation re-attach
  // the digest recorded for it rather than re-recording (which would inflate scanCount) or
  // dropping it (which would let the second report overwrite the first, digest and all). The
  // observation-id set — not the state's own flag — is the authority, because the two reports
  // can race two state objects that both still carry `profileRecorded: false`. A storage
  // failure or a disabled module costs the site its history — never the scan its score.
  const observationRecorded = recordedObservationIds(tabId).has(observation.observationId);
  if (changeMonitorEnabled() && state.report !== null) {
    try {
      if (!observationRecorded) {
        const page = parseUrl(state.url);
        const summary = summarizeRequests(mergeRequests([], state.report.resourceTimings), page.hostname || state.url);
        const recorded = await profiles.record(result, {
          hostname: page.hostname || state.url,
          thirdPartyHosts: summary.thirdPartyHosts,
          trackerHosts: summary.trackers.map((hit) => hit.hostname),
          certificateSubject: result.observation.tls?.certificate?.subjectCN ?? null,
        });
        result.changes = recorded.changes;
        const profileSummary = summarizeProfile(recorded.profile, now);
        result.history = {
          domain: profileSummary.domain,
          scanCount: profileSummary.scanCount,
          lastScore: profileSummary.lastScore,
          averageScore: profileSummary.averageScore,
          lastSeenLabel: profileSummary.lastSeenLabel,
        };
        recordedObservationIds(tabId).add(observation.observationId);
        state.profileRecorded = true;
      } else if (state.result?.changes) {
        result.changes = state.result.changes;
        result.history = state.result.history;
      }
    } catch {
      // History must never break a scan.
    }
  }

  const next: TabState = { ...state, result, scannedAt: now, updatedAt: now };
  states.set(tabId, next);
  await writeState(next);

  try {
    // An open popup redraws itself rather than polling for the fuller score.
    void Promise.resolve(browser.runtime.sendMessage({ type: MSG_SCORE_UPDATED, tabId, result })).catch(
      () => undefined,
    );
  } catch {
    // No popup listening: not an error.
  }

  return result;
}

/** Asks the content script for a fresh report. Silence (no content script) is expected. */
function requestContentReport(tabId: number): void {
  try {
    void Promise.resolve(browser.tabs.sendMessage(tabId, { type: MSG_COLLECT })).catch(() => undefined);
  } catch {
    // The tab has no content script (browser-internal page, or it was closed): nothing to ask.
  }
}

/**
 * Answers the popup for one tab. Never throws, so the popup always gets a renderable answer.
 *
 * `pending` is used whenever a measurement could still arrive: either the tab has been observed
 * but not scored yet, or nothing has been observed *and* collection has just been kicked off. The
 * alternative - answering `none` because the user opened the popup a moment too early - told the
 * user "Sentinel has not seen this page yet" about a page it was about to score, and the popup had
 * no reason to ask again. Because every score is broadcast (`MSG_SCORE_UPDATED`), a `pending` answer
 * is followed by a redraw, so the panel heals itself without a refresh.
 */
async function scoreResponseFor(tabId: number, tabUrl: string | null): Promise<ScoreResponse> {
  if (tabUrl !== null && !isAnalysableUrl(tabUrl)) {
    return {
      type: MSG_SCORE,
      status: 'unsupported',
      result: null,
      tabId,
      tabUrl,
      note: 'Sentinel analyses web pages (http and https). This page is part of the browser itself.',
    };
  }

  const now = Date.now();
  const state = states.get(tabId) ?? (await readState(tabId));

  if (state === null) {
    if (tabUrl === null) {
      return { type: MSG_SCORE, status: 'none', result: null, tabId, tabUrl };
    }
    // Nothing known yet: start looking rather than reporting a gap. The score request may well be
    // the first thing that happens after the extension starts, and the page is right there.
    await loadState(tabId, tabUrl, now);
    requestContentReport(tabId);
    return {
      type: MSG_SCORE,
      status: 'pending',
      result: null,
      tabId,
      tabUrl,
      note: 'Sentinel is looking at this page now.',
    };
  }

  if (state.result !== null) {
    return { type: MSG_SCORE, status: 'ready', result: state.result, tabId, tabUrl: state.url };
  }

  // Observed but not scored yet (or waiting on the content script): ask again, so an open popup
  // converges without the user touching anything.
  requestContentReport(tabId);
  return {
    type: MSG_SCORE,
    status: 'pending',
    result: null,
    tabId,
    tabUrl: state.url,
    note: 'Sentinel is still observing this page.',
  };
}
export default defineBackground(() => {
  // --------------------------------------------------------------- response observation
  // `main_frame` only: the top-level document is the page the user is looking at. Nothing here
  // blocks, redirects or rewrites - `onHeadersReceived` without `webRequestBlocking` cannot.
  browser.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.tabId < 0) return undefined;
      const now = Date.now();
      // Chrome adds `ip` and `fromCache` to header details; the shared browser types do not list
      // them. Reading them through an intersection keeps the reader honest about that difference
      // instead of casting the whole object to `any`.
      const chromeDetails = details as typeof details & { ip?: string; fromCache?: boolean };
      const headers: HeaderEntry[] = selectResponseHeaders(
        details.responseHeaders,
        MAX_HEADER_ENTRIES,
        MAX_HEADER_VALUE_LENGTH,
      );

      const base =
        states.get(details.tabId) ?? createTabState(details.tabId, details.url, createId('obs-'), now);
      const next = applyHeaderObservation(
        base,
        {
          url: details.url,
          statusCode: details.statusCode ?? null,
          statusLine: details.statusLine ?? null,
          serverIp: chromeDetails.ip ?? null,
          fromCache: chromeDetails.fromCache === true,
          headers,
          // Chrome does not expose TLS/certificate facts to extensions through `webRequest`, so
          // this is `null` and the TLS signals report `measured: null` rather than an invented
          // verdict. A browser that does expose them can fill this in without touching the model.
          tls: null,
        },
        createId('obs-'),
        now,
      );

      states.set(details.tabId, next);
      void writeState(next);
      // Returning `undefined` is the whole point: this listener observes, it never blocks.
      return undefined;
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    // Chrome only includes `details.responseHeaders` when the listener asks for it here.
    // Phase 4's Header Dashboard e2e test caught this being missing: without it the header
    // list was silently empty, every header signal reported `measured: null` ("could not
    // look"), and the redistributed weights kept the scores plausible — a bug that looked
    // exactly like a working pipeline until something read the raw headers (D-009).
    ['responseHeaders'],
  );

  // ------------------------------------------------------------------------ orchestration
  browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== 'complete') return;
    const url = tab.url ?? '';
    if (!isAnalysableUrl(url)) return;

    void (async () => {
      const now = Date.now();
      await loadState(tabId, url, now);
      // Cookie metadata is collected alongside the other collectors (D-007): the page-URL pass
      // runs now, the third-party pass once the tracker observer reports the origins the page
      // contacted. Skipped entirely when the cookie module is off.
      await refreshCookiesForTab(tabId);
      // Score immediately with what is known (connection + headers), then ask for the page report
      // and score again: the popup shows the first score at once and redraws on the second.
      await scoreTab(tabId, now);
      requestContentReport(tabId);
    })();
  });

  browser.tabs.onRemoved.addListener((tabId) => {
    states.delete(tabId);
    recordedObservations.delete(tabId);
    void (async () => {
      try {
        await browser.storage.session.remove(sessionKey(tabId));
      } catch {
        // Storage is already gone, or unavailable: nothing is retained either way.
      }
    })();
  });

  // --------------------------------------------------------------------- message handling
  browser.runtime.onMessage.addListener((message: unknown, sender) => {
    // Content script -> background: everything the page could tell us about itself.
    if (isContentReport(message)) {
      const tabId = sender.tab?.id;
      if (typeof tabId !== 'number') return undefined;

      void (async () => {
        const now = Date.now();
        const state = await loadState(tabId, message.url, now);
        const next = applyContentReport(state, message, now);
        states.set(tabId, next);
        // A stale report (the tab has moved on) changes nothing, so it is not scored.
        if (next !== state) {
          await writeState(next);
          // The tracker observer has now reported the origins the page contacted, so the
          // third-party cookie pass has somewhere to look (D-007).
          await refreshCookiesForTab(tabId);
          await scoreTab(tabId, now);
        }
      })();
      return undefined;
    }

    // Popup -> background: "score for this tab, please". Answered from storage rather than by
    // re-running the engine, which is what keeps the popup inside its render budget.
    if (isScoreRequest(message)) {
      return (async (): Promise<ScoreResponse> => {
        if (typeof message.tabId === 'number') {
          const tab = await browser.tabs.get(message.tabId).catch(() => null);
          return scoreResponseFor(message.tabId, tab?.url ?? null);
        }
        const [active] = await browser.tabs.query({ active: true, currentWindow: true });
        if (!active || typeof active.id !== 'number') {
          return { type: MSG_SCORE, status: 'none', result: null, tabId: null, tabUrl: null };
        }
        return scoreResponseFor(active.id, active.url ?? null);
      })();
    }

    // Popup -> background: delete these cookies. This is the only code path in Sentinel that
    // modifies the cookie store (D-007), and it runs because a user clicked Delete in the
    // popup — never on a timer, never on page events. Afterwards the tab is re-enumerated and
    // re-scored so the popup shows the truth about what remains.
    if (isCookieRemovalRequest(message)) {
      return (async (): Promise<ScoreResponse> => {
        const tabId = await resolveTargetTabId(message.tabId);
        if (tabId === null) {
          return { type: MSG_SCORE, status: 'none', result: null, tabId: null, tabUrl: null };
        }
        // Bounded: the popup offers one list, so 100 targets is far above anything it can send.
        for (const target of message.targets.slice(0, 100)) {
          try {
            await browser.cookies.remove({ name: target.name, url: removalUrlFor(target), storeId: target.storeId });
          } catch {
            // A cookie may already be gone (expired, other store). Deletion is best-effort;
            // the re-enumeration below reports the truth either way.
          }
        }
        await refreshCookiesForTab(tabId);
        await scoreTab(tabId, Date.now());
        const state = states.get(tabId);
        return {
          type: MSG_SCORE,
          status: state?.result ? 'ready' : 'pending',
          result: state?.result ?? null,
          tabId,
          tabUrl: state?.url ?? null,
        };
      })();
    }

    // Popup -> background: settings may have changed, so re-read them, re-collect (the module
    // gate decides whether the cookie API is called at all) and re-score.
    if (isRescanRequest(message)) {
      return (async (): Promise<ScoreResponse> => {
        settings = await loadSettings();
        const tabId = await resolveTargetTabId(message.tabId);
        if (tabId === null) {
          return { type: MSG_SCORE, status: 'none', result: null, tabId: null, tabUrl: null };
        }
        await refreshCookiesForTab(tabId);
        await scoreTab(tabId, Date.now());
        const state = states.get(tabId);
        if (state?.result) {
          return { type: MSG_SCORE, status: 'ready', result: state.result, tabId, tabUrl: state.url };
        }
        return scoreResponseFor(tabId, state?.url ?? null);
      })();
    }

    // Popup -> background: forget this site's history (D-008, explicit user action). The profile
    // is removed and the tab re-scored, which records it fresh — the popup then shows the
    // first-visit message rather than a stale digest.
    if (isForgetProfileRequest(message)) {
      return (async (): Promise<ScoreResponse> => {
        const tabId = await resolveTargetTabId(message.tabId);
        if (tabId === null) {
          return { type: MSG_SCORE, status: 'none', result: null, tabId: null, tabUrl: null };
        }
        const state = states.get(tabId);
        if (state) {
          const domain = state.result?.domain ?? getSiteDomain(parseUrl(state.url).hostname);
          if (domain !== '') await profiles.forget(domain);
          // Forget the observation too, so the re-score below records the site fresh.
          recordedObservationIds(tabId).delete(state.observationId);
          state.profileRecorded = false;
        }
        await scoreTab(tabId, Date.now());
        const scored = states.get(tabId);
        return {
          type: MSG_SCORE,
          status: scored?.result ? 'ready' : 'pending',
          result: scored?.result ?? null,
          tabId,
          tabUrl: scored?.url ?? null,
        };
      })();
    }

    // Popup -> background: audit the other installed extensions (Phase 4, D-010). Read-only:
    // `browser.management.getAll()` is a local call and the report is computed on demand, never
    // persisted and never part of a page score. Sentinel excludes itself; no control call
    // (setEnabled/uninstall) exists anywhere in Sentinel — the local-only gate enforces that.
    if (isExtensionAuditRequest(message)) {
      return (async (): Promise<ExtensionAuditResponse> => {
        settings = await loadSettings();
        if (!isModuleEnabled(settings, 'extension-auditor')) {
          return { type: MSG_GET_EXTENSION_AUDIT, status: 'ready', moduleEnabled: false, report: null };
        }
        try {
          const infos = await browser.management.getAll();
          const auditable: AuditableExtension[] = infos
            .filter((info) => info.type === 'extension' && info.id !== browser.runtime.id)
            .map((info) => ({
              id: info.id,
              name: info.name,
              version: info.version,
              enabled: info.enabled === true,
              permissions: info.permissions ?? [],
              hostPermissions: info.hostPermissions ?? [],
            }));
          return {
            type: MSG_GET_EXTENSION_AUDIT,
            status: 'ready',
            moduleEnabled: true,
            report: auditExtensions(auditable, { now: Date.now() }),
          };
        } catch {
          return {
            type: MSG_GET_EXTENSION_AUDIT,
            status: 'unavailable',
            moduleEnabled: true,
            report: null,
            note: 'This browser would not let Sentinel list the installed extensions.',
          };
        }
      })();
    }

    // Options page -> background: forget every site's history (Phase 5, D-011). Explicit user
    // action only, confirmed in the options page; module settings are untouched. Live tab
    // states are also unmarked so the next scan records those sites fresh.
    if (isForgetAllProfilesRequest(message)) {
      return (async (): Promise<ForgetAllProfilesResponse> => {
        const existing = await profiles.list();
        await profiles.clear();
        for (const [tabId, state] of states) {
          recordedObservationIds(tabId).delete(state.observationId);
          state.profileRecorded = false;
        }
        return { type: MSG_FORGET_ALL_PROFILES, removed: existing.length };
      })();
    }

    // Options page -> background: what site history is recorded (Phase 6, D-013). Read-only:
    // the same metadata-only summaries the Changes panel shows, most recently seen first.
    if (isListProfilesRequest(message)) {
      return (async (): Promise<ListProfilesResponse> => {
        const now = Date.now();
        const all = await profiles.list();
        return { type: MSG_LIST_PROFILES, profiles: all.map((profile) => summarizeProfile(profile, now)) };
      })();
    }

    // Options page -> background: forget one site's history (Phase 6, D-013). Explicit user
    // action only, one click per site like the popup's forget; module settings are untouched.
    if (isForgetSiteRequest(message)) {
      return (async (): Promise<ForgetSiteResponse> => {
        const existing = await profiles.get(message.domain);
        await profiles.forget(message.domain);
        for (const [tabId, state] of states) {
          if (state.result?.domain === message.domain) {
            recordedObservationIds(tabId).delete(state.observationId);
            state.profileRecorded = false;
          }
        }
        return { type: MSG_FORGET_SITE, removed: existing !== null };
      })();
    }

    return undefined;
  });

  // A tab that was already loaded when the worker started has no `complete` event coming, so the
  // active tab is asked for a report once at startup. Nothing else happens at startup: no request.
  void (async () => {
    settings = await loadSettings();
    try {
      const [active] = await browser.tabs.query({ active: true, currentWindow: true });
      if (active && typeof active.id === 'number' && isAnalysableUrl(active.url)) {
        const now = Date.now();
        const state = await loadState(active.id, active.url ?? '', now);
        if (state.result === null) requestContentReport(active.id);
      }
    } catch {
      // No active tab, or `tabs` is unavailable: the popup answers `none` and explains why.
    }
  })();
});