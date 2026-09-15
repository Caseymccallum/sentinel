/**
 * The message protocol between Sentinel's three contexts.
 *
 * Content script -> background is a single combined report, because the page pays for every
 * round trip: the observers each walk the page once and the results travel together.
 * Background -> popup is a request/response pair plus an unsolicited "the score changed"
 * broadcast, so an open popup updates itself when a slow content script finally answers.
 *
 * Every message carries a literal `type` so an unrelated extension's traffic can never be
 * mistaken for ours, and nothing here ever crosses the network: `chrome.runtime` messaging
 * is in-process only.
 */

import type { DomReport, ResourceTimingRecord } from './observation';
import type { ExtensionAuditReport, ProfileHistorySummary, ScanResult } from '../core/types';

/** Content script -> background: everything the page could tell us about itself. */
export const MSG_REPORT = 'sentinel:report';

/** Background -> content script: "re-collect and report again". */
export const MSG_COLLECT = 'sentinel:collect';

/** Popup -> background: "score for this tab, please". */
export const MSG_GET_SCORE = 'sentinel:get-score';

/** Background -> popup: the answer to `MSG_GET_SCORE`. */
export const MSG_SCORE = 'sentinel:score';

/** Background -> any listener: a stored score was replaced by a newer one. */
export const MSG_SCORE_UPDATED = 'sentinel:score-updated';

/** The DOM + resource facts a content script can see, in one payload. */
export interface ContentReport {
  type: typeof MSG_REPORT;
  /** The document this report describes; the background drops reports for other URLs. */
  url: string;
  /** `null` when the DOM walk failed (the page is still scored without it). */
  dom: DomReport | null;
  resourceTimings: ResourceTimingRecord[];
  /** False when the Performance API was unavailable, so `[]` means "none" vs "unknown". */
  resourcesCollected: boolean;
}

export interface CollectRequest {
  type: typeof MSG_COLLECT;
}

export interface ScoreRequest {
  type: typeof MSG_GET_SCORE;
  /** Omitted = "whatever tab the user is looking at". */
  tabId?: number;
}

/**
 * `pending` is a real answer, not an error: the popup must render immediately with the
 * connection and header signals while trackers and forms are still being collected.
 */
export type ScoreStatus = 'ready' | 'pending' | 'unsupported' | 'none';

export interface ScoreResponse {
  type: typeof MSG_SCORE;
  status: ScoreStatus;
  /** Null while `status` is `pending`/`unsupported`/`none`. */
  result: ScanResult | null;
  tabId: number | null;
  tabUrl: string | null;
  /** Human-readable reason for a non-`ready` status, shown in the popup. */
  note?: string;
}

export interface ScoreUpdatedMessage {
  type: typeof MSG_SCORE_UPDATED;
  tabId: number;
  result: ScanResult;
}

/** Narrows an unknown message (a listener sees `any`) to our report shape. */
export function isContentReport(message: unknown): message is ContentReport {
  if (typeof message !== 'object' || message === null) return false;
  const candidate = message as Partial<ContentReport>;
  return (
    candidate.type === MSG_REPORT &&
    typeof candidate.url === 'string' &&
    Array.isArray(candidate.resourceTimings)
  );
}

export function isScoreRequest(message: unknown): message is ScoreRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<ScoreRequest>).type === MSG_GET_SCORE;
}

export function isCollectRequest(message: unknown): message is CollectRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<CollectRequest>).type === MSG_COLLECT;
}

/**
 * Popup -> background: delete these cookies.
 *
 * This is the *only* message that can cause Sentinel to modify the cookie store (D-007). It is
 * sent by a popup button the user clicked, and the background treats it as the explicit user
 * action the permission justification promises: no other code path may call
 * `browser.cookies.remove()`.
 */
export const MSG_COOKIE_REMOVE = 'sentinel:cookie-remove';

/** Popup -> background: re-collect (if the module settings allow) and re-score this tab. */
export const MSG_RESCAN = 'sentinel:rescan';

/** The cookie-store coordinates `browser.cookies.remove()` needs, as plain data. */
export interface CookieRemovalTarget {
  name: string;
  domain: string;
  path: string;
  storeId: string;
  secure: boolean;
}

export interface CookieRemovalRequest {
  type: typeof MSG_COOKIE_REMOVE;
  /** Omitted = the active tab. */
  tabId?: number;
  targets: CookieRemovalTarget[];
}

export interface RescanRequest {
  type: typeof MSG_RESCAN;
  /** Omitted = the active tab. */
  tabId?: number;
}

export function isCookieRemovalRequest(message: unknown): message is CookieRemovalRequest {
  if (typeof message !== 'object' || message === null) return false;
  const candidate = message as Partial<CookieRemovalRequest>;
  return (
    candidate.type === MSG_COOKIE_REMOVE &&
    Array.isArray(candidate.targets) &&
    candidate.targets.every(
      (target) =>
        typeof target === 'object' &&
        target !== null &&
        typeof target.name === 'string' &&
        typeof target.domain === 'string' &&
        typeof target.path === 'string' &&
        typeof target.storeId === 'string' &&
        typeof target.secure === 'boolean',
    )
  );
}

export function isRescanRequest(message: unknown): message is RescanRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<RescanRequest>).type === MSG_RESCAN;
}

/**
 * Popup -> background: review the other installed extensions (Phase 4, D-010).
 *
 * Like the page score, this is a request/response pair answered from what the browser already
 * knows: `browser.management.getAll()` is a local, in-process call — nothing here touches the
 * network. The background answers with the audit report; it never enables, disables or
 * removes anything (mechanically enforced by scripts/check-local-only.mjs).
 */
export const MSG_GET_EXTENSION_AUDIT = 'sentinel:get-extension-audit';

export interface ExtensionAuditRequest {
  type: typeof MSG_GET_EXTENSION_AUDIT;
}

export type ExtensionAuditStatus = 'ready' | 'unavailable';

export interface ExtensionAuditResponse {
  type: typeof MSG_GET_EXTENSION_AUDIT;
  status: ExtensionAuditStatus;
  /** False when the user has switched the Extension Auditor module off. */
  moduleEnabled: boolean;
  /** Null while the module is off or the audit could not run. */
  report: ExtensionAuditReport | null;
  /** Human-readable reason for an `unavailable` status, shown in the popup. */
  note?: string;
}

export function isExtensionAuditRequest(message: unknown): message is ExtensionAuditRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<ExtensionAuditRequest>).type === MSG_GET_EXTENSION_AUDIT;
}

/**
 * Options page -> background: what site history is recorded (Phase 6, D-013).
 *
 * Read-only transparency for the "Your data" section: the same metadata-only summaries the
 * popup's Changes panel shows, most recently seen first. Never page paths, queries or titles
 * (D-008); nothing here is a network call.
 */
export const MSG_LIST_PROFILES = 'sentinel:list-profiles';

export interface ListProfilesRequest {
  type: typeof MSG_LIST_PROFILES;
}

export interface ListProfilesResponse {
  type: typeof MSG_LIST_PROFILES;
  profiles: ProfileHistorySummary[];
}

export function isListProfilesRequest(message: unknown): message is ListProfilesRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<ListProfilesRequest>).type === MSG_LIST_PROFILES;
}

/**
 * Options page -> background: forget one site's history (Phase 6, D-013).
 *
 * A user action, like the popup's per-site forget — but addressed by registrable domain,
 * because the options page has no tab to re-score. The background drops the profile and
 * unmarks any live tab state for that domain so the next scan records it fresh.
 */
export const MSG_FORGET_SITE = 'sentinel:forget-site';

export interface ForgetSiteRequest {
  type: typeof MSG_FORGET_SITE;
  /** The registrable domain, as stored in the profile key. */
  domain: string;
}

export interface ForgetSiteResponse {
  type: typeof MSG_FORGET_SITE;
  /** True when a profile existed and was removed. */
  removed: boolean;
}

export function isForgetSiteRequest(message: unknown): message is ForgetSiteRequest {
  if (typeof message !== 'object' || message === null) return false;
  const candidate = message as Partial<ForgetSiteRequest>;
  return candidate.type === MSG_FORGET_SITE && typeof candidate.domain === 'string' && candidate.domain !== '';
}

/**
 * Popup -> background: forget this site's history (D-008). A user action, like cookie deletion:
 * the domain's profile is removed and the tab is re-scored, which records it fresh.
 */
export const MSG_FORGET_PROFILE = 'sentinel:forget-profile';

/**
 * Options page -> background: forget *every* site's history (Phase 5, D-011).
 *
 * Like the per-site forget, this runs only from an explicit user action — a confirmed button
 * on the options page. It removes every recorded domain profile; module settings are
 * untouched (they are preferences, not history).
 */
export const MSG_FORGET_ALL_PROFILES = 'sentinel:forget-all-profiles';

export interface ForgetAllProfilesRequest {
  type: typeof MSG_FORGET_ALL_PROFILES;
}

export interface ForgetAllProfilesResponse {
  type: typeof MSG_FORGET_ALL_PROFILES;
  /** How many domain profiles were removed. */
  removed: number;
}

export function isForgetAllProfilesRequest(message: unknown): message is ForgetAllProfilesRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<ForgetAllProfilesRequest>).type === MSG_FORGET_ALL_PROFILES;
}

export interface ForgetProfileRequest {
  type: typeof MSG_FORGET_PROFILE;
  /** Omitted = the active tab. */
  tabId?: number;
}

export function isForgetProfileRequest(message: unknown): message is ForgetProfileRequest {
  if (typeof message !== 'object' || message === null) return false;
  return (message as Partial<ForgetProfileRequest>).type === MSG_FORGET_PROFILE;
}