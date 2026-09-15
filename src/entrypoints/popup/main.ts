/**
 * The popup's wiring: one request, one render, then redraw on updates.
 *
 * The popup is deliberately the dumbest part of Sentinel. It asks the background worker for the
 * score it already computed, renders it, and redraws when a newer score arrives - it never analyses
 * anything, never waits for a content script, and never makes a request of its own.
 *
 * Performance: the panel is painted from markup the moment the document loads, so the user sees the
 * frame before the score arrives, and the score itself comes from `storage.session` through
 * `MSG_GET_SCORE`. There is no polling and no `setTimeout`: everything after the first paint is
 * driven by a message.
 */

import { browser } from 'wxt/browser';
import {
  MSG_COOKIE_REMOVE,
  MSG_FORGET_PROFILE,
  MSG_GET_EXTENSION_AUDIT,
  MSG_GET_SCORE,
  MSG_RESCAN,
  MSG_SCORE,
  MSG_SCORE_UPDATED,
  type CookieRemovalTarget,
  type ExtensionAuditResponse,
  type ScoreResponse,
} from '../../shared/messages';
import {
  isModuleEnabled,
  loadSettings,
  saveSettings,
  withModuleEnabled,
  type SentinelSettings,
} from '../../shared/settings';
import { removalTargetFor } from '../../background/cookie-classifier';
import type { ClassifiedCookie, ScanResult } from '../../core/types';
import {
  renderChangesPanel,
  renderCookiePanel,
  renderExtensionsPanel,
  renderHeadersPanel,
  renderResponse,
  setActiveTab,
  CHANGE_MONITOR_MODULE_ID,
  COOKIE_MODULE_ID,
  type ChangesPanelHandlers,
  type CookiePanelHandlers,
  type ExtensionsPanelState,
  type PopupTab,
} from './view';

/** The score the popup is currently showing, so a later update can be compared against it. */
let current: ScoreResponse | null = null;
/** The tab the user has selected; survives repaints. */
let activeTab: PopupTab = 'trust-score';
/** The cookie module's setting, loaded once and kept across repaints (D-007). */
let cookieModuleEnabled = true;
/** The change monitor's setting, same lifecycle (D-008). */
let changesModuleEnabled = true;
/** The header dashboard's setting, same lifecycle (D-009). */
let headersModuleEnabled = true;
/** The extension auditor's setting, same lifecycle (D-010). */
let extensionsModuleEnabled = true;
/** The extension audit's latest answer (D-010); fetched lazily, never persisted. */
let extensionsPanel: ExtensionsPanelState = { moduleEnabled: true, loading: false, report: null, note: null };
/**
 * The settings this popup last read or wrote (D-011). The authoritative copy lives in
 * `browser.storage.local`; this cache exists so a panel toggle can flip one module without
 * rebuilding the whole enabled list from module metadata.
 */
let settings: SentinelSettings = { enabledModules: [] };

/**
 * Tab to report on.
 *
 * `null` means "the tab the user is looking at", which is what the real popup surface always
 * means: Chrome renders the popup over the page, so the active tab *is* the page. A `?tabId=`
 * query parameter overrides it, which exists for two honest reasons: the end-to-end test opens the
 * popup as a page (making the popup itself the active tab), and a future "score this tab" action
 * from the tab strip needs to name a tab explicitly.
 */
function tabIdFromLocation(): number | null {
  const raw = new URLSearchParams(window.location.search).get('tabId');
  if (raw === null) return null;
  const parsed = Number(raw);
  return Number.isInteger(parsed) ? parsed : null;
}

const tabIdOverride = tabIdFromLocation();

function isScoreResponse(value: unknown): value is ScoreResponse {
  return typeof value === 'object' && value !== null && (value as { type?: unknown }).type === MSG_SCORE;
}

function isScoreUpdate(value: unknown): value is { type: string; tabId: number } {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { type?: unknown }).type === MSG_SCORE_UPDATED &&
    typeof (value as { tabId?: unknown }).tabId === 'number'
  );
}

function paint(response: ScoreResponse): void {
  current = response;
  renderResponse(document, response, cookieModuleEnabled, changesModuleEnabled, headersModuleEnabled);
  // Restore whichever panel the user had open, then re-attach the panel handlers: a repaint
  // rebuilt the DOM nodes, so the closures must be re-hung.
  setActiveTab(document, activeTab);
  attachCookiePanelHandlers();
  attachChangesPanelHandlers();
  renderExtensionsPanel(document, extensionsPanel);
}

/** Re-hangs the cookie panel's click handlers after a repaint. */
function attachCookiePanelHandlers(): void {
  const result: ScanResult | null = current?.result ?? null;
  const handlers: CookiePanelHandlers = {
    onDelete: (cookie: ClassifiedCookie) => void sendCookieRemoval([removalTargetFor(cookie)]),
    onBulkDelete: (cookies: readonly ClassifiedCookie[]) => showBulkConfirm(cookies),
  };
  renderCookiePanel(document, result, cookieModuleEnabled, handlers);
}

/** Re-hangs the Changes panel's handlers after a repaint. */
function attachChangesPanelHandlers(): void {
  const result: ScanResult | null = current?.result ?? null;
  const handlers: ChangesPanelHandlers = {
    onForget: () => void requestForgetProfile(),
  };
  renderChangesPanel(document, result, changesModuleEnabled, handlers);
}

/**
 * Sends a delete request to the background worker.
 *
 * D-007: this is the popup-side half of the only path that modifies the cookie store — it runs
 * because the user clicked Delete (or confirmed the bulk delete), and the message it sends is
 * the proof of that click.
 */
async function sendCookieRemoval(targets: CookieRemovalTarget[]): Promise<void> {
  try {
    const response = (await browser.runtime.sendMessage({
      type: MSG_COOKIE_REMOVE,
      ...(current?.tabId != null ? { tabId: current.tabId } : {}),
      targets,
    })) as ScoreResponse;
    if (isScoreResponse(response)) paint(response);
  } catch {
    // The worker is gone or the popup closed mid-flight; nothing to do here.
  }
}

/** The inline confirmation for the bulk delete: lists exactly which cookies will be removed. */
function showBulkConfirm(cookies: readonly ClassifiedCookie[]): void {
  const confirmBox = document.getElementById('cookie-confirm');
  if (!confirmBox || cookies.length === 0) return;
  confirmBox.textContent = '';

  const intro = document.createElement('p');
  intro.textContent = `Delete ${cookies.length} ${cookies.length === 1 ? 'cookie' : 'cookies'}? ${cookies
    .slice(0, 8)
    .map((cookie) => cookie.name)
    .join(', ')}${cookies.length > 8 ? ` and ${cookies.length - 8} more` : ''}.`;

  const yes = document.createElement('button');
  yes.type = 'button';
  yes.className = 'danger-button';
  yes.setAttribute('data-testid', 'cookie-confirm-yes');
  yes.textContent = `Delete ${cookies.length} ${cookies.length === 1 ? 'cookie' : 'cookies'}`;
  yes.onclick = () => {
    confirmBox.hidden = true;
    void sendCookieRemoval(cookies.map((cookie) => removalTargetFor(cookie)));
  };

  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'quiet-button';
  cancel.setAttribute('data-testid', 'cookie-confirm-cancel');
  cancel.textContent = 'Cancel';
  cancel.onclick = () => {
    confirmBox.hidden = true;
  };

  confirmBox.append(intro, yes, cancel);
  confirmBox.removeAttribute('hidden');
}

/** Asks the background worker for the active tab's score. Never throws: a failure is a `none`. */
async function requestScore(): Promise<void> {
  try {
    const response = (await browser.runtime.sendMessage({
      type: MSG_GET_SCORE,
      ...(tabIdOverride === null ? {} : { tabId: tabIdOverride }),
    })) as ScoreResponse;
    if (isScoreResponse(response)) {
      paint(response);
      return;
    }
    paint({
      type: 'sentinel:score',
      status: 'none',
      result: null,
      tabId: null,
      tabUrl: null,
      note: 'Sentinel did not answer. Reopen the popup to try again.',
    });
  } catch {
    paint({
      type: 'sentinel:score',
      status: 'none',
      result: null,
      tabId: null,
      tabUrl: null,
      note: 'Sentinel is unavailable in this window. Open a normal browser window and try again.',
    });
  }
}

/** Asks the background worker to re-collect and re-score (after a settings change). */
async function requestRescan(): Promise<void> {
  try {
    const response = (await browser.runtime.sendMessage({
      type: MSG_RESCAN,
      ...(tabIdOverride === null ? {} : { tabId: tabIdOverride }),
    })) as ScoreResponse;
    if (isScoreResponse(response)) paint(response);
  } catch {
    // Worker unavailable; the panel keeps showing the last known state.
  }
}

/**
 * Asks the background worker to forget this site's history (D-008, explicit user action).
 * The re-score that follows records the site fresh, so the panel shows the first-visit message.
 */
async function requestForgetProfile(): Promise<void> {
  try {
    const response = (await browser.runtime.sendMessage({
      type: MSG_FORGET_PROFILE,
      ...(current?.tabId != null ? { tabId: current.tabId } : {}),
    })) as ScoreResponse;
    if (isScoreResponse(response)) paint(response);
  } catch {
    // Worker unavailable; the panel keeps showing the last known state.
  }
}

/** The "Why this score?" disclosure: a plain button toggle, so it works with the keyboard. */
function wireDrilldown(): void {
  const button = document.getElementById('why-button');
  const drilldown = document.getElementById('drilldown');
  if (!button || !drilldown) return;

  button.addEventListener('click', () => {
    const open = drilldown.hasAttribute('hidden');
    if (open) drilldown.removeAttribute('hidden');
    else drilldown.setAttribute('hidden', '');
    button.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      // Move focus into the panel for keyboard users, without scrolling the popup.
      drilldown.querySelector('h2')?.setAttribute('tabindex', '-1');
      (drilldown.querySelector('h2') as HTMLElement | null)?.focus();
    }
  });
}

/** Redraws when the background worker publishes a fuller score for this tab. */
function wireUpdates(): void {
  browser.runtime.onMessage.addListener((message: unknown) => {
    if (!isScoreUpdate(message)) return undefined;
    // Only redraw for the tab this popup is showing.
    if (current?.tabId !== null && current?.tabId !== undefined && message.tabId !== current.tabId) {
      return undefined;
    }
    void requestScore();
    return undefined;
  });
}

/** Tab switching: one delegated listener on the tab bar, so repaints need no re-wiring. */
function wireTabs(): void {
  document.getElementById('tab-bar')?.addEventListener('click', (event) => {
    const target = (event.target as HTMLElement | null)?.closest('button.tab') as HTMLButtonElement | null;
    if (!target || target.disabled) return;
    const id = target.id.replace(/^tab-/, '');
    if (
      id === 'trust-score' ||
      id === 'cookie-transparency' ||
      id === 'change-monitor' ||
      id === 'header-dashboard' ||
      id === 'extension-auditor'
    ) {
      activeTab = id as PopupTab;
      setActiveTab(document, activeTab);
      // D-010: the extension audit is fetched the first time the user opens the tab, not on
      // every popup open — it is not part of the page scan and must not slow it.
      if (id === 'extension-auditor' && extensionsModuleEnabled && !extensionsPanel.loading && extensionsPanel.report === null) {
        void requestExtensionAudit();
      }
    }
  });
}

/**
 * The change monitor's enable switch (D-008). Off means off: no recording, no comparisons, and
 * the background is asked to re-score so the module status reflects the setting.
 */
function wireChangesToggle(): void {
  const toggle = document.getElementById('changes-module-toggle') as HTMLInputElement | null;
  toggle?.addEventListener('change', () => {
    changesModuleEnabled = toggle.checked;
    settings = withModuleEnabled(settings, CHANGE_MONITOR_MODULE_ID, changesModuleEnabled);
    void saveSettings(settings);
    attachChangesPanelHandlers();
    void requestRescan();
  });
}

/**
 * The cookie module's enable switch.
 *
 * Off means off (D-007): the setting is saved, the panel explains itself immediately, and the
 * background is asked to re-score — where it will skip the cookie API entirely.
 */
function wireCookieToggle(): void {
  const toggle = document.getElementById('cookie-module-toggle') as HTMLInputElement | null;
  toggle?.addEventListener('change', () => {
    cookieModuleEnabled = toggle.checked;
    settings = withModuleEnabled(settings, COOKIE_MODULE_ID, cookieModuleEnabled);
    void saveSettings(settings);
    attachCookiePanelHandlers();
    void requestRescan();
  });
}

function main(): void {
  wireTabs();
  wireCookieToggle();
  wireChangesToggle();
  wireHeadersToggle();
  wireExtensionsToggle();
  wireOpenOptions();
  wireDrilldown();
  wireUpdates();
  void loadSettings().then((loaded) => {
    // D-011: the module-level cache is what the panel toggles mutate; `loaded` is the
    // authoritative copy from storage, read once here.
    settings = loaded;
    cookieModuleEnabled = isModuleEnabled(settings, 'cookie-transparency');
    changesModuleEnabled = isModuleEnabled(settings, 'change-monitor');
    headersModuleEnabled = isModuleEnabled(settings, 'header-dashboard');
    extensionsModuleEnabled = isModuleEnabled(settings, 'extension-auditor');
    extensionsPanel = { ...extensionsPanel, moduleEnabled: extensionsModuleEnabled };
    attachCookiePanelHandlers();
    attachChangesPanelHandlers();
    renderExtensionsPanel(document, extensionsPanel);
  });
  void requestScore();
}

/**
 * Asks the background for the extension audit (D-010). Lazy: called the first time the user
 * opens the Extensions tab, or when the module is switched back on. The popup shows a
 * "checking" note while the request is in flight and never blocks the rest of the report.
 */
async function requestExtensionAudit(): Promise<void> {
  extensionsPanel = { ...extensionsPanel, loading: true, note: null };
  renderExtensionsPanel(document, extensionsPanel);
  const unavailable = 'Sentinel could not audit the installed extensions.';
  try {
    const answer = (await browser.runtime.sendMessage({
      type: MSG_GET_EXTENSION_AUDIT,
    })) as ExtensionAuditResponse | undefined;
    if (!answer || answer.type !== MSG_GET_EXTENSION_AUDIT) {
      extensionsPanel = { moduleEnabled: extensionsModuleEnabled, loading: false, report: null, note: unavailable };
    } else if (answer.status === 'unavailable') {
      extensionsPanel = { moduleEnabled: answer.moduleEnabled, loading: false, report: null, note: answer.note ?? unavailable };
    } else {
      extensionsPanel = { moduleEnabled: answer.moduleEnabled, loading: false, report: answer.report, note: null };
    }
  } catch {
    extensionsPanel = { moduleEnabled: extensionsModuleEnabled, loading: false, report: null, note: unavailable };
  }
  renderExtensionsPanel(document, extensionsPanel);
}

/** The header display's enable switch (D-009). Off hides the panel's data immediately. */
function wireHeadersToggle(): void {
  const toggle = document.getElementById('headers-module-toggle') as HTMLInputElement | null;
  toggle?.addEventListener('change', () => {
    headersModuleEnabled = toggle.checked;
    settings = withModuleEnabled(settings, 'header-dashboard', headersModuleEnabled);
    void saveSettings(settings);
    const result: ScanResult | null = current?.result ?? null;
    renderHeadersPanel(document, result, headersModuleEnabled);
    void requestRescan();
  });
}

/**
 * The extension auditor's enable switch (D-010). Switching it on fetches the audit at once;
 * switching it off clears the shown list and the background will answer with an empty one.
 */
function wireExtensionsToggle(): void {
  const toggle = document.getElementById('extensions-module-toggle') as HTMLInputElement | null;
  toggle?.addEventListener('change', () => {
    extensionsModuleEnabled = toggle.checked;
    settings = withModuleEnabled(settings, 'extension-auditor', extensionsModuleEnabled);
    void saveSettings(settings);
    extensionsPanel = { moduleEnabled: extensionsModuleEnabled, loading: false, report: null, note: null };
    renderExtensionsPanel(document, extensionsPanel);
    if (extensionsModuleEnabled) void requestExtensionAudit();
  });
}

/** Opens the options page (D-011): the full view of the settings these panels edit. */
function wireOpenOptions(): void {
  document.getElementById('open-options')?.addEventListener('click', () => {
    void browser.runtime.openOptionsPage();
  });
}

main();

export { main, paint, requestScore };