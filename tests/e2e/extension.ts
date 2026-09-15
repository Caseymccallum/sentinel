/**
 * End-to-end harness: load the built extension, drive the popup, read what it says.
 *
 * The two awkward parts of testing a Chrome extension, both solved here:
 *
 *   1. **Headless with extensions.** Playwright's plain `headless: true` launches
 *      `chrome-headless-shell`, which cannot load extensions. `channel: 'chromium'` uses the full
 *      Chromium build with the new headless mode, which can.
 *   2. **Which tab is "the" tab.** Chrome renders the popup *over* the page, so the active tab is
 *      the page. A test opens the popup as a tab, which would make the popup active instead - so
 *      the harness finds the id of the page's tab through the service worker and opens
 *      `popup.html?tabId=${id}`, which the popup supports explicitly.
 *
 * Everything this file reads comes from the popup's own DOM (`data-testid` attributes declared in
 * `src/entrypoints/popup/index.html`), so the test asserts what a user sees rather than internal
 * state.
 */

import { chromium, type BrowserContext, type Page, type ServiceWorker } from '@playwright/test';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { HOST_RESOLVER_RULES } from '../../scripts/e2e-server.mjs';

export const EXTENSION_DIR = resolve('.output/chrome-mv3');

export interface ExtensionSession {
  context: BrowserContext;
  extensionId: string;
  /** Every page the context has open, including the extension's own. */
  pages(): Page[];
  close(): Promise<void>;
}

/**
 * Options `scripts/capture-popup.mjs` needs and the tests do not. Kept separate from
 * `extraExtensionDirs` so adding a capture-only knob can never change what a test launches.
 */
export interface LaunchOptions {
  /** Device pixel ratio. 2 keeps `docs/popup-*.png` sharp on a retina display; the tests want 1. */
  deviceScaleFactor?: number;
}

/** A snapshot of everything the popup is displaying. */
export interface PopupSnapshot {
  status: string | null;
  tone: string | null;
  score: number | null;
  grade: string;
  headline: string;
  summary: string;
  /** Non-null while the popup says tracker or form checks are still running. */
  pendingNote: string | null;
  /** Every finding row in the drill-down, in the order the popup shows them. */
  findings: { title: string; severity: string | null; measured: string | null; effect: string }[];
  reputation: string;
  barValue: number | null;
}

/** Fails loudly, with a helpful message, when the extension has not been built. */
async function assertBuilt(): Promise<void> {
  try {
    await stat(join(EXTENSION_DIR, 'manifest.json'));
  } catch {
    throw new Error(`No built extension at ${EXTENSION_DIR}. Run \`npm run build\` first (or \`npm run test:e2e\`, which does it for you).`);
  }
}

/**
 * Finds Sentinel's own service worker by asking it for its manifest name.
 *
 * The context can contain other service workers — the audit fixture has none, but headless
 * Chromium ships component extensions whose worker URL can also end in `/background.js`
 * (one with a stable component id once 404'd the popup URL, failing the suite at random).
 * A URL match is therefore not enough: the worker is only Sentinel's when its own manifest
 * says so. Every worker seen within 30 seconds gets one chance; the first that answers
 * "Sentinel" wins.
 */
async function findSentinelWorker(context: BrowserContext): Promise<ServiceWorker> {
  const isSentinel = async (worker: ServiceWorker): Promise<boolean> => {
    try {
      const name = await worker.evaluate(() => chrome.runtime.getManifest().name);
      return name === 'Sentinel';
    } catch {
      // Not evaluateable from here, or already gone: try the next one.
      return false;
    }
  };

  const deadline = Date.now() + 30_000;
  for (;;) {
    for (const worker of context.serviceWorkers()) {
      if (await isSentinel(worker)) return worker;
    }
    if (Date.now() > deadline) {
      throw new Error("Sentinel's service worker did not appear within 30s.");
    }
    await context.waitForEvent('serviceworker', { timeout: 5_000 }).catch(() => {
      // No new worker in this window; loop and re-check what exists.
    });
  }
}

/**
 * Launches Chromium with Sentinel loaded.
 *
 * `--ignore-certificate-errors` covers the fixture server's self-signed certificate, and the host
 * resolver rules point every fixture host (and every tracker host) at 127.0.0.1, so nothing in the
 * test can reach the network even if a URL were wrong.
 *
 * The two cookie switches keep the fixture tracker stubs able to plant third-party cookies: this
 * Chromium build blocks third-party cookie storage by default, and the money test asserts exactly
 * that pipeline (page contacts third-party origin -> origin plants a cookie -> the extension's
 * cookie observer finds it). It is a *browser default* being relaxed for the test profile, not a
 * change to anything Sentinel does.
 *
 * `extraExtensionDirs` names additional unpacked extensions to load (used by the Extension
 * Auditor's test, which needs a deliberately over-permissioned second extension to audit).
 * The fixture extensions declare no service worker, so Sentinel's remains the only one and
 * the extension-id detection below stays unambiguous.
 *
 * `options` exists for the one caller that is not a test: `scripts/capture-popup.mjs` renders the
 * README's screenshots. Tests pass nothing and run at the defaults, so nothing they assert can be
 * affected by it.
 */
export async function launchExtension(
  extraExtensionDirs: string[] = [],
  options: LaunchOptions = {},
): Promise<ExtensionSession> {
  await assertBuilt();
  const userDataDir = await mkdtemp(join(tmpdir(), 'sentinel-e2e-'));

  const loadTargets = [EXTENSION_DIR, ...extraExtensionDirs].join(',');
  const context = await chromium.launchPersistentContext(userDataDir, {
    // `channel: 'chromium'` is required: the default headless build has no extension support.
    channel: 'chromium',
    headless: true,
    // 1 for the tests (Playwright's default anyway), 2 for the screenshot script.
    deviceScaleFactor: options.deviceScaleFactor ?? 1,
    args: [
      `--disable-extensions-except=${loadTargets}`,
      `--load-extension=${loadTargets}`,
      '--ignore-certificate-errors',
      `--host-resolver-rules=${HOST_RESOLVER_RULES}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-features=BlockThirdPartyCookies,TrackingProtection3pcd',
    ],
  });

  // Sentinel's own service worker, identified by its manifest name — not by URL shape and
  // not by arrival order, both of which race when component extensions are around.
  const worker = await findSentinelWorker(context);
  const extensionId = new URL(worker.url()).host;

  return {
    context,
    extensionId,
    pages: () => context.pages(),
    async close() {
      await context.close();
      await rm(userDataDir, { recursive: true, force: true });
    },
  };
}
/** The tab id of the page showing `url`, asked of the extension's own service worker. */
export async function tabIdForUrl(session: ExtensionSession, url: string): Promise<number> {
  // Same discipline as `launchExtension`: the worker is identified by its manifest name.
  const worker = await findSentinelWorker(session.context);
  if (!worker) throw new Error('The extension service worker is not running.');

  const prefix = url.replace(/[?#].*$/, '');
  const tabId = await worker.evaluate(async (target) => {
    // `chrome` is available inside the service worker's own scope.
    const tabs = await chrome.tabs.query({});
    const match = tabs.find((tab) => (tab.url ?? '').startsWith(target));
    return match?.id ?? null;
  }, prefix);

  if (tabId === null) throw new Error(`No tab is showing ${url}.`);
  return tabId;
}

/** Opens the popup for one tab. */
export async function openPopup(session: ExtensionSession, tabId: number): Promise<Page> {
  const page = await session.context.newPage();
  await page.goto(`chrome-extension://${session.extensionId}/popup.html?tabId=${tabId}`);
  await page.waitForSelector('[data-testid="score"]');
  return page;
}

/**
 * Waits until the popup is showing a settled score for the tab.
 *
 * "Settled" means: the background answered `ready`, a number is on screen, and the popup is not
 * saying that tracker or form checks are still running. Waiting only for the pending note would
 * return while the popup was still reporting `pending`, which is the race this harness exists to
 * catch rather than to paper over.
 */
export async function waitForSettled(popup: Page, timeoutMs = 30_000): Promise<void> {
  await popup.waitForFunction(
    () => {
      const root = document.getElementById('popup');
      if (root?.getAttribute('data-status') !== 'ready') return false;
      const score = (document.getElementById('score-value')?.textContent ?? '').trim();
      if (score === '' || score === '—') return false;
      const note = document.querySelector('[data-testid="pending-note"]');
      return note === null || note.hasAttribute('hidden') || (note.textContent ?? '') === '';
    },
    undefined,
    { timeout: timeoutMs },
  );
}

/** Everything the popup is showing right now. */
export async function readPopup(popup: Page): Promise<PopupSnapshot> {
  return popup.evaluate(() => {
    const text = (id: string): string => document.getElementById(id)?.textContent?.trim() ?? '';
    const root = document.getElementById('popup');

    const findings = Array.from(document.querySelectorAll('#findings .finding')).map((item) => ({
      title: item.querySelector('.finding-title')?.textContent?.trim() ?? '',
      // The category and confidence ride along inside the title element, separated by a middot.
      severity: item.getAttribute('data-severity'),
      measured: item.getAttribute('data-measured'),
      effect: item.querySelector('.finding-effect')?.textContent?.trim() ?? '',
    }));

    const rawScore = text('score-value');
    const parsedScore = Number.parseInt(rawScore, 10);
    const barRaw = document.getElementById('score-bar')?.getAttribute('aria-valuenow') ?? '';

    return {
      status: root?.getAttribute('data-status') ?? null,
      tone: root?.getAttribute('data-tone') ?? null,
      score: Number.isNaN(parsedScore) ? null : parsedScore,
      grade: text('grade'),
      headline: text('headline'),
      summary: text('summary'),
      pendingNote:
        document.querySelector('[data-testid="pending-note"]')?.hasAttribute('hidden') === true
          ? null
          : text('pending-note') || null,
      findings,
      reputation: text('reputation'),
      barValue: barRaw === '' ? null : Number.parseInt(barRaw, 10),
    };
  });
}

/** Opens the "Why this score?" view and returns the snapshot it renders. */
export async function openDrilldown(popup: Page): Promise<PopupSnapshot> {
  await popup.click('[data-testid="why-button"]');
  await popup.waitForSelector('[data-testid="drilldown"]:not([hidden])');
  return readPopup(popup);
}

/**
 * Reloads the popup and waits for it to settle.
 *
 * Used after navigating the page: the popup is a real page in this harness, so it does not
 * disappear when the page behind it changes.
 */
export async function refreshPopup(popup: Page): Promise<PopupSnapshot> {
  await popup.reload();
  await waitForSettled(popup);
  return readPopup(popup);
}