/**
 * The money test (Phase 1, Task 1.6).
 *
 * It loads the built extension into headless Chromium and asserts what the popup says about locally
 * served pages. Every layer of the pipeline is exercised, in order:
 *
 *   background `webRequest.onHeadersReceived` -> per-tab headers
 *   content script -> tracker detection from the resource-timing buffer, and DOM/form observation
 *   TrustEngine -> the composite score, the grade and the explanation
 *   `browser.storage.session` -> the popup's answer
 *   popup -> score, grade, reasons and the drill-down
 *
 * The fixtures are served by `scripts/e2e-server.mjs` on 127.0.0.1, and Chromium is launched with
 * host-resolver rules that point every fixture hostname at the loopback address, so this test cannot
 * reach the real internet even if a URL were wrong.
 */

import { expect, test, type Page } from '@playwright/test';
import { resolve } from 'node:path';
import {
  INSECURE_PAGE_URL,
  SECURE_PAGE_URL,
  TRACKER_COOKIE_SEEDS,
  TRACKER_PAGE_URL,
} from '../../scripts/e2e-server.mjs';
import {
  launchExtension,
  openDrilldown,
  openPopup,
  readPopup,
  refreshPopup,
  tabIdForUrl,
  waitForSettled,
  type ExtensionSession,
} from './extension';

let session: ExtensionSession;

test.beforeAll(async () => {
  // The fixture servers are started once per invocation in the runner process
  // (`tests/e2e/global-setup.ts`); this worker only launches the extension. Starting them
  // per worker used to race a recycled worker's teardown under `--repeat-each` and fail
  // with EADDRINUSE on the fixed ports.
  //
  // The audit fixture is a second, deliberately over-permissioned extension (no service
  // worker, so Sentinel's stays the only one) that the Extension Auditor's test audits.
  session = await launchExtension([resolve('tests/fixtures/audit-extension')]);
  // Warm-up: the very first navigation of a cold browser can race the service worker's
  // `webRequest` listener registration, which would miss the main-frame response and make the
  // first test assert on a mis-observed page. One throwaway navigation guarantees the worker
  // is running before any test starts asserting; `visit()` reuses this page afterwards.
  const warmup = await session.context.newPage();
  await warmup.goto(SECURE_PAGE_URL, { waitUntil: 'load' }).catch(() => {});
  await warmup.waitForTimeout(300);
});

test.afterAll(async () => {
  // The browser may already be gone (Playwright's trace teardown has raced us on Windows);
  // a failure here must never skip anything — and the fixture servers are the runner
  // process's responsibility now, closed by `global-teardown.ts` after all workers.
  try {
    await session?.close();
  } catch {
    // The context is already closed or tearing down; nothing left to release.
  }
});

/** Navigates a page to `url` and waits for the load to finish. */
async function visit(url: string): Promise<void> {
  const page =
    session.pages().find((candidate) => candidate.url().startsWith('http')) ??
    (await session.context.newPage());
  await page.goto(url, { waitUntil: 'load' });
  // The content script reports again on `load`; `waitForSettled` below is what actually decides,
  // this just avoids racing the first paint.
  await page.waitForTimeout(150);
}

test('an HTTP page with no headers and three trackers scores 40 or worse, and says why', async () => {
  await visit(INSECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, INSECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);

  await waitForSettled(popup);
  const snapshot = await readPopup(popup);

  expect(snapshot.status).toBe('ready');
  expect(snapshot.score).not.toBeNull();
  expect(snapshot.score as number).toBeLessThanOrEqual(40);
  expect(snapshot.grade).toBe('F');
  expect(snapshot.tone).toBe('poor');

  const drilldown = await openDrilldown(popup);
  const titles = drilldown.findings.map((finding) => finding.title.toLowerCase());
  // The three things that make this page bad must all be reported.
  expect(titles.some((title) => title.includes('encrypted transport'))).toBe(true);
  expect(titles.some((title) => title.includes('third-party tracking'))).toBe(true);
  expect(titles.some((title) => title.includes('password handling'))).toBe(true);

  const tracker = drilldown.findings.find((finding) =>
    finding.title.toLowerCase().includes('third-party tracking'),
  );
  expect(tracker?.effect).toContain('points');
  // A password posted over HTTP is a serious finding, never a note.
  const password = drilldown.findings.find((finding) =>
    finding.title.toLowerCase().includes('password handling'),
  );
  expect(password?.measured).toBe('measured');
  expect(['high', 'critical']).toContain(password?.severity);

  await popup.close();
});

test('the tracker signal recognises third-party hosts on a page that loads only them', async () => {
  await visit(TRACKER_PAGE_URL);
  const tabId = await tabIdForUrl(session, TRACKER_PAGE_URL);
  const popup = await openPopup(session, tabId);

  await waitForSettled(popup);
  const drilldown = await openDrilldown(popup);
  const tracker = drilldown.findings.find((finding) =>
    finding.title.toLowerCase().includes('third-party tracking'),
  );

  // Four tracker hosts are loaded by the fixture, and the popup must report them as trackers -
  // which is only possible if the content script read the page's own resource timings and the
  // knowledge base matched them at DNS-label boundaries.
  expect(tracker).toBeDefined();
  expect(tracker?.effect).not.toBe('No points deducted');
  const surface = drilldown.findings.find((finding) =>
    finding.title.toLowerCase().includes('third-party surface'),
  );
  expect(surface?.effect).toContain('points');

  await popup.close();
});

test('the popup redraws itself when a fuller score arrives for the same tab', async () => {
  await visit(SECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, SECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);
  await waitForSettled(popup);

  // Navigating the tab the popup is reporting on must produce a new score without reopening it.
  const page = session.pages().find((candidate) => candidate.url().startsWith(SECURE_PAGE_URL));
  expect(page).toBeDefined();
  await page?.goto(INSECURE_PAGE_URL, { waitUntil: 'load' });

  await expect
    .poll(async () => (await readPopup(popup)).score, { timeout: 30_000 })
    .toBeLessThanOrEqual(40);

  const snapshot = await refreshPopup(popup);
  expect(snapshot.grade).toBe('F');

  await popup.close();
});

test('a well-configured HTTPS page scores 90 or better, and says why', async () => {
  await visit(SECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, SECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);

  await waitForSettled(popup);
  const snapshot = await readPopup(popup);

  expect(snapshot.status).toBe('ready');
  expect(snapshot.score).not.toBeNull();
  expect(snapshot.score as number).toBeGreaterThanOrEqual(90);
  expect(snapshot.grade).toMatch(/^A/);
  // The progress bar and the number agree, because both come from the same score.
  expect(snapshot.barValue).toBe(snapshot.score);
  expect(snapshot.pendingNote).toBeNull();
  expect(snapshot.headline.toLowerCase()).toContain('trustworthy');

  const drilldown = await openDrilldown(popup);
  expect(drilldown.findings.length).toBeGreaterThanOrEqual(15);
  // Reputation is a stated gap, not a hidden one (see D-004).
  expect(drilldown.reputation).toContain('not yet analyzed');
  // Nothing on this page should be charged: it is the reference "clean" fixture.
  expect(drilldown.findings.filter((finding) => finding.severity === 'critical')).toEqual([]);

  // Phase 2: the clean page contacts no third party, so its Cookies tab must show zero
  // tracking cookies — the cookie observer ran (collected) and genuinely found nothing.
  await openCookiesTab(popup);
  await expect
    .poll(() => cookiesTabSnapshot(popup), { timeout: 15_000 })
    .toMatchObject({ total: 0, collected: true });
  expect(await cookieRows(popup)).toEqual([]);

  await popup.close();
});

// ---------------------------------------------------------------------------
// Cookies tab (Phase 2, Task 2.6.6)
// ---------------------------------------------------------------------------

/** Clicks the Cookies tab and waits until the panel is visible. */
async function openCookiesTab(popup): Promise<void> {
  await popup.click('[data-testid="tab-cookie-transparency"]');
  await popup.waitForSelector('[data-testid="cookie-panel"]:not([hidden])');
}

/** Everything the Cookies tab is showing. */
async function cookiesTabSnapshot(popup): Promise<{ total: number; collected: boolean }> {
  return popup.evaluate(() => {
    const totalText = document.getElementById('cookie-summary-total')?.textContent?.trim() ?? '';
    const parsed = Number.parseInt(totalText, 10);
    // The "not collected" note being hidden is what distinguishes "0 cookies" from "nobody looked".
    const noteHidden = document.getElementById('cookie-disabled-note')?.hasAttribute('hidden') ?? false;
    return { total: Number.isNaN(parsed) ? -1 : parsed, collected: noteHidden };
  });
}

/** The visible cookie rows, one entry per cookie the popup shows. */
async function cookieRows(popup): Promise<{ name: string; category: string; setter: string }[]> {
  return popup.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="cookie-row"]')).map((row) => ({
      name: row.querySelector('.cookie-name')?.textContent?.trim() ?? '',
      category: row.getAttribute('data-category') ?? '',
      setter: row.querySelector('.cookie-setter')?.textContent?.trim() ?? '',
    })),
  );
}

test('the insecure page shows the tracking cookies its third-party scripts planted', async () => {
  // Seed the cookie store with the cookies the tracker hosts stand for (see TRACKER_COOKIE_SEEDS
  // in scripts/e2e-server.mjs for why this is seeded rather than Set-Cookie'd). After this, the
  // only way these cookies can appear in the popup is Sentinel's own third-party pipeline:
  // the page's resource timings name the origins, the cookie observer queries them, the
  // classifier recognises them, and the TrustEngine ships them to the popup.
  await session.context.addCookies(
    TRACKER_COOKIE_SEEDS.map((seed) => ({
      name: seed.name,
      value: seed.value,
      domain: seed.domain,
      path: '/',
      secure: true,
      httpOnly: false,
      sameSite: 'Lax' as const,
      expires: Math.floor(Date.now() / 1000) + seed.maxAge,
    })),
  );

  await visit(INSECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, INSECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);
  await waitForSettled(popup);

  await openCookiesTab(popup);

  // The third-party cookie pass runs after the content script's tracker report, so the popup
  // may first show a report with zero cookies (the page-URL pass alone). Poll until the rows
  // the tracker hosts planted actually appear.
  await expect
    .poll(async () => (await cookieRows(popup)).length, { timeout: 30_000 })
    .toBeGreaterThanOrEqual(5);

  const rows = await cookieRows(popup);
  const names = rows.map((row) => row.name);

  expect(names).toContain('_ga');
  expect(names).toContain('_gid');
  expect(names).toContain('_fbp');
  expect(names).toContain('fr');
  expect(names).toContain('ajs_anonymous_id');
  expect(rows.length).toBeGreaterThanOrEqual(5);

  const fbp = rows.find((row) => row.name === '_fbp');
  expect(fbp?.category).toBe('advertising');
  expect(fbp?.setter).toContain('Meta');

  const gid = rows.find((row) => row.name === '_gid');
  expect(gid?.category).toBe('analytics');
  expect(gid?.setter).toContain('Google Analytics');

  // No cookie row may ever carry a value: the popup has nowhere to put one (D-007).
  const popupHtml = await popup.content();
  expect(popupHtml).not.toContain('GA1.1.1000000000');
  expect(popupHtml).not.toContain('fb.1.1700000000');

  await popup.close();
});
// ---------------------------------------------------------------------------
// Changes tab (Phase 3, D-008)
// ---------------------------------------------------------------------------

/** Clicks the Changes tab and waits until the panel is visible. */
async function openChangesTab(popup: Page): Promise<void> {
  await popup.click('[data-testid="tab-change-monitor"]');
  await popup.waitForSelector('[data-testid="changes-panel"]:not([hidden])');
}

/** The visible change rows, one entry per change the popup shows. */
async function changeRows(popup: Page): Promise<{ kind: string; detail: string; severity: string }[]> {
  return popup.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="change-row"]')).map((row) => ({
      kind: row.getAttribute('data-change-kind') ?? '',
      detail: row.querySelector('.finding-detail')?.textContent?.trim() ?? '',
      severity: row.getAttribute('data-severity') ?? '',
    })),
  );
}

async function changesSummary(popup: Page): Promise<string> {
  return popup.evaluate(() => document.getElementById('changes-summary')?.textContent?.trim() ?? '');
}

test('the Change Monitor reports how a site changed between visits', async () => {
  // Use ONE page for both visits and keep the popup bound to its tab: tab ids are resolved by
  // URL only once (for the trackers visit), after which the popup redraws itself from
  // MSG_SCORE_UPDATED. Re-resolving by URL would be ambiguous here — the warm-up page from
  // beforeAll also sits on clean.html.
  const page: Page =
    session.pages().find((candidate) => candidate.url().startsWith('http')) ??
    (await session.context.newPage());

  // Visit the tracker fixture and wait until it settles: "settled" implies the content report
  // arrived, which implies the background recorded the scan before publishing. The profile's
  // last recorded scan for this domain is now deterministically the tracker page.
  await page.goto(TRACKER_PAGE_URL, { waitUntil: 'load' });
  const tabId = await tabIdForUrl(session, TRACKER_PAGE_URL);
  const trackersPopup = await openPopup(session, tabId);
  await waitForSettled(trackersPopup);
  await trackersPopup.close();

  // The clean fixture sits on the same registrable domain (secure.test) — the key profiles are
  // stored under — and loads no trackers: the recorded scans must differ, so the Changes panel
  // must report the tracker hosts disappearing. Navigating the same tab keeps the popup bound;
  // it redraws itself when the fuller, recorded score is broadcast.
  await page.goto(SECURE_PAGE_URL, { waitUntil: 'load' });
  const popup = await openPopup(session, tabId);
  await waitForSettled(popup);

  await openChangesTab(popup);

  // The clean scan's digest is attached before its score is published, so the row should be
  // there already; the poll only covers the popup's own redraw race.
  await expect
    .poll(
      async () =>
        (await changeRows(popup)).filter((row) => row.kind === 'trackers' && row.detail.includes('fewer'))
          .length,
      { timeout: 30_000 },
    )
    .toBeGreaterThanOrEqual(1);

  const rows = await changeRows(popup);
  const trackers = rows.find((row) => row.kind === 'trackers');
  expect(trackers?.detail).toContain('fewer than last time');

  const summary = await changesSummary(popup);
  expect(summary).toContain('secure.test');
  expect(summary).toContain('Seen');

  await popup.close();
});

// ---------------------------------------------------------------------------
// Headers tab (Phase 4, D-009)
// ---------------------------------------------------------------------------

test('the Header Dashboard shows the response headers beside recommended practice', async () => {
  await visit(SECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, SECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);
  await waitForSettled(popup);

  await popup.click('[data-testid="tab-header-dashboard"]');
  await popup.waitForSelector('[data-testid="headers-panel"]:not([hidden])');

  const rows = await popup.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="header-row"]')).map((row) => ({
      present: row.getAttribute('data-present'),
      recommended: row.getAttribute('data-recommended'),
      title: row.querySelector('.finding-title')?.textContent?.trim() ?? '',
      value: row.querySelector('.header-value')?.textContent?.trim() ?? '',
    })),
  );

  // The secure fixture sends a real CSP, and the dashboard shows the actual value.
  const csp = rows.find((row) => row.title.includes('Content Security Policy'));
  expect(csp?.present).toBe('yes');
  expect(csp?.value.length ?? 0).toBeGreaterThan(0);

  // Headers the fixture does not send are reported absent with the recommended value —
  // and only because the response was actually observed (D-006).
  const absent = rows.find((row) => row.present === 'no');
  expect(absent?.recommended).toBe('yes');
  expect(absent?.value).toBe('absent');

  const summary = await popup.evaluate(
    () => document.getElementById('headers-summary')?.textContent?.trim() ?? '',
  );
  expect(summary).toContain('response headers observed');
  expect(summary).toContain('recommended headers present');

  await popup.close();
});

// ---------------------------------------------------------------------------
// Extensions tab (Phase 4, D-010)
// ---------------------------------------------------------------------------

test('the Extension Auditor lists the other extension and its over-broad permissions', async () => {
  await visit(SECURE_PAGE_URL);
  const tabId = await tabIdForUrl(session, SECURE_PAGE_URL);
  const popup = await openPopup(session, tabId);
  await waitForSettled(popup);

  // The audit is fetched lazily when the tab is opened; wait for the rows to appear.
  await popup.click('[data-testid="tab-extension-auditor"]');
  await popup.waitForSelector('[data-testid="extensions-panel"]:not([hidden])');
  await popup.waitForSelector('[data-testid="extension-row"]', { timeout: 30_000 });

  const summary = await popup.evaluate(
    () => document.getElementById('extensions-summary')?.textContent?.trim() ?? '',
  );
  // The audit reviewed the fixture; headless Chromium can surface its own component
  // extensions too, so the count is asserted loosely while the fixture's row is asserted
  // exactly.
  expect(summary).toMatch(/extension(s)? reviewed/);

  const rows = await popup.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="extension-row"]')).map((row) => ({
      risk: row.getAttribute('data-risk'),
      name: row.querySelector('.finding-title')?.textContent?.trim() ?? '',
      text: row.textContent?.trim() ?? '',
    })),
  );
  expect(rows.length).toBeGreaterThanOrEqual(1);
  // D-010: Sentinel does not audit itself — no row may be Sentinel's own entry.
  for (const row of rows) {
    expect(row.name.startsWith('Sentinel —')).toBe(false);
    expect(row.name).not.toBe('Sentinel');
  }
  // The fixture declares history + cookies + <all_urls>: high risk, with the findings spelled out.
  const fixture = rows.find((row) => row.name.includes('Sentinel Audit Fixture'));
  expect(fixture).toBeDefined();
  expect(fixture?.risk).toBe('high');
  expect(fixture?.text).toContain('Browsing history');
  expect(fixture?.text).toContain('Broad host access');

  await popup.close();
});

// ---------------------------------------------------------------------------
// Options page (Phase 5, D-011)
// ---------------------------------------------------------------------------

/** Mirrors `SETTINGS_KEY` in `src/shared/settings.ts` (not imported: it pulls in `wxt/browser`). */
const SETTINGS_KEY = 'sentinel:settings';

test('the options page toggles modules and forgets all site history', async () => {
  // Give the forget action something to remove: the tracker fixture visit records a profile.
  await visit(TRACKER_PAGE_URL);

  const options = await session.context.newPage();
  await options.goto(`chrome-extension://${session.extensionId}/options.html`);
  await options.waitForSelector('[data-testid="option-row"]');

  const rows = await options.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="option-row"]')).map((row) => ({
      id: row.getAttribute('data-module-id'),
      checked: (row.querySelector('input') as HTMLInputElement).checked,
      label: row.querySelector('.module-title')?.textContent?.trim() ?? '',
    })),
  );
  expect(rows).toHaveLength(5);
  expect(rows.every((row) => row.checked)).toBe(true);
  expect(rows.find((row) => row.id === 'header-dashboard')?.label).toBe('Header Dashboard');

  // Toggle a module off: the settings store records the decision.
  await options.click('[data-testid="option-toggle-header-dashboard"]');
  let stored = await options.evaluate(async (key) => (await chrome.storage.local.get(key))[key], SETTINGS_KEY);
  expect(stored.enabledModules).not.toContain('header-dashboard');

  // And back on.
  await options.click('[data-testid="option-toggle-header-dashboard"]');
  stored = await options.evaluate(async (key) => (await chrome.storage.local.get(key))[key], SETTINGS_KEY);
  expect(stored.enabledModules).toContain('header-dashboard');

  // The "Your data" section lists what the tracker visit recorded (Phase 6, D-013):
  // metadata only — domain, scan count, last score, last seen.
  await options.waitForSelector('[data-testid="site-row"]');
  const siteRows = await options.evaluate(() =>
    Array.from(document.querySelectorAll('[data-testid="site-row"]')).map((row) => ({
      domain: row.getAttribute('data-domain') ?? '',
      text: row.textContent?.trim() ?? '',
    })),
  );
  expect(siteRows.length).toBeGreaterThanOrEqual(1);
  // The row carries the profile's metadata line (scan count, last seen); the count itself
  // depends on how many earlier tests visited this registrable domain.
  for (const row of siteRows) {
    expect(row.domain).not.toBe('');
    expect(row.text).toMatch(/Seen \d+/);
    expect(row.text).toContain('last seen');
  }

  // Per-site forget is a one-click user action; forget every listed site (earlier tests may
  // have recorded more than one registrable domain) and the refreshed list empties out.
  const countRows = (): Promise<number> =>
    options.evaluate(() => document.querySelectorAll('[data-testid="site-row"]').length);
  for (let guard = 0; (await countRows()) > 0 && guard < 12; guard += 1) {
    await options.click('[data-testid="site-row"] [data-testid="site-forget"]');
    await options.waitForTimeout(400);
  }
  expect(await countRows()).toBe(0);
  const emptySummary = await options.evaluate(
    () => document.getElementById('site-summary')?.textContent?.trim() ?? '',
  );
  expect(emptySummary).toContain('No site history recorded');

  // Record the site again so the confirmed bulk clear provably removes something.
  await visit(TRACKER_PAGE_URL);

  // Forget all site history: arm, then confirm — destructive only after two clicks (D-011).
  await options.click('[data-testid="forget-all"]');
  await options.click('[data-testid="forget-all-confirm"]');
  await options.waitForSelector('[data-testid="forget-all-note"]:not([hidden])');
  const note = await options.evaluate(
    () => document.getElementById('forget-all-note')?.textContent?.trim() ?? '',
  );
  expect(note).toMatch(/Forgotten [1-9]\d* sites?\./);

  // The refreshed list is empty, and storage no longer holds any profile.
  await expect
    .poll(async () => (await options.evaluate(() => document.querySelectorAll('[data-testid="site-row"]').length)), {
      timeout: 15_000,
    })
    .toBe(0);

  const profileKeys = await options.evaluate(async () =>
    Object.keys(await chrome.storage.local.get(null)).filter((key) => key.startsWith('sentinel:profile:')),
  );
  expect(profileKeys).toHaveLength(0);

  await options.close();
});

// ---------------------------------------------------------------------------
// The popup surface a real user gets (release 0.2.0)
// ---------------------------------------------------------------------------

test('the popup opened the way the toolbar opens it describes the tab the user is looking at', async () => {
  // Every other test in this file opens `popup.html?tabId=N`, which is not how anyone uses the
  // extension: a real toolbar click passes no tab id at all, and the background resolves "whatever
  // tab the user is looking at" itself (`resolveTargetTabId` in src/entrypoints/background.ts).
  // Nothing else covers that branch - and a bug in it would leave every other test green while
  // breaking the product completely.
  //
  // A popup has to be a page to be driveable, and opening it makes it the active tab. So the
  // fixture page is brought back to the front first, which is the state a real popup is in when it
  // asks: open, but not the tab anyone is looking at.
  await visit(INSECURE_PAGE_URL);
  const page = session.pages().find((candidate) => candidate.url().startsWith('http://insecure.test')) as Page;

  const popup = await session.context.newPage();
  await popup.goto(`chrome-extension://${session.extensionId}/popup.html`);

  // Reloading after `bringToFront` is what makes the popup ask again while the page is the active
  // tab. Bounded rather than unbounded, because which tab the browser considers active on this path
  // is the browser's business and not something to assume.
  let tabUrl = '';
  for (let attempt = 0; attempt < 3 && !tabUrl.includes('insecure.test'); attempt += 1) {
    await page.bringToFront();
    await popup.reload();
    await popup.waitForTimeout(500);
    tabUrl = (await popup.textContent('#url'))?.trim() ?? '';
  }
  expect(tabUrl, 'the popup never described the active tab').toContain('insecure.test');

  await waitForSettled(popup);
  const snapshot = await readPopup(popup);
  expect(snapshot.status).toBe('ready');
  expect(snapshot.score as number).toBeLessThanOrEqual(40);
  expect(snapshot.grade).toBe('F');

  await popup.close();
});
