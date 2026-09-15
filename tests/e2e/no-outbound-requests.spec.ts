/**
 * The zero-outbound-request check (RELEASE.md §4), automated.
 *
 * Sentinel's central promise is that nothing leaves the browser. `check:local-only` proves that of
 * the source and of every built bundle, but not of the running product: a dependency could call an
 * API whose request never appears as a literal anywhere, and a browser could act on the extension's
 * behalf. This test closes that gap by launching the extension in a real Chromium, driving it, and
 * failing if *any* request in the whole browser context leaves a small set of origins a clean run is
 * allowed to touch.
 *
 * The rule is deliberately fail-closed, and deliberately broader than "requests made by Sentinel":
 * any request to an origin outside the list fails, whichever part of the browser made it. That
 * matters because a request made from the content script is attributed to the *page's* frame — a
 * DevTools check has to notice it by URL alone, and so does this. The cost is that the allow-list has
 * to name everything a clean run legitimately touches, so it is derived from
 * `scripts/e2e-server.mjs` rather than written out, and any addition to it is a visible edit.
 *
 * What a full drive actually produces was measured, not assumed: eleven request signatures, all of
 * them the extension's own pages and assets, the fixture pages and stylesheets, the four tracker
 * stubs those fixtures load (served from 127.0.0.1 by host-resolver rules), and Chromium's own
 * `chrome://theme` resource while `openOptionsPage()` renders chrome://extensions. No remote host.
 */

import { expect, test } from '@playwright/test';
import { resolve } from 'node:path';
import {
  CROSS_ORIGIN_HOST,
  HTTP_PORT,
  HTTPS_PORT,
  INSECURE_HOST,
  INSECURE_PAGE_URL,
  SECURE_HOST,
  SECURE_PAGE_URL,
  TRACKER_HOSTS,
  TRACKER_PAGE_URL,
  TRACKER_PORT,
} from '../../scripts/e2e-server.mjs';
import { launchExtension, openPopup, tabIdForUrl, waitForSettled, type ExtensionSession } from './extension';

/** The origins a clean run may touch, taken from the fixture server so they cannot drift apart. */
const FIXTURE_ORIGINS = new Set([
  `https://${SECURE_HOST}:${HTTPS_PORT}`,
  `http://${INSECURE_HOST}:${HTTP_PORT}`,
  `https://${CROSS_ORIGIN_HOST}:${TRACKER_PORT}`,
  ...TRACKER_HOSTS.map((host) => `https://${host}:${TRACKER_PORT}`),
]);

/**
 * Schemes that cannot reach the network. `chrome:` is the browser's own UI — opening the options
 * page lands on `chrome://extensions/?options=…`, which pulls its channel logo from `chrome://theme`.
 * That request belongs to Chromium, not to Sentinel, and failing on it would make this check lie.
 */
const ALLOWED_SCHEMES = new Set(['chrome-extension:', 'chrome:', 'data:', 'blob:', 'about:', 'devtools:']);

/**
 * A request's scheme and authority.
 *
 * `new URL(...).origin` is useless here: for the non-special schemes in the list above it is the
 * string "null", which would make every extension page look like the same origin.
 */
function sourceOf(url: string): string {
  const scheme = /^([a-z][a-z0-9+.-]*:)/i.exec(url)?.[1].toLowerCase() ?? '';
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(url)?.[1] ?? '';
  return authority === '' ? scheme : `${scheme}//${authority}`;
}

/**
 * Whether a request is one a clean run may make.
 *
 * The scheme is checked on its own: `chrome-extension://<id>/popup.html` has an authority, so its
 * `sourceOf` value is `chrome-extension://<id>` and would never match a bare scheme. Fixture traffic
 * is the opposite case — a real host and port, which is what the fixture-origin set holds.
 */
function isAllowed(url: string): boolean {
  const scheme = /^([a-z][a-z0-9+.-]*:)/i.exec(url)?.[1].toLowerCase() ?? '';
  if (ALLOWED_SCHEMES.has(scheme)) return true;
  return FIXTURE_ORIGINS.has(sourceOf(url));
}

/** The five module tabs, in the order the popup renders them. */
const POPUP_TABS = [
  'trust-score',
  'header-dashboard',
  'cookie-transparency',
  'change-monitor',
  'extension-auditor',
];

test('no request in the browser context leaves the fixtures, extension pages or chrome://', async () => {
  // Three pages through five tabs each, plus the options page: enough driving that a stray request
  // would have to be extremely well hidden to escape it.
  test.setTimeout(180_000);

  const observed: { url: string; source: string }[] = [];
  let session: ExtensionSession | undefined;

  try {
    // The audit fixture is loaded so the Extension Auditor has something to review: exercising
    // `chrome.management` is part of "drive the product" in RELEASE.md §4.
    session = await launchExtension([resolve('tests/fixtures/audit-extension')]);
    session.context.on('request', (request) => {
      observed.push({ url: request.url(), source: sourceOf(request.url()) });
    });

    // The first navigation of a cold browser can beat the service worker's listener registration
    // (DEVELOPMENT.md section 8); the warm-up is what makes the run below representative.
    const page = await session.context.newPage();
    await page.goto(SECURE_PAGE_URL, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(300);

    for (const url of [SECURE_PAGE_URL, TRACKER_PAGE_URL, INSECURE_PAGE_URL]) {
      await page.goto(url, { waitUntil: 'load' });
      await page.waitForTimeout(200);
      const popup = await openPopup(session, await tabIdForUrl(session, url));
      await waitForSettled(popup);
      for (const tab of POPUP_TABS) {
        await popup.click(`[data-testid="tab-${tab}"]`);
        await popup.waitForTimeout(400);
      }
      // Opening the options page is a real code path (settings read, recorded-site list) and the
      // only one that leaves the extension's own pages for the browser's UI.
      await popup.click('[data-testid="open-options"]');
      await popup.waitForTimeout(700);
      await popup.close();
    }
  } finally {
    await session?.close();
  }

  // First prove the drive happened. A check that passes because nothing was observed is worse than
  // no check at all: it would report success for a browser that never loaded the extension.
  expect(observed.length, 'the drive produced almost no requests, so it did not run').toBeGreaterThan(20);
  expect(
    observed.some((entry) => entry.source.startsWith('chrome-extension:')),
    'the extension pages were never loaded',
  ).toBe(true);
  expect(
    observed.some((entry) => FIXTURE_ORIGINS.has(entry.source)),
    'no fixture page was ever visited',
  ).toBe(true);

  const offenders = observed.filter((entry) => !isAllowed(entry.url));
  expect(offenders.map((entry) => `${entry.source}  ${entry.url}`).join('\n')).toBe('');
});

