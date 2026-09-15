#!/usr/bin/env node
/**
 * capture-popup - regenerates the popup screenshots that `README.md` shows.
 *
 * A README that shows the product is read; a screenshot nobody can reproduce is a claim rather
 * than evidence. So these images are produced here, from the *built* extension, in headless
 * Chromium, against the same local fixtures the money test drives (`scripts/e2e-server.mjs`) and
 * through the same harness (`tests/e2e/extension.ts`). No mockup, no hand-editing, no image that
 * cannot be re-derived: anyone can run `npm run screenshots` and compare the result.
 *
 * The fixture hostname visible inside the images (`insecure.test:4174`) is deliberate. A real
 * site's screenshot would be an unreproducible asset; this one is a command.
 *
 * Output: `docs/popup-score.png` (the whole popup), `docs/popup-cookies.png` (the Cookies panel)
 * and `docs/popup-findings.png` (the drill-down, cut after the sixth finding: a full capture of
 * this page's drill-down is 8296 px tall, which is a file nobody reads and a megabyte nobody needs).
 *
 * Usage:
 *   npm run screenshots      # builds first, then captures (see package.json)
 *
 * The harness is TypeScript, which Node executes directly from Node 23 on (type stripping), so
 * this script shares the harness rather than duplicating its launching rules. On an older runtime
 * `loadHarness` fails with a sentence instead of a stack trace.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { INSECURE_PAGE_URL, TRACKER_COOKIE_SEEDS, startFixtureServers } from './e2e-server.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DOCS_DIR = join(ROOT, 'docs');

/** Every image comes from one page, so the README tells one story: the worst fixture there is. */
const PAGE_URL = INSECURE_PAGE_URL;

/** 2x, because a 360 px popup rendered at 1x looks soft on any modern display. */
const DEVICE_SCALE_FACTOR = 2;

/**
 * How many findings `docs/popup-findings.png` carries. The fixture's drill-down runs to fifteen
 * rows; stopping after a whole row keeps the image readable rather than merely long.
 */
const DRILLDOWN_ROWS_CAPTURED = 6;

/**
 * Loads the e2e harness, or explains why it could not be loaded. The `catch` is the whole reason
 * this is a function: `import()` of a `.ts` file is a runtime feature, and the failure mode on an
 * unsupported Node is a syntax error with nothing in it about Node versions.
 */
async function loadHarness() {
  try {
    return await import('../tests/e2e/extension.ts');
  } catch (error) {
    throw new Error(
      `Could not load tests/e2e/extension.ts: ${error instanceof Error ? error.message : String(error)}. ` +
        'This script needs Node 23 or newer (older runtimes cannot execute TypeScript directly).',
    );
  }
}

/** Writes a PNG into `docs/` and reports its size. */
async function writePng(name, png) {
  await writeFile(join(DOCS_DIR, name), png);
  console.log(`  wrote docs/${name} (${(png.length / 1024).toFixed(1)} kB)`);
}

/** Screenshots one element, so the image is that element and nothing around it. */
async function capture(page, selector, name) {
  await writePng(name, await page.locator(selector).screenshot());
}

/**
 * Screenshots from the top of `container` down to the bottom of its `index`-th `child`, so the
 * image can never end halfway through a row. Width comes from `frame` - the popup itself - so a
 * cropped image is framed like the uncropped ones instead of losing the popup's side padding.
 *
 * `fullPage` is required because the container is taller than the viewport, and a clip is measured
 * from the document origin while `boundingBox()` answers in viewport coordinates - hence `scrollY`.
 */
async function captureThrough(page, frame, container, child, index, name) {
  const frameBox = await page.locator(frame).boundingBox();
  const box = await page.locator(container).boundingBox();
  const last = await page.locator(child).nth(index).boundingBox();
  if (frameBox === null || box === null || last === null) {
    throw new Error(`Cannot capture ${container} through ${child} #${index}: it is not on screen.`);
  }
  const scrollY = await page.evaluate(() => window.scrollY);
  await writePng(
    name,
    await page.screenshot({
      fullPage: true,
      clip: {
        x: frameBox.x,
        y: box.y + scrollY,
        width: frameBox.width,
        height: last.y + last.height - box.y,
      },
    }),
  );
}

/** Waits for the document's own fonts, so no image catches a fallback face mid-swap. */
async function fontsReady(page) {
  await page.evaluate(() => document.fonts.ready.then(() => undefined));
}

/**
 * Polls until at least `minimum` of `selector` are on screen.
 *
 * The Cookies panel fills in two stages - the page-URL pass first, then the third-party pass once
 * the content script has named the tracker origins - so capturing on first paint would photograph
 * an honestly empty list and call it a feature.
 */
async function waitForRows(page, selector, minimum, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const count = await page.locator(selector).count();
    if (count >= minimum) return count;
    if (Date.now() > deadline) {
      throw new Error(
        `Only ${count} of the expected ${minimum} "${selector}" row(s) appeared within ${timeoutMs} ms.`,
      );
    }
    await page.waitForTimeout(250);
  }
}

async function main() {
  const { launchExtension, openDrilldown, openPopup, tabIdForUrl, waitForSettled } = await loadHarness();
  await mkdir(DOCS_DIR, { recursive: true });

  const servers = await startFixtureServers();
  const session = await launchExtension([], { deviceScaleFactor: DEVICE_SCALE_FACTOR });

  try {
    // Warm-up, for the same reason the money test has one: the first navigation of a cold browser
    // can beat the service worker's `webRequest` listener registration. A page nobody observed
    // would be captured as "Sentinel did not observe this page load".
    const page = await session.context.newPage();
    await page.goto(PAGE_URL, { waitUntil: 'load' }).catch(() => {});
    await page.waitForTimeout(300);

    // The cookies the fixture tracker hosts stand for, seeded exactly as the money test seeds them
    // (`TRACKER_COOKIE_SEEDS` explains why they are seeded rather than sent as Set-Cookie).
    await session.context.addCookies(
      TRACKER_COOKIE_SEEDS.map((seed) => ({
        name: seed.name,
        value: seed.value,
        domain: seed.domain,
        path: '/',
        secure: true,
        httpOnly: false,
        sameSite: 'Lax',
        expires: Math.floor(Date.now() / 1000) + seed.maxAge,
      })),
    );

    await page.goto(PAGE_URL, { waitUntil: 'load' });
    await page.waitForTimeout(150);

    const tabId = await tabIdForUrl(session, PAGE_URL);
    const popup = await openPopup(session, tabId);
    // Wider than the popup's 360 px so the element is never clipped by the viewport it sits in.
    await popup.setViewportSize({ width: 400, height: 900 });
    await waitForSettled(popup);
    await fontsReady(popup);
    await capture(popup, '#popup', 'popup-score.png');

    await openDrilldown(popup);
    await fontsReady(popup);
    await captureThrough(
      popup,
      '#popup',
      '#drilldown',
      '#findings .finding',
      DRILLDOWN_ROWS_CAPTURED - 1,
      'popup-findings.png',
    );

    await popup.click('[data-testid="tab-cookie-transparency"]');
    await popup.waitForSelector('[data-testid="cookie-panel"]:not([hidden])');
    const rows = await waitForRows(popup, '[data-testid="cookie-row"]', 5);
    await fontsReady(popup);
    await capture(popup, '#popup', 'popup-cookies.png');

    console.log(`\nScreenshots regenerated from ${PAGE_URL} (${rows} cookie rows on screen).`);
    console.log('Commit the PNGs with the README change that needed them.');
  } finally {
    // A leaked fixture server holds a fixed port and breaks the next run (DEVELOPMENT.md section 8).
    await session.close();
    await servers.stop();
  }
}

await main();

