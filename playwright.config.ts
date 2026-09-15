import { defineConfig } from '@playwright/test';

/**
 * Playwright configuration for Sentinel's end-to-end "money test".
 *
 * The test loads the *built* extension, so `npm run test:e2e` builds first. Everything runs
 * serially in one worker: the fixtures share fixed ports (4173, 4174 and 8788) and the extension
 * writes to `browser.storage.session`, so parallel workers would fight over both.
 *
 * Deliberately not part of `npm run verify`: verify has to run anywhere the source does, while this
 * needs a Chromium download and a built extension. It is the gate for changes to the collection
 * layer, and it is documented in `docs/DEVELOPMENT.md`.
 */
export default defineConfig({
  testDir: './tests/e2e',
  // Only the specs: `tests/e2e/fixtures` holds the pages the server serves.
  testMatch: /.*\.spec\.ts$/,
  // The fixture servers bind fixed ports (4173, 4174, 8788) once per invocation, in the
  // runner process — never per worker, whose recycle under `--repeat-each` used to race the
  // next group's bind (D-012-era harness fix).
  globalSetup: './tests/e2e/global-setup.ts',
  globalTeardown: './tests/e2e/global-teardown.ts',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  reporter: [['list']],
  use: {
    trace: 'retain-on-failure',
  },
});