import { startFixtureServers } from '../../scripts/e2e-server.mjs';

/**
 * Global setup (Phase 5): the fixture servers start once per Playwright invocation.
 *
 * Before this, the servers lived in `beforeAll`, which binds them per *worker* — and with
 * `--repeat-each`, Playwright recycles workers mid-run, so a recycled group's `beforeAll`
 * raced the previous worker's teardown (and its Chromium keep-alive connections, which keep
 * `server.close()` pending) and failed with EADDRINUSE. One set of servers for the whole
 * invocation removes the race at its root: workers share the fixed ports, and teardown
 * happens once, after every worker is gone.
 *
 * `stopFixtureServers` is exported because Playwright gives `globalTeardown` no handle to
 * this setup's return value — both files run in the same runner process, so the module-level
 * `stop` below is shared state, not duplicated state.
 */
let stop: (() => Promise<void>) | null = null;

export default async function globalSetup(): Promise<void> {
  const servers = await startFixtureServers();
  stop = servers.stop;
}

/** Closes the fixture servers; safe to call when they were never started. */
export async function stopFixtureServers(): Promise<void> {
  const current = stop;
  stop = null;
  await current?.();
}
