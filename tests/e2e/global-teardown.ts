import { stopFixtureServers } from './global-setup';

/** Closes the fixture servers started by `global-setup.ts`, after every worker is gone. */
export default async function globalTeardown(): Promise<void> {
  await stopFixtureServers();
}
