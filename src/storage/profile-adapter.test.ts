/**
 * Browser profile-adapter tests (Phase 3, D-008).
 *
 * The adapter is the only place Sentinel's history touches a browser API, so the tests run
 * against WXT's in-memory fake browser: round-trips, the key-prefix boundary (a foreign key or
 * a corrupt record must never be trusted), forgetting, and clearing.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { createDomainProfile } from '../core/domain-profile';
import { createBrowserProfileAdapter, profileKey } from './profile-adapter';

const NOW = 1_700_000_000_000;

function seedProfile(domain: string) {
  return { ...createDomainProfile(domain, domain, NOW), scanCount: 2 };
}

beforeEach(() => {
  return fakeBrowser.reset();
});

describe('createBrowserProfileAdapter', () => {
  it('round-trips a profile through storage.local', async () => {
    const adapter = createBrowserProfileAdapter();
    const profile = seedProfile('example.com');

    await adapter.write(profile);
    const read = await adapter.read('example.com');

    expect(read).not.toBeNull();
    expect(read?.domain).toBe('example.com');
    expect(read?.scanCount).toBe(2);
  });

  it('reads an unknown domain as null', async () => {
    const adapter = createBrowserProfileAdapter();

    expect(await adapter.read('never-seen.example')).toBeNull();
  });

  it('treats a corrupt record under our key prefix as absent', async () => {
    await fakeBrowser.storage.local.set({ [profileKey('broken.example')]: { hello: 'world' } });
    const adapter = createBrowserProfileAdapter();

    expect(await adapter.read('broken.example')).toBeNull();
    expect(await adapter.list()).toEqual([]);
  });

  it('lists only profiles under the sentinel prefix, ignoring foreign keys', async () => {
    const adapter = createBrowserProfileAdapter();
    await adapter.write(seedProfile('a.example'));
    await adapter.write(seedProfile('b.example'));
    await fakeBrowser.storage.local.set({ 'sentinel:settings': { enabledModules: [] } });
    await fakeBrowser.storage.local.set({ 'unrelated': true });

    const domains = (await adapter.list()).map((profile) => profile.domain).sort();

    expect(domains).toEqual(['a.example', 'b.example']);
  });

  it('removes one domain without touching the others, and clears everything', async () => {
    const adapter = createBrowserProfileAdapter();
    await adapter.write(seedProfile('a.example'));
    await adapter.write(seedProfile('b.example'));

    await adapter.remove('a.example');
    expect(await adapter.read('a.example')).toBeNull();
    expect(await adapter.read('b.example')).not.toBeNull();

    await adapter.clear();
    expect(await adapter.list()).toEqual([]);
  });
});
