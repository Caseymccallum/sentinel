/**
 * The `ProfileStorageAdapter` backed by `browser.storage.local` (Phase 3, D-008).
 *
 * This is the persistence boundary `DomainProfileStore` deliberately leaves open: the core
 * never imports a browser API, and this adapter contains nothing but key-prefix plumbing and
 * validation. Profiles live under `sentinel:profile:<domain>` alongside the settings key, are
 * keyed by registrable domain, and hold metadata only (D-008).
 *
 * A stored record that fails validation is treated as absent rather than thrown — a corrupt
 * profile can only ever cost a site its history, never break a scan.
 */

import { browser } from 'wxt/browser';
import type { DomainProfile, ProfileStorageAdapter } from '../core/domain-profile';

const KEY_PREFIX = 'sentinel:profile:';

export function profileKey(domain: string): string {
  return `${KEY_PREFIX}${domain}`;
}

/** Structural check so a corrupt or foreign record under our prefix is dropped, not trusted. */
function isDomainProfile(value: unknown): value is DomainProfile {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<DomainProfile>;
  return (
    typeof candidate.domain === 'string' &&
    candidate.domain !== '' &&
    typeof candidate.hostname === 'string' &&
    typeof candidate.createdAt === 'number' &&
    typeof candidate.updatedAt === 'number' &&
    typeof candidate.scanCount === 'number' &&
    Array.isArray(candidate.thirdPartyHosts) &&
    Array.isArray(candidate.trackerHosts)
  );
}

export function createBrowserProfileAdapter(): ProfileStorageAdapter {
  return {
    async read(domain) {
      try {
        const key = profileKey(domain);
        const stored = (await browser.storage.local.get(key)) as Record<string, DomainProfile | undefined>;
        const profile = stored[key];
        return isDomainProfile(profile) ? profile : null;
      } catch {
        return null;
      }
    },

    async write(profile) {
      try {
        await browser.storage.local.set({ [profileKey(profile.domain)]: profile });
      } catch {
        // Storage full or unavailable: history is a luxury, never a dependency.
      }
    },

    async list() {
      try {
        const stored = (await browser.storage.local.get(null)) as Record<string, unknown>;
        return Object.entries(stored)
          .filter(([key]) => key.startsWith(KEY_PREFIX))
          .map(([, value]) => value)
          .filter(isDomainProfile);
      } catch {
        return [];
      }
    },

    async remove(domain) {
      try {
        await browser.storage.local.remove(profileKey(domain));
      } catch {
        // Already gone, or storage unavailable: forgetting is idempotent.
      }
    },

    async clear() {
      try {
        const stored = (await browser.storage.local.get(null)) as Record<string, unknown>;
        const keys = Object.keys(stored).filter((key) => key.startsWith(KEY_PREFIX));
        if (keys.length > 0) await browser.storage.local.remove(keys);
      } catch {
        // Nothing to clear, or storage unavailable.
      }
    },
  };
}
