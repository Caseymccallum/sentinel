/**
 * Sentinel settings.
 *
 * Deliberately tiny: the only user decision stored today is which modules are enabled. The
 * important property is the one the Cookie Transparency permission justification (D-007)
 * promises: when the cookie module is switched off, the background never calls
 * `chrome.cookies.getAll()` at all, and no cookie signal appears in the score.
 *
 * Settings live in `browser.storage.local` (they are preferences, not per-page data) and are
 * read by the background before each scan and by the popup when it renders its toggles.
 */

import { browser } from 'wxt/browser';
import { MODULES } from '../core/modules';
import type { ModuleId } from '../core/types';

const SETTINGS_KEY = 'sentinel:settings';

export interface SentinelSettings {
  /** Modules the user has switched on. Anything absent is off. */
  enabledModules: ModuleId[];
}

/** Everything on: modules are opt-out, and a module that ships enabled stays enabled. */
export function defaultSettings(): SentinelSettings {
  return { enabledModules: MODULES.map((module) => module.id) };
}

/**
 * Pure normaliser: unknown or malformed stored settings fall back to defaults rather than
 * throwing, so a corrupt record can only ever widen availability back to defaults, never
 * crash a scan. An empty list is treated as malformed rather than "disable everything" —
 * the trust-score module has no reason to be switched off wholesale.
 */
export function normalizeSettings(value: unknown): SentinelSettings {
  const defaults = defaultSettings();
  if (typeof value !== 'object' || value === null) return defaults;
  const raw = (value as { enabledModules?: unknown }).enabledModules;
  if (!Array.isArray(raw)) return defaults;
  const enabled = defaults.enabledModules.filter((id) => raw.includes(id));
  if (enabled.length === 0) return defaults;
  return { enabledModules: enabled };
}

export function isModuleEnabled(settings: SentinelSettings, id: ModuleId): boolean {
  return settings.enabledModules.includes(id);
}

/**
 * Pure toggle: one module on/off, everything else untouched.
 *
 * The popup's per-panel switches and the options page's module list are two surfaces onto
 * the same decision (D-011), so both go through this helper — there is exactly one place
 * that knows how the enabled list is built.
 */
export function withModuleEnabled(settings: SentinelSettings, id: ModuleId, enabled: boolean): SentinelSettings {
  if (enabled) {
    if (settings.enabledModules.includes(id)) return settings;
    return { enabledModules: [...settings.enabledModules, id] };
  }
  return { enabledModules: settings.enabledModules.filter((module) => module !== id) };
}

export async function loadSettings(): Promise<SentinelSettings> {
  try {
    const stored = (await browser.storage.local.get(SETTINGS_KEY)) as Record<string, unknown>;
    return normalizeSettings(stored[SETTINGS_KEY]);
  } catch {
    return defaultSettings();
  }
}

export async function saveSettings(settings: SentinelSettings): Promise<void> {
  try {
    await browser.storage.local.set({ [SETTINGS_KEY]: settings });
  } catch {
    // Storage unavailable: the in-memory decision still governs this session.
  }
}
