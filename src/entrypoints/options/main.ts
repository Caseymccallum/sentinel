/**
 * The options page's wiring (Phase 5, D-011).
 *
 * The dumbest possible surface onto the settings store: load, render, and forward each user
 * action. Module toggles go through `withModuleEnabled` — the same helper the popup's panel
 * switches use — so the two surfaces can never disagree about how the enabled list is built.
 * The forget-all action asks the background worker, which owns the profile store; this page
 * never touches storage for history itself.
 */

import { browser } from 'wxt/browser';
import {
  MSG_FORGET_ALL_PROFILES,
  MSG_FORGET_SITE,
  MSG_LIST_PROFILES,
  type ForgetAllProfilesResponse,
  type ForgetSiteResponse,
  type ListProfilesResponse,
} from '../../shared/messages';
import {
  defaultSettings,
  loadSettings,
  saveSettings,
  withModuleEnabled,
  type SentinelSettings,
} from '../../shared/settings';
import type { ProfileHistorySummary } from '../../core/types';
import { renderForgetSection, renderModules, renderProfileList, type OptionsHandlers } from './view';

let settings: SentinelSettings = defaultSettings();
let forgetArmed = false;
let forgetNote = '';
/** The recorded sites (D-013); fetched on page open and refreshed after each forget. */
let sites: ProfileHistorySummary[] = [];

const moduleHandlers: OptionsHandlers = {
  onToggleModule(id, enabled) {
    settings = withModuleEnabled(settings, id, enabled);
    void saveSettings(settings);
    paint();
  },
};

const forgetHandlers = {
  onArm() {
    forgetArmed = true;
    paint();
  },
  onConfirm() {
    void (async () => {
      try {
        const answer = (await browser.runtime.sendMessage({
          type: MSG_FORGET_ALL_PROFILES,
        })) as ForgetAllProfilesResponse | undefined;
        forgetNote = answer
          ? `Forgotten ${answer.removed} ${answer.removed === 1 ? 'site' : 'sites'}.`
          : 'Sentinel could not clear the history.';
      } catch {
        forgetNote = 'Sentinel could not clear the history.';
      }
      forgetArmed = false;
      await refreshSites();
      paint();
    })();
  },
};

const siteHandlers = {
  onForgetSite(domain: string) {
    void (async () => {
      try {
        await browser.runtime.sendMessage({ type: MSG_FORGET_SITE, domain });
        forgetNote = `Forgotten ${domain}.`;
      } catch {
        forgetNote = 'Sentinel could not clear the history.';
      }
      await refreshSites();
      paint();
    })();
  },
};

/** Asks the background for the current recorded-site list (D-013). */
async function refreshSites(): Promise<void> {
  try {
    const answer = (await browser.runtime.sendMessage({
      type: MSG_LIST_PROFILES,
    })) as ListProfilesResponse | undefined;
    sites = answer?.profiles ?? [];
  } catch {
    // The worker may be starting up; an empty list is an honest "nothing shown yet" and the
    // user can reopen the page. Never invent sites we did not see.
    sites = [];
  }
}

function paint(): void {
  renderModules(document, settings, moduleHandlers);
  renderForgetSection(document, { armed: forgetArmed, note: forgetNote }, forgetHandlers);
  renderProfileList(document, sites, siteHandlers);
}

void (async () => {
  await refreshSites();
  settings = await loadSettings();
  paint();
})();
