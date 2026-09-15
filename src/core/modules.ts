/**
 * The module registry.
 *
 * Sentinel's features are grouped into five modules that can each be switched off on their
 * own, so this file is the single place that declares which ones exist, what they are
 * called, and whether they contribute findings yet. `TrustEngine` uses it to report a
 * `ModuleRunStatus` for every scan, and the options page uses it to lay out the toggles.
 *
 * A module with `state: 'planned'` has no analysers yet. It can already be toggled and
 * appears in scan results as `ran: false`, so the wiring is exercised before the analysis
 * exists and no result ever claims a planned module looked at anything.
 */

import type { ModuleId, ModuleState } from './types';

export interface ModuleDefinition {
  id: ModuleId;
  label: string;
  /** One sentence, written for the options page. */
  description: string;
  state: ModuleState;
}

/** Every module, in the order the UI should show them. */
export const MODULES: readonly ModuleDefinition[] = [
  {
    id: 'trust-score',
    label: 'Trust Score',
    description:
      'Scores a page on connection security, response hardening, privacy exposure and page hygiene, and explains every finding.',
    state: 'active',
  },
  {
    id: 'header-dashboard',
    label: 'Header Dashboard',
    description: 'Shows the response headers a site sends next to the values good practice recommends.',
    state: 'active',
  },
  {
    id: 'cookie-transparency',
    label: 'Cookies',
    description: 'Explains which cookies a page sets or receives, who they belong to and how long they last.',
    state: 'active',
  },
  {
    id: 'change-monitor',
    label: 'Changes',
    description: 'Remembers how each site looked last time and reports when its security posture changes.',
    state: 'active',
  },
  {
    id: 'extension-auditor',
    label: 'Extension Auditor',
    description: 'Reviews the other extensions you have installed for over-broad permissions and known risks.',
    state: 'active',
  },
];

const MODULE_INDEX = new Map<string, ModuleDefinition>(MODULES.map((module) => [module.id, module]));

export function getModule(id: string): ModuleDefinition | undefined {
  return MODULE_INDEX.get(id);
}

export function isKnownModule(id: string): id is ModuleId {
  return MODULE_INDEX.has(id);
}

/** Every module id, in UI order. */
export function moduleIds(): ModuleId[] {
  return MODULES.map((module) => module.id);
}

/** Modules that produce findings today. */
export function activeModules(): ModuleDefinition[] {
  return MODULES.filter((module) => module.state === 'active');
}
