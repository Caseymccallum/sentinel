/**
 * The options page's rendering layer (Phase 5, D-011).
 *
 * Pure functions of the settings: they read the DOM they are given, write text and
 * attributes, and decide nothing. The same discipline as the popup's `view.ts`, for the same
 * reason — the UI layer holds no analysis logic, so it can be unit-tested in jsdom without a
 * browser or an extension.
 */

import { MODULES } from '../../core/modules';
import type { ModuleId, ProfileHistorySummary } from '../../core/types';
import { isModuleEnabled, type SentinelSettings } from '../../shared/settings';

/** One row of the module list, as the options page shows it. */
export interface ModuleRowView {
  id: ModuleId;
  label: string;
  description: string;
  enabled: boolean;
}

/** Every module in UI order, with the user's current decision attached. */
export function moduleRows(settings: SentinelSettings): ModuleRowView[] {
  return MODULES.map((module) => ({
    id: module.id,
    label: module.label,
    description: module.description,
    enabled: isModuleEnabled(settings, module.id),
  }));
}

export interface OptionsHandlers {
  onToggleModule?(id: ModuleId, enabled: boolean): void;
}

/** Renders the module list from the current settings, re-wiring one listener per toggle. */
export function renderModules(
  doc: Document,
  settings: SentinelSettings,
  handlers: OptionsHandlers = {},
): void {
  const list = doc.getElementById('module-list');
  if (!list) return;

  list.textContent = '';
  for (const row of moduleRows(settings)) {
    const item = doc.createElement('li');
    item.className = 'module-row';
    item.dataset.moduleId = row.id;
    item.setAttribute('data-testid', 'option-row');

    const label = doc.createElement('label');
    label.className = 'module-toggle';
    label.htmlFor = `module-toggle-${row.id}`;

    const toggle = doc.createElement('input');
    toggle.type = 'checkbox';
    toggle.id = `module-toggle-${row.id}`;
    toggle.checked = row.enabled;
    toggle.setAttribute('data-testid', `option-toggle-${row.id}`);
    toggle.addEventListener('change', () => handlers.onToggleModule?.(row.id, toggle.checked));

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'module-title';
    title.textContent = row.label;
    const description = doc.createElement('p');
    description.className = 'module-description';
    description.textContent = row.description;
    body.append(title, description);

    label.append(toggle, body);
    item.appendChild(label);
    list.appendChild(item);
  }
}

/** The "forget all site history" section: arm, confirm, result note. */
export interface ForgetSectionHandlers {
  onArm?(): void;
  onConfirm?(): void;
}

export interface ForgetSectionState {
  /** True after the first click, when the destructive button is showing. */
  armed: boolean;
  /** Result of the last forget, shown until the next action. */
  note: string;
}

export function renderForgetSection(
  doc: Document,
  state: ForgetSectionState,
  handlers: ForgetSectionHandlers = {},
): void {
  const arm = doc.getElementById('forget-all') as HTMLButtonElement | null;
  const confirm = doc.getElementById('forget-all-confirm') as HTMLButtonElement | null;
  const note = doc.getElementById('forget-all-note');
  if (!arm || !confirm || !note) return;

  arm.hidden = state.armed;
  confirm.hidden = !state.armed;
  arm.onclick = () => handlers.onArm?.();
  confirm.onclick = () => handlers.onConfirm?.();

  note.textContent = state.note;
  if (state.note === '') note.setAttribute('hidden', '');
  else note.removeAttribute('hidden');
}

/**
 * Renders the recorded-site list (Phase 6, D-013): one metadata-only row per site, worst
 * memory last — most recently seen first, as the background sorted them. A row's forget
 * button is a one-click user action, like the popup's per-site forget; only the bulk clear
 * demands a confirmation (D-011).
 */
export interface ProfileListHandlers {
  onForgetSite?(domain: string): void;
}

/** Renders the site list and its summary line from the background's answer. */
export function renderProfileList(
  doc: Document,
  profiles: readonly ProfileHistorySummary[],
  handlers: ProfileListHandlers = {},
): void {
  const list = doc.getElementById('site-list');
  const summary = doc.getElementById('site-summary');
  if (!list || !summary) return;

  if (profiles.length === 0) {
    summary.textContent = 'No site history recorded.';
    list.textContent = '';
    return;
  }

  summary.textContent =
    `${profiles.length} ${profiles.length === 1 ? 'site' : 'sites'} recorded in this browser ` +
    '(metadata only \u2014 never page paths or titles).';

  list.textContent = '';
  for (const profile of profiles) {
    const item = doc.createElement('li');
    item.className = 'site-row';
    item.dataset.domain = profile.domain;
    item.setAttribute('data-testid', 'site-row');

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'module-title';
    title.textContent = profile.domain;
    const detail = doc.createElement('p');
    detail.className = 'module-description';
    const parts = [`Seen ${profile.scanCount} ${profile.scanCount === 1 ? 'time' : 'times'}`];
    if (profile.lastScore !== null) parts.push(`last score ${profile.lastScore}`);
    parts.push(`last seen ${profile.lastSeenLabel}`);
    detail.textContent = parts.join(' \u00b7 ');
    body.append(title, detail);

    const forget = doc.createElement('button');
    forget.type = 'button';
    forget.className = 'quiet-button';
    forget.textContent = 'Forget';
    forget.setAttribute('data-testid', 'site-forget');
    forget.setAttribute('aria-label', `Forget history for ${profile.domain}`);
    forget.onclick = () => handlers.onForgetSite?.(profile.domain);

    item.append(body, forget);
    list.appendChild(item);
  }
}
