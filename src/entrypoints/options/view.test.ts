// @vitest-environment jsdom
/**
 * Options view tests (Phase 5, D-011).
 *
 * The options page is where every module is explained in full, so the tests are about what the
 * user is told and what a toggle does: all five modules render with the user's current decision,
 * a change is reported back through the handler, and the forget-all section is destructive only
 * after a confirmed second click.
 */

import { describe, expect, it, vi } from 'vitest';
import { moduleRows, renderForgetSection, renderModules, renderProfileList } from './view';
import { defaultSettings, withModuleEnabled, type SentinelSettings } from '../../shared/settings';
import type { ProfileHistorySummary } from '../../core/types';

function optionsDocument(): Document {
  const doc = document.implementation.createHTMLDocument('options');
  doc.body.innerHTML = `
    <ul id="module-list"></ul>
    <p id="site-summary"></p>
    <ul id="site-list"></ul>
    <p id="forget-all-note" hidden></p>
    <button id="forget-all" hidden></button>
    <button id="forget-all-confirm" hidden></button>
  `;
  return doc;
}

describe('moduleRows', () => {
  it('lists every module in registry order with the user\u2019s decision attached', () => {
    const rows = moduleRows(defaultSettings());
    expect(rows.map((row) => row.id)).toEqual([
      'trust-score',
      'header-dashboard',
      'cookie-transparency',
      'change-monitor',
      'extension-auditor',
    ]);
    for (const row of rows) {
      expect(row.enabled).toBe(true);
      expect(row.description.length).toBeGreaterThan(0);
    }
  });

  it('reflects a stored off-switch as disabled, not as an error', () => {
    const settings: SentinelSettings = {
      enabledModules: defaultSettings().enabledModules.filter((id) => id !== 'change-monitor'),
    };
    const rows = moduleRows(settings);
    expect(rows.find((row) => row.id === 'change-monitor')?.enabled).toBe(false);
    expect(rows.find((row) => row.id === 'trust-score')?.enabled).toBe(true);
  });
});

describe('withModuleEnabled', () => {
  it('removes exactly one module and touches nothing else', () => {
    const next = withModuleEnabled(defaultSettings(), 'cookie-transparency', false);
    expect(next.enabledModules).not.toContain('cookie-transparency');
    expect(next.enabledModules).toHaveLength(4);
  });

  it('adds a module back exactly once', () => {
    const off = withModuleEnabled(defaultSettings(), 'cookie-transparency', false);
    const on = withModuleEnabled(off, 'cookie-transparency', true);
    expect(on.enabledModules).toHaveLength(5);
    expect(on.enabledModules.filter((id) => id === 'cookie-transparency')).toHaveLength(1);
  });

  it('is idempotent when the module is already in the requested state', () => {
    const before = defaultSettings();
    expect(withModuleEnabled(before, 'trust-score', true).enabledModules).toEqual(before.enabledModules);
    const off = withModuleEnabled(before, 'trust-score', false);
    expect(withModuleEnabled(off, 'trust-score', false).enabledModules).toEqual(off.enabledModules);
  });
});

describe('renderModules', () => {
  it('renders one checked row per module, with its description', () => {
    const doc = optionsDocument();
    renderModules(doc, defaultSettings());

    const rows = doc.querySelectorAll('[data-testid="option-row"]');
    expect(rows).toHaveLength(5);
    const first = rows[0] as HTMLElement;
    expect(first.dataset.moduleId).toBe('trust-score');
    expect((doc.getElementById('module-toggle-trust-score') as HTMLInputElement).checked).toBe(true);
    expect(first.textContent).toContain('Trust Score');
    expect(first.textContent?.length ?? 0).toBeGreaterThan('Trust Score'.length);
  });

  it('reports a toggle change through the handler with the module id', () => {
    const doc = optionsDocument();
    const onToggleModule = vi.fn();
    renderModules(doc, defaultSettings(), { onToggleModule });

    const cookieToggle = doc.getElementById('module-toggle-cookie-transparency') as HTMLInputElement;
    cookieToggle.checked = false;
    cookieToggle.dispatchEvent(new Event('change'));
    expect(onToggleModule).toHaveBeenCalledWith('cookie-transparency', false);

    cookieToggle.checked = true;
    cookieToggle.dispatchEvent(new Event('change'));
    expect(onToggleModule).toHaveBeenCalledWith('cookie-transparency', true);
  });
});

describe('renderForgetSection', () => {
  it('arms on the first click and only confirms on the second, separate button', () => {
    const doc = optionsDocument();
    const onArm = vi.fn();
    const onConfirm = vi.fn();
    renderForgetSection(doc, { armed: false, note: '' }, { onArm, onConfirm });

    const arm = doc.getElementById('forget-all') as HTMLButtonElement;
    const confirm = doc.getElementById('forget-all-confirm') as HTMLButtonElement;
    expect(arm.hidden).toBe(false);
    expect(confirm.hidden).toBe(true);

    arm.click();
    expect(onArm).toHaveBeenCalledTimes(1);
    expect(onConfirm).not.toHaveBeenCalled();

    renderForgetSection(doc, { armed: true, note: '' }, { onArm, onConfirm });
    expect((doc.getElementById('forget-all') as HTMLButtonElement).hidden).toBe(true);
    confirm.click();
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('shows the result note once a forget has run, and hides it when there is none', () => {
    const doc = optionsDocument();
    renderForgetSection(doc, { armed: false, note: 'Forgotten 3 sites.' });
    const note = doc.getElementById('forget-all-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('Forgotten 3 sites');

    renderForgetSection(doc, { armed: false, note: '' });
    expect(note.hidden).toBe(true);
  });
});

describe('renderProfileList', () => {
  const site = (domain: string, scanCount: number, lastScore: number | null): ProfileHistorySummary => ({
    domain,
    scanCount,
    lastScore,
    averageScore: lastScore,
    lastSeenLabel: '2 hours ago',
  });

  it('renders one metadata-only row per site, most recently seen first', () => {
    const doc = optionsDocument();
    renderProfileList(doc, [site('a.example', 3, 92), site('b.example', 1, null)]);

    const rows = doc.querySelectorAll('[data-testid="site-row"]');
    expect(rows).toHaveLength(2);
    expect(doc.getElementById('site-summary')?.textContent).toContain('2 sites recorded');
    expect(doc.getElementById('site-summary')?.textContent).toContain('never page paths or titles');

    const first = rows[0] as HTMLElement;
    expect(first.dataset.domain).toBe('a.example');
    expect(first.textContent).toContain('Seen 3 times');
    expect(first.textContent).toContain('last score 92');
    expect(first.textContent).toContain('last seen 2 hours ago');
    // A site with no score yet is shown honestly, not with a fabricated number.
    const second = rows[1] as HTMLElement;
    expect(second.textContent).toContain('Seen 1 time');
    expect(second.textContent).not.toContain('last score');
  });

  it('shows an empty store honestly, with no rows', () => {
    const doc = optionsDocument();
    renderProfileList(doc, []);
    expect(doc.getElementById('site-summary')?.textContent).toContain('No site history recorded');
    expect(doc.querySelectorAll('[data-testid="site-row"]')).toHaveLength(0);
  });

  it('wires each row\u2019s forget button to the handler with that row\u2019s domain', () => {
    const doc = optionsDocument();
    const onForgetSite = vi.fn();
    renderProfileList(doc, [site('a.example', 2, 80), site('b.example', 5, 64)], { onForgetSite });

    const buttons = Array.from(doc.querySelectorAll('[data-testid="site-forget"]')) as HTMLButtonElement[];
    expect(buttons).toHaveLength(2);
    buttons[1]?.click();
    expect(onForgetSite).toHaveBeenCalledTimes(1);
    expect(onForgetSite).toHaveBeenCalledWith('b.example');
    expect(buttons[0]?.getAttribute('aria-label')).toBe('Forget history for a.example');
  });
});
