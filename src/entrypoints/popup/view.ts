/**
 * The popup's rendering layer.
 *
 * Everything here is a pure function of a `ScoreResponse`: it reads the DOM it is given, writes
 * text and attributes, and decides nothing about the page. Scoring lives in `src/core`, plain
 * language lives in `ExplanationBuilder`, and module metadata lives in `src/core/modules.ts` - so
 * this file can be (and is) unit-tested in jsdom without a browser or an extension.
 *
 * Two rules from the brief are visible in the code below:
 *
 *   1. **Never block.** The score is whatever the background worker had in `storage.session`; the
 *      popup never waits for a content script, and when the tracker and form checks have not run
 *      yet it says "checking…" instead of showing a number that is not there (D-006).
 *   2. **Reputation is not a measurement.** There is no reputation term in the model (D-004), so the
 *      drill-down states that plainly rather than leaving the user to wonder.
 */

import { ExplanationBuilder } from '../../core/explanation-builder';
import { MODULES } from '../../core/modules';
import type {
  ClassifiedCookie,
  ExtensionAuditReport,
  Finding,
  FindingView,
  ModuleId,
  ProfileChange,
  ScanResult,
  Severity,
} from '../../core/types';
import type { ScoreResponse } from '../../shared/messages';

const builder = new ExplanationBuilder();

/** How many reasons the collapsed view shows before the user opens the drill-down. */
export const MAX_VISIBLE_REASONS = 4;

/**
 * Marker glyphs.
 *
 * Written as escapes on purpose: these four characters are the popup's entire visual vocabulary for
 * "fine", "worth knowing", "serious" and "could not check", and an editor or tool that mangles an
 * emoji would silently change what the user is told. The comment names each glyph.
 */
export const MARKER_OK = '\u2705'; // ✅ nothing deducted
export const MARKER_WARN = '\u26A0\uFE0F'; // ⚠️ points deducted, not serious
export const MARKER_BAD = '\u274C'; // ❌ serious finding
export const MARKER_UNMEASURED = '\u25CC'; //  could not be checked

export type Marker = typeof MARKER_OK | typeof MARKER_WARN | typeof MARKER_BAD | typeof MARKER_UNMEASURED;

/**
 * The marker the drill-down puts next to a finding.
 *
 * A check that could not run gets `◌` rather than a green tick: "we could not look" and "we looked
 * and it was fine" are different statements, and using one glyph for both would be a lie of
 * omission (D-006).
 */
export function findingMarker(finding: FindingView): Marker {
  if (finding.measured === null) return MARKER_UNMEASURED;
  if (finding.impact <= 0) return MARKER_OK;
  const rank = ['info', 'low', 'medium', 'high', 'critical'];
  return rank.indexOf(finding.severity) >= rank.indexOf('high') ? MARKER_BAD : MARKER_WARN;
}

export interface FindingRow {
  marker: Marker;
  /** Screen-reader text for the marker, e.g. "no points deducted". */
  markerLabel: string;
  view: FindingView;
}

const MARKER_LABELS: Readonly<Record<Marker, string>> = {
  [MARKER_OK]: 'Nothing deducted',
  [MARKER_WARN]: 'Worth knowing',
  [MARKER_BAD]: 'Serious finding',
  [MARKER_UNMEASURED]: 'Could not be checked',
};

/** Findings in the order the model sorted them (worst first), described for the UI. */
export function findingRows(result: ScanResult): FindingRow[] {
  const categories = result.score?.categories ?? [];
  const byId = new Map(categories.map((category) => [category.categoryId, category]));

  return result.findings.map((finding: Finding) => {
    const view = builder.describeFinding(finding, byId.get(finding.categoryId));
    const marker = findingMarker(view);
    return { marker, markerLabel: MARKER_LABELS[marker], view };
  });
}

/** The plain-language lines the main view shows, from the explanation builder. */
export function visibleReasons(result: ScanResult, limit = MAX_VISIBLE_REASONS): string[] {
  const highlights = result.explanation.highlights;
  if (highlights.length > 0) return highlights.slice(0, limit);

  const caveats = result.explanation.coverageNote === null ? [] : [result.explanation.coverageNote];
  if (result.findings.length === 0) return caveats;
  return caveats.slice(0, limit);
}

/** How the score should read at a glance. */
export function scoreTone(value: number | null): 'good' | 'fair' | 'poor' | 'unknown' {
  if (value === null) return 'unknown';
  if (value >= 80) return 'good';
  if (value >= 60) return 'fair';
  return 'poor';
}

/**
 * "Tracker and form checks are still running" - and which of the two, because the popup can only
 * promise what it knows. Returns `null` once everything that can be measured has been.
 */
export function analyzingNote(result: ScanResult): string | null {
  const { domReportAvailable, resourcesCollected } = result.observation;
  const pending: string[] = [];
  if (!resourcesCollected) pending.push('third-party tracking');
  if (!domReportAvailable) pending.push('forms and embedded content');
  if (pending.length === 0) return null;
  return `Still checking ${pending.join(' and ')}. Reload the page if this does not settle.`;
}

/** Text for a status that has no score: the popup must always say *why*. */
export function statusMessage(response: ScoreResponse): string {
  if (response.note) return response.note;
  switch (response.status) {
    case 'unsupported':
      return 'Sentinel analyses web pages (http and https). This page is part of the browser itself.';
    case 'none':
      return 'Sentinel has not seen this page yet. Reload the tab to let it observe the request.';
    case 'pending':
      return 'Sentinel is still observing this page.';
    default:
      // `ready` without a result should not happen; if it ever does, say so rather than showing a
      // blank panel or implying that the page was clean.
      return 'Sentinel has no report for this tab yet. Reload the page to have it look again.';
  }
}

/** One line per module, for the toggle bar. Planned modules are shown but cannot be switched on. */
export function moduleRows(enabled: readonly string[] = ['trust-score']): {
  id: string;
  label: string;
  state: string;
  enabled: boolean;
}[] {
  return MODULES.map((module) => ({
    id: module.id,
    label: module.label,
    state: module.state,
    enabled: module.state === 'active' && enabled.includes(module.id),
  }));
}
/** Text of the reputation line. Reputation is not measured, and the popup says so (D-004). */
export const REPUTATION_LINE =
  'Reputation: not yet analyzed. Sentinel has no network access, so it cannot look a site up in a reputation service.';

function element(doc: Document, id: string): HTMLElement | null {
  return doc.getElementById(id);
}

/**
 * Writes text into an element when it exists.
 *
 * A missing element is not an error here: the popup's markup and this code are separate files, and
 * a drift between them should degrade one line of the popup rather than break the whole panel.
 */
export function setText(doc: Document, id: string, text: string): void {
  const node = element(doc, id);
  if (node) node.textContent = text;
}

function setHidden(doc: Document, id: string, hidden: boolean): void {
  const node = element(doc, id);
  if (!node) return;
  if (hidden) node.setAttribute('hidden', '');
  else node.removeAttribute('hidden');
}

/** The value shown next to the dial: a number, or an em dash when there is no score. */
export function scoreText(response: ScoreResponse): string {
  return response.result?.score?.value !== undefined ? String(response.result.score.value) : '—';
}

export function gradeText(response: ScoreResponse): string {
  return response.result?.score?.grade ?? '–';
}

/**
 * Renders the whole popup from one response.
 *
 * Called on open and again whenever the background worker publishes a fuller score, so the popup
 * never needs a refresh button and never polls. `cookieModuleEnabled` is the user's setting; the
 * live click handlers are attached once by `main.ts`, which is why `renderCookiePanel` accepts
 * (and `renderResponse` passes an empty) handler set.
 */
export function renderResponse(
  doc: Document,
  response: ScoreResponse,
  cookieModuleEnabled = true,
  changesModuleEnabled = true,
  headersModuleEnabled = true,
): void {
  const result = response.result;
  const value = result?.score?.value ?? null;
  const tone = scoreTone(value);

  // The panel's own state, so tests and the stylesheet can key off it without string matching.
  const root = element(doc, 'popup');
  if (root) {
    root.dataset.status = response.status;
    root.dataset.tone = tone;
  }

  setText(doc, 'url', response.tabUrl ?? 'No page reported yet');
  setText(doc, 'score-value', scoreText(response));
  setText(doc, 'grade', gradeText(response));
  setText(doc, 'headline', result?.explanation.headline ?? 'Nothing to score yet');
  // The summary line is the explanation when there is a score, and the reason there is no score
  // when there is not. A user should never see a generic status line next to a real number.
  setText(doc, 'summary', result ? result.explanation.summary : statusMessage(response));

  // The progress bar is the score: labelled, valued and described for assistive technology.
  const bar = element(doc, 'score-bar');
  if (bar) {
    bar.setAttribute('role', 'progressbar');
    bar.setAttribute('aria-valuemin', '0');
    bar.setAttribute('aria-valuemax', '100');
    bar.setAttribute('aria-valuenow', value === null ? '0' : String(value));
    bar.setAttribute(
      'aria-valuetext',
      value === null
        ? 'No score yet'
        : `${value} out of 100, grade ${result?.score?.grade ?? 'unknown'}`,
    );
    bar.setAttribute('aria-label', 'Trust score out of 100');
    const fill = element(doc, 'score-bar-fill');
    if (fill) fill.style.width = `${value ?? 0}%`;
  }

  const reasons = element(doc, 'reasons');
  if (reasons) {
    reasons.textContent = '';
    if (result) {
      for (const reason of visibleReasons(result)) {
        const item = doc.createElement('li');
        item.textContent = reason;
        reasons.appendChild(item);
      }
    }
  }

  const note = element(doc, 'pending-note');
  const pending = result ? analyzingNote(result) : null;
  if (note) {
    note.textContent = pending ?? '';
    if (pending === null) note.setAttribute('hidden', '');
    else note.removeAttribute('hidden');
  }

  const coverage = element(doc, 'coverage-note');
  const coverageText = result?.explanation.coverageNote ?? '';
  if (coverage) {
    coverage.textContent = coverageText;
    if (coverageText === '') coverage.setAttribute('hidden', '');
    else coverage.removeAttribute('hidden');
  }

  setText(doc, 'reputation', REPUTATION_LINE);
  setHidden(doc, 'why-button', result === null);
  renderFindings(doc, result ? findingRows(result) : []);
  renderTabs(doc, activeTabOf(doc));
  renderCookiePanel(doc, result, cookieModuleEnabled, {});
  renderChangesPanel(doc, result, changesModuleEnabled, {});
  renderHeadersPanel(doc, result, headersModuleEnabled);
}
/** Writes every finding into the drill-down, with its marker and its plain-language detail. */
export function renderFindings(doc: Document, rows: readonly FindingRow[]): void {
  const list = element(doc, 'findings');
  if (!list) return;
  list.textContent = '';

  for (const row of rows) {
    const item = doc.createElement('li');
    item.className = 'finding';
    item.dataset.severity = row.view.severity;
    item.dataset.measured = row.view.measured === null ? 'unmeasured' : 'measured';

    const marker = doc.createElement('span');
    marker.className = 'finding-marker';
    marker.setAttribute('aria-label', row.markerLabel);
    marker.textContent = row.marker;

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'finding-title';
    title.textContent = row.view.title;
    const category = doc.createElement('span');
    category.className = 'finding-category';
    category.textContent = `${row.view.categoryLabel} · ${row.view.confidenceLabel}`;
    title.appendChild(category);

    const detail = doc.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = row.view.detail;

    const effect = doc.createElement('p');
    effect.className = 'finding-effect';
    effect.textContent = row.view.scoreEffect;

    body.append(title, detail, effect);
    if (row.view.remediation) {
      const fix = doc.createElement('p');
      fix.className = 'finding-fix';
      fix.textContent = `Fix: ${row.view.remediation}`;
      body.appendChild(fix);
    }
    if (row.view.evidence.length > 0) {
      const details = doc.createElement('details');
      const summary = doc.createElement('summary');
      summary.textContent = `Technical detail (${row.view.evidence.length})`;
      const dl = doc.createElement('dl');
      for (const evidenceRow of row.view.evidence) {
        const dt = doc.createElement('dt');
        dt.textContent = evidenceRow.label;
        const dd = doc.createElement('dd');
        dd.textContent = evidenceRow.value;
        dl.append(dt, dd);
      }
      details.append(summary, dl);
      body.appendChild(details);
    }

    item.append(marker, body);
    list.appendChild(item);
  }
}

/** The popup's content panels; every module now has a real tab. */
export type PopupTab =
  | 'trust-score'
  | 'cookie-transparency'
  | 'change-monitor'
  | 'header-dashboard'
  | 'extension-auditor';

export const COOKIE_MODULE_ID: ModuleId = 'cookie-transparency';
export const CHANGE_MONITOR_MODULE_ID: ModuleId = 'change-monitor';
export const DEFAULT_TAB: PopupTab = 'trust-score';

/** Panel element ids, so `setActiveTab` and `activeTabOf` can never disagree. */
const PANEL_IDS: Readonly<Record<PopupTab, string>> = {
  'trust-score': 'panel-trust-score',
  'cookie-transparency': 'panel-cookies',
  'change-monitor': 'panel-changes',
  'header-dashboard': 'panel-headers',
  'extension-auditor': 'panel-extensions',
};

/** Shorter names for the tab bar; the options page keeps the full module labels. */
const TAB_LABELS: Partial<Record<ModuleId, string>> = {
  'header-dashboard': 'Headers',
  'extension-auditor': 'Extensions',
};

/** One tab in the tab bar (the module bar, expanded into a real selector). */
export function tabRows(): { id: string; label: string; state: string }[] {
  return MODULES.map((module) => ({
    id: module.id,
    label: TAB_LABELS[module.id] ?? module.label,
    state: module.state,
  }));
}

/** Renders the tab bar: active modules are selectable, planned ones stay disabled. */
export function renderTabs(doc: Document, activeTab: PopupTab): void {
  const bar = element(doc, 'tab-bar');
  if (!bar) return;
  bar.textContent = '';

  for (const row of tabRows()) {
    const button = doc.createElement('button');
    button.type = 'button';
    button.className = 'tab';
    button.id = `tab-${row.id}`;
    button.setAttribute('data-testid', `tab-${row.id}`);
    button.setAttribute('role', 'tab');
    button.textContent = row.state === 'active' ? row.label : `${row.label} (not yet built)`;

    const selected = row.state === 'active' && row.id === activeTab;
    button.setAttribute('aria-selected', selected ? 'true' : 'false');
    button.classList.toggle('active', selected);
    if (row.state !== 'active') button.disabled = true;

    bar.appendChild(button);
  }
}

/** Shows one panel and hides the others, then re-renders the tab bar to match. */
export function setActiveTab(doc: Document, tab: PopupTab): void {
  for (const [id, panelId] of Object.entries(PANEL_IDS) as [PopupTab, string][]) {
    const node = element(doc, panelId);
    if (node) node.hidden = id !== tab;
  }
  renderTabs(doc, tab);
}

/** The tab currently shown, derived from the panels rather than stored separately. */
export function activeTabOf(doc: Document): PopupTab {
  for (const [id, panelId] of Object.entries(PANEL_IDS) as [PopupTab, string][]) {
    const node = element(doc, panelId);
    if (node && !node.hidden) return id;
  }
  return DEFAULT_TAB;
}

/** Click handlers `main.ts` attaches; `renderCookiePanel` invokes them, never the browser APIs. */
export interface CookiePanelHandlers {
  onDelete?(cookie: ClassifiedCookie): void;
  onBulkDelete?(cookies: readonly ClassifiedCookie[]): void;
}

/** A cookie is individually deletable when the knowledge base says so (conservative: D-007). */
export function cookieDeletable(cookie: ClassifiedCookie): boolean {
  return cookie.safeToDelete === 'yes' || cookie.safeToDelete === 'will-log-out';
}

const SAFE_TO_DELETE_LABELS: Readonly<Record<ClassifiedCookie['safeToDelete'], string>> = {
  yes: 'Delete',
  'will-log-out': 'Delete (logs out)',
  no: 'Essential — do not delete',
  unknown: 'Purpose unknown',
};

/** SameSite flag as a short label; `unspecified` is omitted rather than shown as noise. */
function sameSiteLabel(sameSite: ClassifiedCookie['sameSite']): string | null {
  if (sameSite === 'no_restriction') return 'SameSite None';
  if (sameSite === 'lax') return 'SameSite Lax';
  if (sameSite === 'strict') return 'SameSite Strict';
  return null;
}

/** Splits `__Host-`/`__Secure-` prefixes out so the UI can highlight them. */
export function splitCookiePrefix(name: string): { prefix: string | null; rest: string } {
  for (const prefix of ['__Host-', '__Secure-']) {
    if (name.startsWith(prefix)) return { prefix, rest: name.slice(prefix.length) };
  }
  return { prefix: null, rest: name };
}

function cookieSummaryBreakdown(summary: NonNullable<ScanResult['cookies']>['summary']): string {
  const parts: string[] = [];
  if (summary.essential > 0) parts.push(`${summary.essential} essential`);
  if (summary.advertising > 0) parts.push(`${summary.advertising} advertising`);
  if (summary.analytics > 0) parts.push(`${summary.analytics} analytics`);
  if (summary.social > 0) parts.push(`${summary.social} social`);
  if (summary.unknown > 0) parts.push(`${summary.unknown} unknown`);
  return parts.join(' · ');
}

/** Renders the Cookies panel: summary header, module toggle state, rows, bulk action. */
export function renderCookiePanel(
  doc: Document,
  result: ScanResult | null,
  moduleEnabled: boolean,
  handlers: CookiePanelHandlers,
): void {
  const toggle = element(doc, 'cookie-module-toggle') as HTMLInputElement | null;
  if (toggle) toggle.checked = moduleEnabled;

  const note = element(doc, 'cookie-disabled-note');
  const list = element(doc, 'cookie-list');
  const bulk = element(doc, 'cookie-bulk-delete') as HTMLButtonElement | null;
  const confirm = element(doc, 'cookie-confirm');
  if (!list || !note || !bulk || !confirm) return;

  const clear = (message: string) => {
    list.textContent = '';
    setText(doc, 'cookie-summary-total', '');
    setText(doc, 'cookie-summary-breakdown', '');
    setText(doc, 'cookie-summary-longest', '');
    bulk.hidden = true;
    confirm.hidden = true;
    note.textContent = message;
    note.removeAttribute('hidden');
  };

  if (!moduleEnabled) {
    // D-007 in action: with the module off the background never calls the cookie API, and the
    // panel explains that instead of showing stale data.
    clear('Cookie analysis is switched off. Sentinel will not read cookies until you enable it.');
    return;
  }

  const report = result?.cookies ?? null;
  if (report === null || !report.collected) {
    clear('Cookie data has not been collected for this page yet. Reload the page to let Sentinel look.');
    return;
  }

  const { cookies, summary } = report;
  note.textContent = '';
  note.setAttribute('hidden', '');

  setText(doc, 'cookie-summary-total', `${summary.total} ${summary.total === 1 ? 'cookie' : 'cookies'}`);
  setText(
    doc,
    'cookie-summary-breakdown',
    summary.total === 0 ? 'No cookies apply to this page.' : cookieSummaryBreakdown(summary),
  );
  setText(
    doc,
    'cookie-summary-longest',
    summary.longestExpirationName !== null && summary.longestExpirationDays > 0
      ? `Longest-lasting: ${summary.longestExpirationName} (${summary.longestExpirationDays} days)`
      : '',
  );

  list.textContent = '';
  for (const cookie of cookies) {
    list.appendChild(cookieRow(doc, cookie, handlers));
  }

  const bulkTargets = cookies.filter((cookie) => cookieDeletable(cookie));
  if (bulkTargets.length === 0) {
    bulk.hidden = true;
  } else {
    bulk.textContent = `Delete all tracking cookies (${bulkTargets.length})`;
    bulk.removeAttribute('hidden');
    bulk.onclick = () => handlers.onBulkDelete?.(bulkTargets);
  }
  confirm.hidden = true;
}

function flagList(cookie: ClassifiedCookie): string[] {
  const flags: string[] = [];
  if (cookie.secure) flags.push('Secure');
  if (cookie.httpOnly) flags.push('HttpOnly');
  const sameSite = sameSiteLabel(cookie.sameSite);
  if (sameSite !== null) flags.push(sameSite);
  return flags;
}

function lifetimeText(cookie: ClassifiedCookie): string {
  if (cookie.session) return 'session';
  if (typeof cookie.expirationDate !== 'number') return 'no expiry reported';
  const days = Math.max(0, Math.round((cookie.expirationDate * 1000 - Date.now()) / 86_400_000));
  return days === 1 ? 'expires in 1 day' : `expires in ${days} days`;
}

/** One cookie row: name (prefix highlighted), setter, badge, lifetime, flags, explanation. */
function cookieRow(doc: Document, cookie: ClassifiedCookie, handlers: CookiePanelHandlers): HTMLElement {
  const item = doc.createElement('li');
  item.className = 'cookie-row';
  item.dataset.category = cookie.category;
  item.dataset.cookieId = cookie.id;
  item.setAttribute('data-testid', 'cookie-row');

  const header = doc.createElement('div');
  header.className = 'cookie-row-header';

  const { prefix, rest } = splitCookiePrefix(cookie.name);
  const name = doc.createElement('span');
  name.className = 'cookie-name';
  if (prefix !== null) {
    const marker = doc.createElement('span');
    marker.className = 'cookie-prefix';
    marker.textContent = prefix;
    name.appendChild(marker);
  }
  name.appendChild(doc.createTextNode(rest));

  const setter = doc.createElement('span');
  setter.className = 'cookie-setter';
  setter.textContent = `· ${cookie.setBy}`;

  const badge = doc.createElement('span');
  badge.className = 'cookie-badge';
  badge.dataset.category = cookie.category;
  badge.textContent = cookie.category;

  header.append(name, setter, badge);

  const meta = doc.createElement('p');
  meta.className = 'cookie-meta';
  const flags = flagList(cookie);
  meta.textContent = `${lifetimeText(cookie)}${flags.length > 0 ? ` · ${flags.join(' · ')}` : ''}`;

  const explanation = doc.createElement('p');
  explanation.className = 'cookie-explanation';
  explanation.textContent = cookie.description;

  const body = doc.createElement('div');
  body.className = 'cookie-row-body';
  body.append(header, meta, explanation);

  if (cookieDeletable(cookie)) {
    const button = doc.createElement('button');
    button.type = 'button';
    button.className = 'cookie-delete';
    button.setAttribute('data-testid', 'cookie-delete');
    button.textContent = SAFE_TO_DELETE_LABELS[cookie.safeToDelete];
    button.title = cookie.safeToDelete === 'will-log-out' ? 'Deleting this cookie will log you out of this site.' : '';
    button.onclick = () => handlers.onDelete?.(cookie);
    item.append(body, button);
  } else {
    const keep = doc.createElement('span');
    keep.className = 'cookie-keep';
    keep.textContent = SAFE_TO_DELETE_LABELS[cookie.safeToDelete];
    item.append(body, keep);
  }

  return item;
}

/** Click handlers `main.ts` attaches for the Changes panel. */
export interface ChangesPanelHandlers {
  onForget?(): void;
}

const CHANGE_KIND_LABELS: Readonly<Record<ProfileChange['kind'], string>> = {
  score: 'Score',
  trackers: 'Trackers',
  'third-party': 'Third parties',
  headers: 'Headers',
  signals: 'Signals',
  certificate: 'Certificate',
};

/** Glyph for a change row: worse is a warning, better is fine, everything else is a note. */
function changeMarker(change: ProfileChange): Marker {
  if (!change.worsened) return change.severity === 'info' ? MARKER_OK : MARKER_WARN;
  return change.severity === 'high' || change.severity === 'critical' ? MARKER_BAD : MARKER_WARN;
}

/** Renders the Changes panel: history line, module toggle state, change rows, forget action. */
export function renderChangesPanel(
  doc: Document,
  result: ScanResult | null,
  moduleEnabled: boolean,
  handlers: ChangesPanelHandlers,
): void {
  const toggle = element(doc, 'changes-module-toggle') as HTMLInputElement | null;
  if (toggle) toggle.checked = moduleEnabled;

  const note = element(doc, 'changes-disabled-note');
  const list = element(doc, 'changes-list');
  const summary = element(doc, 'changes-summary');
  const forget = element(doc, 'changes-forget') as HTMLButtonElement | null;
  if (!list || !note || !summary || !forget) return;

  const clear = (message: string) => {
    list.textContent = '';
    summary.textContent = '';
    forget.hidden = true;
    note.textContent = message;
    note.removeAttribute('hidden');
  };

  if (!moduleEnabled) {
    // D-008 in action: with the module off nothing is recorded and nothing is compared.
    clear('Change monitoring is switched off. Sentinel will not record site history or report changes until you enable it.');
    return;
  }

  const history = result?.history;
  if (history === undefined) {
    clear('No history for this site yet. Reload the page so Sentinel can record a full scan.');
    return;
  }

  note.textContent = '';
  note.setAttribute('hidden', '');

  const historyParts = [`Seen ${history.scanCount} ${history.scanCount === 1 ? 'time' : 'times'}`];
  if (history.lastScore !== null) historyParts.push(`last score ${history.lastScore}`);
  if (history.averageScore !== null) historyParts.push(`average ${history.averageScore}`);
  historyParts.push(`last seen ${history.lastSeenLabel}`);
  summary.textContent = `${historyParts.join(' · ')} (${history.domain}).`;

  const changes = result?.changes ?? [];
  list.textContent = '';
  for (const change of changes) {
    const item = doc.createElement('li');
    item.className = 'finding';
    item.dataset.severity = change.severity;
    item.dataset.changeKind = change.kind;
    item.setAttribute('data-testid', 'change-row');

    const marker = doc.createElement('span');
    marker.className = 'finding-marker';
    marker.textContent = changeMarker(change);

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'finding-title';
    title.textContent = CHANGE_KIND_LABELS[change.kind];
    const detail = doc.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = change.detail;
    body.append(title, detail);

    item.append(marker, body);
    list.appendChild(item);
  }

  forget.textContent = 'Forget this site';
  forget.removeAttribute('hidden');
  forget.onclick = () => handlers.onForget?.();
}

/** Renders the Headers panel (Phase 4, D-009): every observed header beside recommended practice. */
export function renderHeadersPanel(
  doc: Document,
  result: ScanResult | null,
  moduleEnabled: boolean,
): void {
  const toggle = element(doc, 'headers-module-toggle') as HTMLInputElement | null;
  if (toggle) toggle.checked = moduleEnabled;

  const note = element(doc, 'headers-disabled-note');
  const list = element(doc, 'headers-list');
  const summary = element(doc, 'headers-summary');
  if (!list || !note || !summary) return;

  const clear = (message: string) => {
    list.textContent = '';
    summary.textContent = '';
    note.textContent = message;
    note.removeAttribute('hidden');
  };

  if (!moduleEnabled) {
    clear('Header display is switched off. Sentinel will not show response headers until you enable it.');
    return;
  }

  const report = result?.headers ?? null;
  if (report === null) {
    clear('Header data has not been collected for this page yet. Reload the page to let Sentinel look.');
    return;
  }
  if (!report.available) {
    clear('Sentinel did not observe this page load, so its response headers are unknown.');
    return;
  }

  note.textContent = '';
  note.setAttribute('hidden', '');

  const presentRecommended = report.rows.filter((row) => row.recommended && row.present).length;
  const recommendedTotal = report.rows.filter((row) => row.recommended).length;
  summary.textContent =
    `${report.observedCount} response headers observed \u00b7 ` +
    `${presentRecommended} of ${recommendedTotal} recommended headers present.`;

  list.textContent = '';
  for (const row of report.rows) {
    const item = doc.createElement('li');
    item.className = 'finding header-row';
    item.dataset.present = row.present ? 'yes' : 'no';
    item.dataset.recommended = row.recommended ? 'yes' : 'no';
    item.setAttribute('data-testid', 'header-row');

    const marker = doc.createElement('span');
    marker.className = 'finding-marker';
    marker.textContent = row.present ? MARKER_OK : MARKER_WARN;
    marker.setAttribute('aria-label', row.present ? 'Header present' : 'Recommended header absent');

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'finding-title';
    title.textContent = row.label;
    const name = doc.createElement('span');
    name.className = 'finding-category';
    name.textContent = row.name;
    title.appendChild(name);

    const value = doc.createElement('p');
    value.className = 'header-value';
    value.textContent = row.present ? row.value : 'absent';

    body.append(title, value);
    if (!row.present && row.guidance !== null) {
      const guidance = doc.createElement('p');
      guidance.className = 'finding-fix';
      guidance.textContent = `Recommended: ${row.guidance}`;
      body.appendChild(guidance);
    }

    item.append(marker, body);
    list.appendChild(item);
  }
}

/** Plain-language labels for the audit severities, shared by the summary line and the rows. */
const SEVERITY_LABELS: Readonly<Record<Severity, string>> = {
  info: 'No concern',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

/** Glyph for an extension's overall risk: serious findings cross, concerns warn, the rest tick. */
function riskMarker(risk: Severity): Marker {
  if (risk === 'critical' || risk === 'high') return MARKER_BAD;
  if (risk === 'medium' || risk === 'low') return MARKER_WARN;
  return MARKER_OK;
}

/** Everything the Extensions panel needs to draw one frame; owned by `main.ts`. */
export interface ExtensionsPanelState {
  moduleEnabled: boolean;
  /** True while the background has not answered yet; the popup never blocks on it. */
  loading: boolean;
  report: ExtensionAuditReport | null;
  /** Shown instead of a report when the audit could not run. */
  note?: string | null;
}

/**
 * Renders the Extensions panel (Phase 4, D-010). The audit is fetched lazily, when the user
 * first opens the tab — it is not part of the page scan, so it must not slow the page score.
 */
export function renderExtensionsPanel(doc: Document, state: ExtensionsPanelState): void {
  const toggle = element(doc, 'extensions-module-toggle') as HTMLInputElement | null;
  if (toggle) toggle.checked = state.moduleEnabled;

  const note = element(doc, 'extensions-disabled-note');
  const list = element(doc, 'extensions-list');
  const summary = element(doc, 'extensions-summary');
  if (!list || !note || !summary) return;

  const clear = (message: string) => {
    list.textContent = '';
    summary.textContent = '';
    note.textContent = message;
    note.removeAttribute('hidden');
  };

  if (!state.moduleEnabled) {
    clear('The Extension Auditor is switched off. Sentinel will not list your other extensions until you enable it.');
    return;
  }
  if (state.loading) {
    clear('Checking the extensions installed in this browser\u2026');
    return;
  }
  if (state.note) {
    clear(state.note);
    return;
  }
  const report = state.report;
  if (report === null) {
    clear('Sentinel could not audit the installed extensions.');
    return;
  }

  note.textContent = '';
  note.setAttribute('hidden', '');

  if (report.extensions.length === 0) {
    summary.textContent = 'No other extensions are installed. (Sentinel does not audit itself.)';
    return;
  }

  const worst = report.extensions[0]?.risk ?? 'info';
  summary.textContent =
    `${report.extensions.length} ${report.extensions.length === 1 ? 'extension' : 'extensions'} reviewed \u00b7 ` +
    `highest concern: ${SEVERITY_LABELS[worst].toLowerCase()}.`;

  list.textContent = '';
  for (const entry of report.extensions) {
    const item = doc.createElement('li');
    item.className = 'finding ext-row';
    item.dataset.risk = entry.risk;
    item.dataset.enabled = entry.enabled ? 'yes' : 'no';
    item.setAttribute('data-testid', 'extension-row');

    const marker = doc.createElement('span');
    marker.className = 'finding-marker';
    marker.textContent = riskMarker(entry.risk);
    marker.setAttribute('aria-label', SEVERITY_LABELS[entry.risk]);

    const body = doc.createElement('div');
    const title = doc.createElement('p');
    title.className = 'finding-title';
    title.textContent = entry.name;
    const version = doc.createElement('span');
    version.className = 'finding-category';
    version.textContent = `v${entry.version}${entry.enabled ? '' : ' \u00b7 disabled'}`;
    title.appendChild(version);
    body.appendChild(title);

    for (const finding of entry.findings) {
      const line = doc.createElement('p');
      line.className = 'finding-detail ext-permission';
      line.dataset.severity = finding.severity;
      line.textContent = `${finding.label}: ${finding.why}`;
      body.appendChild(line);
    }

    item.append(marker, body);
    list.appendChild(item);
  }
}



