// @vitest-environment jsdom
/**
 * Popup view tests.
 *
 * The popup is where a score becomes a claim about a website, so these tests are about what the
 * user is told rather than about pixels:
 *
 *   - the score, the grade and the progress bar agree, and the bar carries the ARIA values that
 *     make it readable by assistive technology;
 *   - a check that has not run yet is shown as "still checking", never as a pass;
 *   - the drill-down marks "no points deducted", "worth knowing", "serious" and "could not be
 *     checked" differently;
 *   - "Reputation: not yet analyzed" is present, because there is no reputation term in the model.
 *
 * The fixture is a real `ScanResult` from the real engine over a hand-built observation: the render
 * path is then exercised end to end, which is the only way to catch a popup that disagrees with the
 * engine about the shape of its own data.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  MARKER_BAD,
  MARKER_OK,
  MARKER_UNMEASURED,
  MARKER_WARN,
  MAX_VISIBLE_REASONS,
  REPUTATION_LINE,
  activeTabOf,
  analyzingNote,
  findingMarker,
  findingRows,
  gradeText,
  moduleRows,
  renderChangesPanel,
  renderCookiePanel,
  renderExtensionsPanel,
  renderHeadersPanel,
  renderResponse,
  scoreText,
  scoreTone,
  setActiveTab,
  splitCookiePrefix,
  statusMessage,
  visibleReasons,
} from './view';
import { TrustEngine } from '../../core/trust-engine';
import { TRUST_SCORE_ANALYZERS } from '../../modules/trust-score/signals';
import type { PageObservation } from '../../shared/observation';
import type { CookieRecord, ExtensionAuditReport } from '../../core/types';
import type { ScoreResponse } from '../../shared/messages';
import type { FindingView, ScanResult } from '../../core/types';
import { classifyCookies } from '../../background/cookie-classifier';

const NOW = 1_700_000_000_000;
const URL = 'https://shop.example.com/checkout';

function observation(overrides: Partial<PageObservation> = {}): PageObservation {
  return {
    observationId: 'obs-1',
    tabId: 7,
    frameId: 0,
    url: URL,
    hostname: 'shop.example.com',
    origin: 'https://shop.example.com',
    startedAt: NOW - 900,
    updatedAt: NOW,
    mainDocument: {
      url: URL,
      statusCode: 200,
      statusLine: 'HTTP/1.1 200 OK',
      serverIp: '203.0.113.7',
      fromCache: false,
      headers: [
        { name: 'content-security-policy', value: "default-src 'self'; object-src 'none'; frame-ancestors 'none'" },
        { name: 'x-frame-options', value: 'DENY' },
        { name: 'referrer-policy', value: 'strict-origin-when-cross-origin' },
        { name: 'permissions-policy', value: 'geolocation=()' },
        { name: 'strict-transport-security', value: 'max-age=31536000; includeSubDomains' },
        { name: 'x-content-type-options', value: 'nosniff' },
        { name: 'cross-origin-opener-policy', value: 'same-origin' },
        { name: 'cross-origin-resource-policy', value: 'same-origin' },
      ],
      tls: null,
    },
    requests: [],
    requestsTruncated: false,
    resourceTimings: [
      {
        url: 'https://www.google-analytics.com/analytics.js',
        hostname: 'www.google-analytics.com',
        origin: 'https://www.google-analytics.com',
        initiatorType: 'script',
        transferSize: 2100,
        durationMs: 40,
        thirdParty: true,
      },
    ],
    resourcesCollected: true,
    dom: {
      url: URL,
      collectedAt: NOW - 100,
      documentHasCspMeta: false,
      forms: [],
      iframes: [],
      scripts: [],
      mixedContentUrls: [],
      speculativeUrls: [],
      dnsPrefetchHosts: [],
      pingAttributeCount: 0,
      inlineEventHandlerCount: 0,
      inlineScriptCount: 0,
      sensitiveFieldNames: [],
      passwordFieldCount: 0,
      isFramed: false,
      targetBlankWithoutNoopener: 0,
      notes: [],
    },
    warnings: [],
    ...overrides,
  };
}

function scan(overrides: Partial<PageObservation> = {}): ScanResult {
  return new TrustEngine({ analyzers: TRUST_SCORE_ANALYZERS, clock: () => NOW }).run(observation(overrides), {
    now: NOW,
  });
}

function ready(result: ScanResult): ScoreResponse {
  return { type: 'sentinel:score', status: 'ready', result, tabId: 7, tabUrl: URL };
}

/** The popup's markup, as `index.html` ships it. Kept in sync with that file by hand. */
function popupDocument(): Document {
  const doc = document.implementation.createHTMLDocument('popup');
  doc.body.innerHTML = `
    <main id="popup" data-status="loading" data-tone="unknown">
      <p id="score-value"></p>
      <p id="grade"></p>
      <h1 id="headline"></h1>
      <p id="url"></p>
      <div id="score-bar"><div id="score-bar-fill"></div></div>
      <p id="summary"></p>
      <p id="pending-note" hidden></p>
      <p id="coverage-note" hidden></p>
      <ul id="reasons"></ul>
      <button id="why-button" hidden></button>
      <section id="drilldown" hidden><ul id="findings"></ul><p id="reputation"></p></section>
      <nav id="tab-bar"></nav>
      <section id="panel-trust-score"></section>
      <section id="panel-cookies" hidden>
        <div id="cookie-summary">
          <p id="cookie-summary-total"></p>
          <p id="cookie-summary-breakdown"></p>
          <p id="cookie-summary-longest"></p>
        </div>
        <p id="cookie-disabled-note" hidden></p>
        <input type="checkbox" id="cookie-module-toggle" />
        <button id="cookie-bulk-delete" hidden></button>
        <div id="cookie-confirm" hidden></div>
        <ul id="cookie-list"></ul>
      </section>
      <section id="panel-changes" hidden>
        <p id="changes-summary"></p>
        <p id="changes-disabled-note" hidden></p>
        <input type="checkbox" id="changes-module-toggle" />
        <button id="changes-forget" hidden></button>
        <ul id="changes-list"></ul>
      </section>
      <section id="panel-headers" hidden>
        <p id="headers-summary"></p>
        <p id="headers-disabled-note" hidden></p>
        <input type="checkbox" id="headers-module-toggle" />
        <ul id="headers-list"></ul>
      </section>
      <section id="panel-extensions" hidden>
        <p id="extensions-summary"></p>
        <p id="extensions-disabled-note" hidden></p>
        <input type="checkbox" id="extensions-module-toggle" />
        <ul id="extensions-list"></ul>
      </section>
    </main>
  `;
  return doc;
}
describe('renderResponse', () => {
  it('shows the score, grade and summary the engine produced', () => {
    const doc = popupDocument();
    const result = scan();
    renderResponse(doc, ready(result));

    expect(doc.getElementById('score-value')?.textContent).toBe(String(result.score?.value));
    expect(doc.getElementById('grade')?.textContent).toBe(result.score?.grade);
    expect(doc.getElementById('headline')?.textContent).toBe(result.explanation.headline);
    expect(doc.getElementById('summary')?.textContent).toBe(result.explanation.summary);
    expect(doc.getElementById('reasons')?.children.length).toBeGreaterThan(0);
    expect(doc.getElementById('reasons')?.children.length).toBeLessThanOrEqual(MAX_VISIBLE_REASONS);
  });

  it('exposes the score as a labelled progress bar, not just a number', () => {
    const doc = popupDocument();
    const result = scan();
    renderResponse(doc, ready(result));

    const bar = doc.getElementById('score-bar');
    expect(bar?.getAttribute('role')).toBe('progressbar');
    expect(bar?.getAttribute('aria-valuemin')).toBe('0');
    expect(bar?.getAttribute('aria-valuemax')).toBe('100');
    expect(bar?.getAttribute('aria-valuenow')).toBe(String(result.score?.value));
    expect(bar?.getAttribute('aria-valuetext')).toContain(`${result.score?.value} out of 100`);
    expect(bar?.getAttribute('aria-label')).toBe('Trust score out of 100');
    expect(doc.getElementById('score-bar-fill')?.style.width).toBe(`${result.score?.value}%`);
  });

  it('lists every finding in the drill-down, with a marker and a plain-language effect', () => {
    const doc = popupDocument();
    const result = scan();
    renderResponse(doc, ready(result));

    const items = doc.querySelectorAll('#findings .finding');
    expect(items.length).toBe(result.findings.length);
    expect(doc.querySelectorAll('#findings .finding-marker').length).toBe(result.findings.length);
    // The one tracker on the page produces a deduction, and the effect is spelled out in points.
    const first = doc.querySelector('#findings .finding') as HTMLElement;
    expect(first.dataset.severity).toBeDefined();
    expect(first.textContent).toContain('points');
  });

  it('states that reputation was not analysed, in the drill-down', () => {
    const doc = popupDocument();
    renderResponse(doc, ready(scan()));

    expect(doc.getElementById('reputation')?.textContent).toBe(REPUTATION_LINE);
    expect(doc.getElementById('reputation')?.textContent).toContain('not yet analyzed');
  });

  it('renders the tab bar with all five modules selectable, none left unbuilt', () => {
    const doc = popupDocument();
    renderResponse(doc, ready(scan()));

    const tabs = doc.querySelectorAll('#tab-bar .tab');
    expect(tabs.length).toBe(5);
    // Phase 4: every module is active, so every tab is selectable and nothing says "not yet built".
    for (const tab of doc.querySelectorAll<HTMLButtonElement>('#tab-bar .tab')) {
      expect(tab.disabled).toBe(false);
      expect(tab.textContent).not.toContain('(not yet built)');
    }
    const trustTab = doc.getElementById('tab-trust-score') as HTMLButtonElement;
    expect(trustTab.getAttribute('aria-selected')).toBe('true');
    expect((doc.getElementById('tab-cookie-transparency') as HTMLButtonElement).disabled).toBe(false);
    // The two Phase 4 tabs use their short labels.
    expect((doc.getElementById('tab-header-dashboard') as HTMLButtonElement).textContent).toBe('Headers');
    expect((doc.getElementById('tab-extension-auditor') as HTMLButtonElement).textContent).toBe('Extensions');
  });

  it('shows a "still checking" note while the content script has not answered', () => {
    const doc = popupDocument();
    const pending = scan({ resourcesCollected: false, resourceTimings: [], dom: null });
    renderResponse(doc, ready(pending));

    const note = doc.getElementById('pending-note');
    expect(note?.hasAttribute('hidden')).toBe(false);
    expect(note?.textContent).toContain('Still checking');
    expect(note?.textContent).toContain('third-party tracking');
    expect(doc.getElementById('popup')?.dataset.status).toBe('ready');
  });

  it('hides the pending note once everything that can be measured has been', () => {
    const doc = popupDocument();
    renderResponse(doc, ready(scan()));

    expect(doc.getElementById('pending-note')?.hasAttribute('hidden')).toBe(true);
  });

  it('renders a status with no score as a plain explanation, and hides the drill-down button', () => {
    const doc = popupDocument();
    renderResponse(doc, {
      type: 'sentinel:score',
      status: 'unsupported',
      result: null,
      tabId: null,
      tabUrl: 'chrome://extensions',
    });

    expect(doc.getElementById('score-value')?.textContent).toBe('—');
    expect(doc.getElementById('grade')?.textContent).toBe('–');
    expect(doc.getElementById('summary')?.textContent).toContain('http and https');
    expect(doc.getElementById('why-button')?.hasAttribute('hidden')).toBe(true);
    expect(doc.getElementById('findings')?.children.length).toBe(0);
    expect(doc.getElementById('popup')?.dataset.status).toBe('unsupported');
  });

  it('renders a full score in well under the 200 ms budget', () => {
    const doc = popupDocument();
    const result = scan();
    const response = ready(result);

    // Warm the code paths once so the measurement is about rendering, not module loading.
    renderResponse(doc, response);

    const startedAt = performance.now();
    for (let index = 0; index < 5; index += 1) renderResponse(doc, response);
    const average = (performance.now() - startedAt) / 5;

    expect(average).toBeLessThan(200);
  });
});
describe('findingMarker', () => {
  const view = (overrides: Partial<FindingView> = {}): FindingView => ({
    signalId: 'x',
    categoryId: 'connection',
    categoryLabel: 'Connection security',
    title: 'x',
    severity: 'low',
    severityLabel: 'Minor',
    confidence: 'high',
    confidenceLabel: 'Directly observed',
    detail: 'x',
    evidence: [],
    remediation: null,
    measured: 100,
    measuredLabel: 'Everything checked out',
    impact: 0,
    maxImpact: 45,
    scoreEffect: 'No points deducted',
    ...overrides,
  });

  it('uses a tick, a warning and a cross for the three measured outcomes', () => {
    expect(findingMarker(view())).toBe(MARKER_OK);
    expect(findingMarker(view({ impact: 3, severity: 'low' }))).toBe(MARKER_WARN);
    expect(findingMarker(view({ impact: 20, severity: 'critical' }))).toBe(MARKER_BAD);
  });

  it('never shows a tick for a check that could not run', () => {
    expect(findingMarker(view({ measured: null, measuredLabel: 'Not measured' }))).toBe(MARKER_UNMEASURED);
  });
});

describe('scoreTone', () => {
  it('bands the score and treats "no score" as its own state', () => {
    expect(scoreTone(100)).toBe('good');
    expect(scoreTone(80)).toBe('good');
    expect(scoreTone(79)).toBe('fair');
    expect(scoreTone(60)).toBe('fair');
    expect(scoreTone(59)).toBe('poor');
    expect(scoreTone(0)).toBe('poor');
    expect(scoreTone(null)).toBe('unknown');
  });
});

describe('analyzingNote', () => {
  it('names only the checks that have not run yet', () => {
    const both = scan({ resourcesCollected: false, resourceTimings: [], dom: null });
    expect(analyzingNote(both)).toContain('third-party tracking');
    expect(analyzingNote(both)).toContain('forms and embedded content');

    const formsOnly = scan({ dom: null });
    expect(analyzingNote(formsOnly)).toContain('forms and embedded content');
    expect(analyzingNote(formsOnly)).not.toContain('third-party tracking');

    expect(analyzingNote(scan())).toBeNull();
  });
});

describe('visibleReasons', () => {
  it('prefers the highest-impact highlights and never exceeds the limit', () => {
    const result = scan();
    const reasons = visibleReasons(result);

    expect(reasons.length).toBeLessThanOrEqual(MAX_VISIBLE_REASONS);
    for (const reason of reasons) {
      expect(result.explanation.highlights).toContain(reason);
    }
  });

  it('falls back to the coverage caveat when there is nothing serious to lead with', () => {
    const partial = scan({ resourcesCollected: false, resourceTimings: [], dom: null });
    if (partial.explanation.highlights.length === 0) {
      expect(visibleReasons(partial)).toEqual([partial.explanation.coverageNote]);
    } else {
      expect(visibleReasons(partial).length).toBeGreaterThan(0);
    }
  });
});

describe('statusMessage', () => {
  it('prefers the background worker own note', () => {
    expect(
      statusMessage({ type: 'sentinel:score', status: 'none', result: null, tabId: null, tabUrl: null, note: 'Custom.' }),
    ).toBe('Custom.');
  });

  it('explains each status without a note', () => {
    const base = { type: 'sentinel:score' as const, result: null, tabId: null, tabUrl: null };
    expect(statusMessage({ ...base, status: 'unsupported' })).toContain('http and https');
    expect(statusMessage({ ...base, status: 'none' })).toContain('Reload the tab');
    expect(statusMessage({ ...base, status: 'pending' })).toContain('still observing');
    // `ready` without a result is a contradiction the popup still has to say something about.
    expect(statusMessage({ ...base, status: 'ready' })).toContain('no report for this tab');
  });
});

describe('moduleRows and text helpers', () => {
  it('marks only the active, enabled modules as on', () => {
    const rows = moduleRows(['trust-score']);
    expect(rows.find((row) => row.id === 'trust-score')).toMatchObject({ state: 'active', enabled: true });
    // Phase 4: every module is active, so the only difference left is the user's setting.
    expect(rows.find((row) => row.id === 'change-monitor')).toMatchObject({ state: 'active', enabled: false });
    expect(rows.find((row) => row.id === 'header-dashboard')).toMatchObject({ state: 'active', enabled: false });
    expect(rows.find((row) => row.id === 'extension-auditor')).toMatchObject({ state: 'active', enabled: false });
  });

  it('formats a score and a grade for a response with and without a result', () => {
    const result = scan();
    expect(scoreText(ready(result))).toBe(String(result.score?.value));
    expect(gradeText(ready(result))).toBe(result.score?.grade);

    const empty: ScoreResponse = { type: 'sentinel:score', status: 'pending', result: null, tabId: null, tabUrl: null };
    expect(scoreText(empty)).toBe('—');
    expect(gradeText(empty)).toBe('–');
  });

  it('describes findings in the order the model gave them, worst first', () => {
    const rows = findingRows(scan());
    const impacts = rows.map((row) => row.view.impact);
    const sorted = [...impacts].sort((a, b) => b - a);
    expect(impacts).toEqual(sorted);
  });
});

// ---------------------------------------------------------------------------
// Cookies panel (Phase 2, Task 2.6.5)
// ---------------------------------------------------------------------------

function cookieRecord(overrides: Partial<CookieRecord> = {}): CookieRecord {
  return {
    name: 'theme',
    domain: 'shop.example.com',
    hostOnly: true,
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'lax',
    session: true,
    storeId: '0',
    valueLength: 0,
    firstParty: true,
    ...overrides,
  };
}

function cookieReport(): NonNullable<ScanResult['cookies']> {
  // The view's lifetime labels read the real clock, so the fixture's expiries are relative to
  // now rather than to the file's fixed `NOW`.
  const now = Date.now();
  const { cookies, summary } = classifyCookies(
    [
      cookieRecord({ name: 'csrftoken' }),
      cookieRecord({ name: '_ga', domain: '.google-analytics.com', firstParty: false, session: false, expirationDate: (now + 730 * 86_400_000) / 1000 }),
      cookieRecord({ name: '_fbp', domain: '.facebook.com', firstParty: false, session: false, expirationDate: (now + 90 * 86_400_000) / 1000 }),
      cookieRecord({ name: 'mystery' }),
    ],
    now,
  );
  return { collected: true, cookies, summary };
}

describe('setActiveTab and activeTabOf', () => {
  it('switches panels and keeps the tab bar in sync', () => {
    const doc = popupDocument();
    renderResponse(doc, ready(scan()));

    expect(activeTabOf(doc)).toBe('trust-score');
    expect((doc.getElementById('tab-trust-score') as HTMLButtonElement).getAttribute('aria-selected')).toBe('true');

    setActiveTab(doc, 'cookie-transparency');

    expect((doc.getElementById('panel-trust-score') as HTMLElement).hidden).toBe(true);
    expect((doc.getElementById('panel-cookies') as HTMLElement).hidden).toBe(false);
    expect((doc.getElementById('panel-changes') as HTMLElement).hidden).toBe(true);
    expect(activeTabOf(doc)).toBe('cookie-transparency');
    expect((doc.getElementById('tab-cookie-transparency') as HTMLButtonElement).getAttribute('aria-selected')).toBe(
      'true',
    );

    setActiveTab(doc, 'change-monitor');

    expect((doc.getElementById('panel-cookies') as HTMLElement).hidden).toBe(true);
    expect((doc.getElementById('panel-changes') as HTMLElement).hidden).toBe(false);
    expect(activeTabOf(doc)).toBe('change-monitor');
    expect((doc.getElementById('tab-change-monitor') as HTMLButtonElement).getAttribute('aria-selected')).toBe('true');

    setActiveTab(doc, 'trust-score');

    expect((doc.getElementById('panel-trust-score') as HTMLElement).hidden).toBe(false);
    expect((doc.getElementById('panel-cookies') as HTMLElement).hidden).toBe(true);
    expect((doc.getElementById('panel-changes') as HTMLElement).hidden).toBe(true);
    expect(activeTabOf(doc)).toBe('trust-score');
  });
});

describe('renderCookiePanel', () => {
  it('shows the summary counts and the longest-lasting cookie', () => {
    const doc = popupDocument();
    renderCookiePanel(doc, { ...scan(), cookies: cookieReport() }, true, {});

    expect(doc.getElementById('cookie-summary-total')?.textContent).toBe('4 cookies');
    const breakdown = doc.getElementById('cookie-summary-breakdown')?.textContent ?? '';
    expect(breakdown).toContain('1 essential');
    expect(breakdown).toContain('1 advertising');
    expect(breakdown).toContain('1 analytics');
    expect(breakdown).toContain('1 unknown');
    expect(doc.getElementById('cookie-summary-longest')?.textContent).toContain('Longest-lasting: _ga');
    expect(doc.getElementById('cookie-summary-longest')?.textContent).toContain('730 days');
  });

  it('renders every cookie row with name, setter, badge, lifetime, flags and explanation', () => {
    const doc = popupDocument();
    renderCookiePanel(doc, { ...scan(), cookies: cookieReport() }, true, {});

    const rows = doc.querySelectorAll('[data-testid="cookie-row"]');
    expect(rows).toHaveLength(4);

    const fbp = Array.from(rows).find((row) => row.querySelector('.cookie-name')?.textContent === '_fbp');
    expect(fbp).toBeDefined();
    expect(fbp?.getAttribute('data-category')).toBe('advertising');
    expect(fbp?.querySelector('.cookie-setter')?.textContent).toContain('Meta');
    expect(fbp?.querySelector('.cookie-badge')?.textContent).toBe('advertising');
    expect(fbp?.querySelector('.cookie-meta')?.textContent).toContain('expires in 90 days');
    expect(fbp?.querySelector('.cookie-meta')?.textContent).toContain('Secure');
    expect(fbp?.querySelector('.cookie-explanation')?.textContent).toContain('Meta Pixel');
  });

  it('highlights __Host- and __Secure- prefixes', () => {
    expect(splitCookiePrefix('__Host-session')).toEqual({ prefix: '__Host-', rest: 'session' });
    expect(splitCookiePrefix('__Secure-id')).toEqual({ prefix: '__Secure-', rest: 'id' });
    expect(splitCookiePrefix('_ga')).toEqual({ prefix: null, rest: '_ga' });

    const doc = popupDocument();
    const { cookies, summary } = classifyCookies([cookieRecord({ name: '__Host-token' })], NOW);
    renderCookiePanel(doc, { ...scan(), cookies: { collected: true, cookies, summary } }, true, {});

    expect(doc.querySelector('.cookie-prefix')?.textContent).toBe('__Host-');
    expect(doc.querySelector('.cookie-name')?.textContent).toBe('__Host-token');
  });

  it('wires the per-cookie delete button to the handler with that cookie', () => {
    const doc = popupDocument();
    const onDelete = vi.fn();
    renderCookiePanel(doc, { ...scan(), cookies: cookieReport() }, true, { onDelete });

    const buttons = doc.querySelectorAll('[data-testid="cookie-delete"]');
    // csrftoken (essential — no), mystery (unknown): only _ga and _fbp are deletable.
    expect(buttons).toHaveLength(2);

    const fbpButton = Array.from(buttons).find(
      (button) =>
        (button.closest('[data-testid="cookie-row"]') as HTMLElement)?.getAttribute('data-category') ===
        'advertising',
    ) as HTMLButtonElement;
    fbpButton.click();

    expect(onDelete).toHaveBeenCalledTimes(1);
    expect(onDelete.mock.calls[0]?.[0]).toMatchObject({ name: '_fbp', domain: '.facebook.com', storeId: '0' });
  });

  it('shows the bulk-delete button only when tracking cookies are deletable, and passes them to the handler', () => {
    const doc = popupDocument();
    const onBulkDelete = vi.fn();
    renderCookiePanel(doc, { ...scan(), cookies: cookieReport() }, true, { onBulkDelete });

    const bulk = doc.getElementById('cookie-bulk-delete') as HTMLButtonElement;
    expect(bulk.hidden).toBe(false);
    expect(bulk.textContent).toContain('Delete all tracking cookies');
    expect(bulk.textContent).toContain('2');

    bulk.click();
    expect(onBulkDelete).toHaveBeenCalledTimes(1);
    expect(onBulkDelete.mock.calls[0]?.[0].map((cookie: { name: string }) => cookie.name).sort()).toEqual([
      '_fbp',
      '_ga',
    ]);
  });

  it('explains itself when the module is switched off (no rows, no stale data)', () => {
    const doc = popupDocument();
    renderCookiePanel(doc, { ...scan(), cookies: cookieReport() }, false, {});

    const note = doc.getElementById('cookie-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('switched off');
    expect(doc.querySelectorAll('[data-testid="cookie-row"]')).toHaveLength(0);
    expect((doc.getElementById('cookie-bulk-delete') as HTMLButtonElement).hidden).toBe(true);
  });

  it('says data has not been collected when the module is on but the observer has not run', () => {
    const doc = popupDocument();
    renderCookiePanel(doc, scan(), true, {});

    const note = doc.getElementById('cookie-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('has not been collected');
    expect(doc.querySelectorAll('[data-testid="cookie-row"]')).toHaveLength(0);
  });

  it('shows an empty page honestly: zero cookies is a real answer, not a gap', () => {
    const doc = popupDocument();
    const { cookies, summary } = classifyCookies([], NOW);
    renderCookiePanel(doc, { ...scan(), cookies: { collected: true, cookies, summary } }, true, {});

    expect(doc.getElementById('cookie-summary-total')?.textContent).toBe('0 cookies');
    expect(doc.getElementById('cookie-summary-breakdown')?.textContent).toContain('No cookies apply');
    expect(doc.querySelectorAll('[data-testid="cookie-row"]')).toHaveLength(0);
    expect((doc.getElementById('cookie-bulk-delete') as HTMLButtonElement).hidden).toBe(true);
  });
});




// ---------------------------------------------------------------------------
// Changes panel (Phase 3, D-008)
// ---------------------------------------------------------------------------

function history(): NonNullable<ScanResult['history']> {
  return { domain: 'example.com', scanCount: 3, lastScore: 82, averageScore: 88.5, lastSeenLabel: '2 hours ago' };
}

function changes(): NonNullable<ScanResult['changes']> {
  return [
    { kind: 'score', detail: 'Trust score moved from 92 to 82 (-10).', severity: 'medium', worsened: true },
    { kind: 'trackers', detail: '1 tracking request fewer than last time (4 \u2192 3).', severity: 'info', worsened: false },
  ];
}

describe('renderChangesPanel', () => {
  it('shows the history line and every change row, worst-marker first by severity', () => {
    const doc = popupDocument();
    renderChangesPanel(doc, { ...scan(), history: history(), changes: changes() }, true, {});

    const summary = doc.getElementById('changes-summary')?.textContent ?? '';
    expect(summary).toContain('Seen 3 times');
    expect(summary).toContain('last score 82');
    expect(summary).toContain('average 88.5');
    expect(summary).toContain('2 hours ago');
    expect(summary).toContain('example.com');

    const rows = doc.querySelectorAll('[data-testid="change-row"]');
    expect(rows).toHaveLength(2);
    const kinds = Array.from(rows).map((row) => row.getAttribute('data-change-kind'));
    expect(kinds).toEqual(['score', 'trackers']);
    expect(rows[0]?.querySelector('.finding-detail')?.textContent).toContain('92 to 82');
  });

  it('marks a worsened change differently from an improvement', () => {
    const doc = popupDocument();
    renderChangesPanel(doc, { ...scan(), history: history(), changes: changes() }, true, {});

    const rows = doc.querySelectorAll('[data-testid="change-row"]');
    expect(rows[0]?.getAttribute('data-severity')).toBe('medium');
    expect(rows[1]?.getAttribute('data-severity')).toBe('info');
  });

  it('wires the forget button to the handler', () => {
    const doc = popupDocument();
    const onForget = vi.fn();
    renderChangesPanel(doc, { ...scan(), history: history(), changes: changes() }, true, { onForget });

    const forget = doc.getElementById('changes-forget') as HTMLButtonElement;
    expect(forget.hidden).toBe(false);
    forget.click();
    expect(onForget).toHaveBeenCalledTimes(1);
  });

  it('explains itself when the module is switched off', () => {
    const doc = popupDocument();
    renderChangesPanel(doc, { ...scan(), history: history(), changes: changes() }, false, {});

    const note = doc.getElementById('changes-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('switched off');
    expect(doc.querySelectorAll('[data-testid="change-row"]')).toHaveLength(0);
    expect((doc.getElementById('changes-forget') as HTMLButtonElement).hidden).toBe(true);
  });

  it('says history has not been recorded yet when the module is on', () => {
    const doc = popupDocument();
    renderChangesPanel(doc, scan(), true, {});

    const note = doc.getElementById('changes-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('No history');
    expect(doc.querySelectorAll('[data-testid="change-row"]')).toHaveLength(0);
  });
});
describe('renderHeadersPanel', () => {
  it('shows every observed header, recommended ones first, with a summary line', () => {
    const doc = popupDocument();
    const result = scan();
    renderResponse(doc, ready(result));

    // The fixture observation carries eight security headers (COEP is missing), so 8 of 9.
    expect(doc.getElementById('headers-summary')?.textContent).toContain('8 of 9 recommended headers present');
    const rows = doc.querySelectorAll('[data-testid="header-row"]');
    expect(rows.length).toBe(result.headers?.rows.length ?? 0);
    const first = rows[0] as HTMLElement;
    expect(first.dataset.recommended).toBe('yes');
    expect(first.dataset.present).toBe('yes');
    expect(first.textContent).toContain('Content Security Policy');
    expect(first.textContent).toContain("default-src 'self'");
  });

  it('marks an absent recommended header honestly, with the recommended value', () => {
    const doc = popupDocument();
    renderResponse(doc, ready(scan()));

    const coep = Array.from(doc.querySelectorAll('[data-testid="header-row"]')).find(
      (row) => row.textContent?.includes('Cross-Origin-Embedder-Policy'),
    ) as HTMLElement | undefined;
    expect(coep).toBeDefined();
    expect(coep?.dataset.present).toBe('no');
    expect(coep?.textContent).toContain('absent');
    expect(coep?.textContent).toContain('Recommended:');
  });

  it('says so when headers were not collected (null is never a silent clean)', () => {
    const doc = popupDocument();
    renderHeadersPanel(doc, { ...scan(), headers: null }, true);

    const note = doc.getElementById('headers-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('has not been collected');
  });

  it('explains itself when the module is switched off', () => {
    const doc = popupDocument();
    renderHeadersPanel(doc, scan(), false);

    const note = doc.getElementById('headers-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('switched off');
    expect(doc.querySelectorAll('[data-testid="header-row"]')).toHaveLength(0);
  });
});

describe('renderExtensionsPanel', () => {
  const audit: ExtensionAuditReport = {
    auditedAt: NOW,
    extensions: [
      {
        id: 'snoopy',
        name: 'Snoopy',
        version: '2.0.0',
        enabled: true,
        hostAccess: 'broad',
        risk: 'high',
        findings: [
          {
            name: 'host-access',
            label: 'Broad host access',
            severity: 'high',
            why: 'Can read and change every site you visit, on every page.',
          },
          { name: 'history', label: 'Browsing history', severity: 'high', why: 'Can read your entire browsing history.' },
        ],
      },
      {
        id: 'benign',
        name: 'Benign',
        version: '1.0',
        enabled: false,
        hostAccess: 'none',
        risk: 'info',
        findings: [],
      },
    ],
  };

  it('renders every extension row worst first, with its findings and version', () => {
    const doc = popupDocument();
    renderExtensionsPanel(doc, { moduleEnabled: true, loading: false, report: audit, note: null });

    expect(doc.getElementById('extensions-summary')?.textContent).toContain('2 extensions reviewed');
    expect(doc.getElementById('extensions-summary')?.textContent).toContain('high');
    const rows = doc.querySelectorAll('[data-testid="extension-row"]');
    expect(rows).toHaveLength(2);
    expect((rows[0] as HTMLElement).dataset.risk).toBe('high');
    expect(rows[0]?.textContent).toContain('Snoopy');
    expect(rows[0]?.textContent).toContain('Broad host access');
    expect(rows[0]?.textContent).toContain('Browsing history');
    // The disabled, harmless extension is shown honestly as disabled and of no concern.
    expect((rows[1] as HTMLElement).dataset.enabled).toBe('no');
    expect(rows[1]?.textContent).toContain('disabled');
  });

  it('shows the empty browser honestly, and notes that Sentinel does not audit itself', () => {
    const doc = popupDocument();
    renderExtensionsPanel(doc, { moduleEnabled: true, loading: false, report: { auditedAt: NOW, extensions: [] }, note: null });
    expect(doc.getElementById('extensions-summary')?.textContent).toContain('No other extensions are installed');
  });

  it('shows a checking note while the background has not answered, and never blocks', () => {
    const doc = popupDocument();
    renderExtensionsPanel(doc, { moduleEnabled: true, loading: true, report: null, note: null });

    const note = doc.getElementById('extensions-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('Checking');
  });

  it('explains itself when the module is switched off', () => {
    const doc = popupDocument();
    renderExtensionsPanel(doc, { moduleEnabled: false, loading: false, report: null, note: null });

    const note = doc.getElementById('extensions-disabled-note') as HTMLElement;
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain('switched off');
    expect(doc.querySelectorAll('[data-testid="extension-row"]')).toHaveLength(0);
  });
});
