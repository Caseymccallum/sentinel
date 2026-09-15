/**
 * The content script: Sentinel's only view of the page itself.
 *
 * It walks the DOM once and reads the page's own resource-timing buffer, then sends one combined
 * report to the background worker. Two rules shape everything here:
 *
 *   1. **Observe only.** It never reads a field's value, never submits a form, never registers a
 *      listener that could intercept one, and never writes to the page. See the safety contract
 *      at the top of `src/content/form-observer.ts`.
 *   2. **Never block the page.** The walk is synchronous but bounded (every list is capped), the
 *      report is sent fire-and-forget, and a failure to send is swallowed: a page must not be
 *      slowed down or broken because Sentinel could not reach its own background worker.
 *
 * It answers `MSG_COLLECT` by collecting again. That matters because this script runs at
 * `document_idle`, which is *before* every subresource has finished loading: the background asks
 * for a second look when the tab reports `complete`, and the second report is the accurate one.
 */

import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import { collectResourceTimings, type PerformanceEntryLike } from '../content/tracker-observer';
import { isInCrossOriginFrame, observeDom } from '../content/dom-observer';
import { MSG_REPORT, isCollectRequest, type ContentReport } from '../shared/messages';
import { hostnameOf, schemeOf } from '../shared/urls';
import type { DomReport, ResourceTimingRecord } from '../shared/observation';

/** Schemes Sentinel has nothing to say about (`chrome:`, `about:`, `file:`). */
function isAnalysablePage(): boolean {
  const scheme = schemeOf(window.location.href);
  return scheme === 'http' || scheme === 'https';
}

/** Reads the Performance API, or reports that it was unavailable. */
function readResourceTimings(): { records: ResourceTimingRecord[]; collected: boolean } {
  try {
    const entries = performance.getEntriesByType('resource') as unknown as PerformanceEntryLike[];
    const { records } = collectResourceTimings(entries, hostnameOf(window.location.href));
    return { records, collected: true };
  } catch {
    // A browser that refuses the call is not a page with no resources, and the report says so.
    return { records: [], collected: false };
  }
}

/** Builds the report the background worker scores. Never throws: a failed walk is a `null` DOM. */
export function collectReport(now: number): ContentReport {
  const url = window.location.href;
  const hostname = hostnameOf(url);
  const { records, collected } = readResourceTimings();

  let dom: DomReport | null = null;
  try {
    dom = observeDom(document, {
      pageHostname: hostname,
      pageScheme: schemeOf(url),
      baseUrl: url,
      inCrossOriginFrame: isInCrossOriginFrame(window),
      isFramed: window.top !== window.self,
      insecureUrls: records.filter((record) => record.url.startsWith('http://')).map((record) => record.url),
      collectedAt: now,
    });
  } catch {
    // The DOM walk failed, so the report carries `null` and the analysers report those checks as
    // unmeasured rather than as clean.
    dom = null;
  }

  return {
    type: MSG_REPORT,
    url,
    dom,
    resourceTimings: records,
    resourcesCollected: collected,
  };
}

/** Sends a report, ignoring a missing or asleep background worker. */
function sendReport(report: ContentReport): void {
  try {
    // The promise rejects when no background listener answers; that is not the page's problem.
    void Promise.resolve(browser.runtime.sendMessage(report)).catch(() => undefined);
  } catch {
    // Synchronous failure (extension context invalidated). Nothing to do and nothing to report.
  }
}

export default defineContentScript({
  // Declared statically, so the script needs no `scripting` permission and no injection call.
  matches: ['<all_urls>'],
  runAt: 'document_idle',
  // Phase 1 analyses the top-level document. Sub-frames are reported as frames by the parent's
  // DOM walk, which is where `hygiene.embedded-content` reads them from.
  allFrames: false,

  main() {
    if (!isAnalysablePage()) return;

    browser.runtime.onMessage.addListener((message: unknown) => {
      if (!isCollectRequest(message)) return undefined;
      sendReport(collectReport(Date.now()));
      return undefined;
    });

    sendReport(collectReport(Date.now()));

    // A late look, once the page has settled: `document_idle` can fire before slow subresources
    // finish, and the resource timings are the tracker signal's only input.
    if (document.readyState !== 'complete') {
      window.addEventListener(
        'load',
        () => sendReport(collectReport(Date.now())),
        { once: true },
      );
    }
  },
});