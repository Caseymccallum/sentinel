import { defineConfig } from 'wxt';

/**
 * Sentinel — local-first trust & privacy analysis.
 *
 * Non-negotiable constraints enforced here:
 *   - No API keys, no accounts, no telemetry: no `externally_connectable`, no remote
 *     hosts, and a CSP that forbids remote script/object loading.
 *   - Everything is analysed in the browser. `scripts/check-local-only.mjs` fails the
 *     build if any network primitive sneaks into the source or the bundle.
 */
const DESCRIPTION =
  'Local-first trust and privacy analysis. Scores websites, explains every finding, and never phones home.';

export default defineConfig({
  srcDir: 'src',
  manifestVersion: 3,

  vite: () => ({
    build: {
      modulePreload: {
        // Vite's module-preload helper ships a `fetch()` fallback for browsers without preload
        // support. Sentinel's chunks load from `chrome-extension://`, so that fallback is dead code
        // - and "dead code that can make a network request" is exactly what check-local-only exists
        // to catch, so the polyfill is switched off rather than allow-listed.
        polyfill: false,
      },
    },
  }),

  manifest: ({ browser }) => ({
    name: 'Sentinel',
    short_name: 'Sentinel',
    description: DESCRIPTION,
    author: 'Casey McCallum',
    homepage_url: 'https://github.com/caseymccallum/sentinel',
    // `storage`  — settings, history, session-scoped page observations.
    // `webRequest` — *observational only*: reads response headers + TLS state of
    //                requests the page already made. Sentinel never makes a request
    //                of its own, and never blocks, redirects or modifies traffic.
    // `cookies`  — D-007: required by chrome.cookies.getAll() to enumerate cookies for
    //                the active tab (and for the third-party origins the tracker observer
    //                detected). Only cookie *metadata* is kept — the value is discarded by
    //                the observer and never stored, logged or transmitted. Writes
    //                (chrome.cookies.remove()) happen only from an explicit popup action;
    //                chrome.cookies.set() is never called. Justification is mirrored in
    //                scripts/check-local-only.mjs's allow-list, which asserts the built
    //                manifest against it on every `npm run verify`.
    //
    // `management` — D-010: required by browser.management.getAll() to list the *other*
    //                installed extensions and the permissions they hold, for the Extension
    //                Auditor. Read-only by decision: Sentinel never calls setEnabled,
    //                uninstall or uninstallSelf (mechanically enforced by
    //                scripts/check-local-only.mjs), the audit is computed on demand and
    //                never persisted, and it never enters the page Trust Score.
    //
    // That is the entire permission list, and it is deliberately stable: the content script is
    // registered statically (declared in `src/entrypoints/content.ts` via `defineContentScript`,
    // which WXT writes into `content_scripts`), so it needs no `scripting` permission, and tab
    // metadata is readable through the `<all_urls>` host access, so it needs no `tabs` permission.
    permissions: ['storage', 'webRequest', 'cookies', 'management'],
    host_permissions: ['<all_urls>'],
    action: {
      default_title: 'Sentinel — trust report for this page',
    },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'",
    },
    ...(browser === 'firefox'
      ? {
          browser_specific_settings: {
            gecko: {
              id: 'sentinel@caseymccallum.dev',
              strict_min_version: '115.0',
              // Explicitly declare that we collect nothing (Firefox 140+ manifest key).
              data_collection_permissions: { required: ['none'] },
            },
          },
        }
      : {}),
  }),
});
