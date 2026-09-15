# Releasing Sentinel

This is the release checklist. It exists because Sentinel's central promise — *nothing ever
leaves the browser* — cannot be checked by one gate alone: the automated gates prove the
source and the built bundles, and only a human with the Network tab open can prove the
running product. Every step below either runs a gate that fails loudly or writes down what a
human must look at. If a step cannot be completed, the release does not ship.

## 1. Version policy

- **`MODEL_VERSION`** (`src/core/scoring-model.ts`) is bumped when weights, impacts or
  thresholds change meaningfully — never for UI or module work that cannot move a number.
  The version travels with every stored `ScanResult`, so history can be read in context
  (see `docs/SCORING.md`).
- **`package.json` `version`** is bumped for every user-visible release. Grade thresholds are
  deliberately *not* versioned (fixed so a grade the user learned keeps its meaning).
- Decisions are numbered (`D-00x`) in `docs/ARCHITECTURE.md`; a release note can cite them.

## 2. The automated gates (all must be green, in this order)

1. **`npm run verify`** — icons, `tsc --noEmit`, the unit suite, the Chrome build,
   `check:local-only` (network primitives + permission allow-list, scanned in source *and*
   every built bundle) and `check:size` (400 kB per built target, 200 kB per file).
   `verify` rebuilds **Chrome only**; see step 3 for the Firefox sequence.
2. **`npm run test:e2e`** — builds the extension and drives the real popup in headless
   Chromium against local fixtures: scores, grades, findings, cookies, changes, the Header
   Dashboard, the Extension Auditor and the options page.
3. **`npm run test:e2e -- --repeat-each=2`** — the stability pass. All tests must pass twice
   consecutively; a flake is a bug to fix, not a re-run to survive. (If a run fails with
   `EADDRINUSE` on 4173/4174/8788, a previous runner is still holding the fixture ports —
   `netstat -ano | findstr "4173 4174 8788"`, kill the holder, re-run.)

## 3. Building both targets

1. `npm run build:all` — produces `.output/chrome-mv3/` and `.output/firefox-mv3/`.
2. `npm run verify` again. The gates scan every built target, so this is the run that vouches
   for Firefox; without a fresh `build:firefox`, they would vouch for a stale one (D-012).
3. Inspect both `manifest.json` files by eye:
   - Chrome: `permissions` is exactly `["storage", "webRequest", "cookies", "management"]`,
     `host_permissions` is exactly `["<all_urls>"]`, the page CSP is
     `script-src 'self'; object-src 'none'`, `options_ui` points at `options.html`.
   - Firefox: same four permissions, the Gecko id `sentinel@caseymccallum.dev`,
     `data_collection_permissions: { required: ['none'] }`, `background.scripts`.
   Any difference needs a written decision in `docs/ARCHITECTURE.md` *before* the build.
4. `npm run zip` and `npm run zip:firefox` produce the store packages; check both contain
   the built files and no stray artifacts (`node_modules`, `.map` sources, tests).

## 4. Manual Chrome checks (no substitute exists)

Load the unpacked extension from `.output/chrome-mv3/` into a clean profile, then:

1. **The zero-outbound-requests check.** Open DevTools on the extension's service worker, the
   popup and one ordinary page each, with the Network tab open and "preserve log" on. Browse
   a handful of real sites (including one HTTPS page with third-party scripts). Confirm that
   **no request originates from Sentinel itself** — not from the worker, not from the popup,
   not from the options page, not from an icon fetch. This is the only check that can
   validate the running product (ARCHITECTURE.md §6, open item 3); the automated gate
   `check:local-only` inspects source and bundles, not behaviour.
2. **Exercise all five popup tabs** on a good page and a bad one: score + drill-down, Headers
   (values beside recommendations), Cookies (counts, per-cookie delete), Changes (history
   line after a reload), Extensions (the audit list, and that Sentinel itself is absent).
3. **Exercise the settings surfaces**: every options-page toggle, the popup's panel toggles,
   per-site forget, and the armed-confirm "Forget all site history" — then confirm in
   `chrome://extensions` → storage that profiles are gone.
4. **Reload-and-change**: visit a page, reload it, and the Changes tab reports the
   difference between visits.
5. **Disabled-module honesty**: switch a module off and confirm its tab says so and no
   finding claims it was checked (a switched-off module is a gap, never a bonus).

## 5. Manual Firefox checks (the Gecko smoke test)

Firefox is built and gate-checked but not e2e-tested (D-012), so a human drives it once:

1. `about:debugging` → "This Firefox" → "Load Temporary Add-on…" from `.output/firefox-mv3/`.
2. Repeat the Chrome smoke checks above as far as Firefox's UI allows (the popup, the options
   page, the module toggles, the forget actions).
3. Firefox-specific confirmations: the gecko permission prompts name only the four
   permissions; no console errors from the event-page background; the popup renders.
4. Record anything Firefox-specific that behaves differently — it either becomes a decision
   in `docs/ARCHITECTURE.md` or a fix before release.

## 6. Listing copy (both stores)

The permission justifications are written once, in two places that must agree: the comments
in `wxt.config.ts` and the allow-list in `scripts/check-local-only.mjs`. The store listing
should quote them, not paraphrase:

- `storage` — settings and per-tab session data; nothing is synced or transmitted.
- `webRequest` — reads response headers of requests the page already made; observational only.
- `cookies` — enumerates cookie *metadata* for the active tab; values are never read, kept or
  shown; deletion happens only on an explicit click (D-007).
- `management` — lists the other installed extensions and their permissions; read-only, the
  control calls are machine-forbidden (D-010).
- `<all_urls>` — the product scores *the page you are on*, whatever it is.

The listing must also carry the three plain claims, each mechanically enforced somewhere:
**local-first** (`check:local-only`), **observational, never interference** (no blocking
primitives in the gate), and **every number inspectable** (`docs/SCORING.md`).

## 7. Ship

1. Tag the release (`v<version>`) with a one-paragraph summary citing the decisions that
   shaped it.
2. Attach both store packages and the built manifests.
3. Note in the tag message which manual checks were done and by whom — a release where the
   human steps are undocumented is not a completed release.


