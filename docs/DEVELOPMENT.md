# Developing Sentinel

This is the working document: how to run the gates, what the invariants are, and the traps that have
already cost time once. `docs/ARCHITECTURE.md` explains *why* the system is shaped the way it is;
this file explains how to work on it without breaking it.

## 1. The determinism-of-behaviour contract

Sentinel's promise is that a page cannot make the extension behave differently and that the extension
cannot affect a page. Three rules turn that into something testable:

1. **The popup never makes a network call.** It asks the background worker for a score it already
   computed (`MSG_GET_SCORE`) and renders the answer. No fetch, no XHR, no remote font, no analytics,
   ever - and `check:local-only` fails the build if one appears in the source or the bundle.
2. **The popup never blocks on a content script.** It renders whatever the background has *now*, and
   redraws when a fuller score is broadcast. If tracker or form checks are still running it says so
   ("Still checking third-party tracking") instead of showing a number that does not exist yet.
3. **The popup renders in under 200 ms from click.** The markup paints before the score arrives, the
   answer comes from `storage.session` rather than from re-running the engine, and
   `src/entrypoints/popup/view.test.ts` renders a full result five times and asserts the average is
   under the budget, so a regression fails a unit test rather than a stopwatch in review.

The corollary for the collection layer: **the popup may never be the reason a measurement is
missing.** If the background has not seen a page yet, it starts looking and answers `pending` rather
than answering `none` (see `scoreResponseFor` in `src/entrypoints/background.ts`).

## 2. What "not measured" means (and what it must never mean)

`measured: null` is a first-class result: "Sentinel could not look". Three situations produce it, and
the UI is expected to keep them apart:

| Situation | Flag | What the user is told |
| --- | --- | --- |
| The page load was never observed (installed later, or a page it cannot see into) | `pageObserved()` false | "Sentinel did not observe this page load" |
| The response was seen but the content script has not answered | `resourcesCollected === false` | "Still checking third-party tracking and forms" |
| The browser refuses to expose a fact (TLS details, certificate) | analyser-level | "This browser does not expose negotiated TLS details" |

A check that *did* run and found nothing wrong measures **100**, not `null`. See D-006 in
`docs/ARCHITECTURE.md` for why that line is drawn where it is.

## 3. Scoring model invariants

Asserted by `validateScoringModel()` and by `src/core/scoring-model.test.ts`. Breaking one fails the
suite, which is the point: the numbers in front of a user are not allowed to drift silently.

1. **Category weights sum to exactly 1** (tolerance `1e-6`). Currently `connection 0.20`,
   `headers 0.20`, `privacy 0.25`, `hygiene 0.15`, `cookies 0.20` (Phase 2).
2. **Every category has exactly 100 points of budget**: the `maxImpact` values of its signals sum to
   100, so a category reaches 0 only when every signal in it measured its worst value.
3. **Signal ids are unique and reference a real category.**
4. **Grade boundaries are fixed** and evaluated at 0.01 resolution (`scoreToGrade`): A+ 97, A 93,
   A- 90, B+ 87, B 83, B- 80, C+ 77, C 73, C- 70, D+ 67, D 63, D- 60, F below.
5. **A hard cap is declared in one place** (`SCORE_CAPS`), names a signal that exists, has a ceiling
   in range and a reason a user can read. A cap reports itself only when it actually lowered the
   number, and only a `measured === 0` result can trigger one.

Re-normalisation: categories that could not be measured are dropped from the weighted average and the
remaining weights are re-normalised, which is why `TrustScore.coverage` exists. A page is never
penalised for a check the browser refused to expose.

## 4. Running the gates

| Command | What it does |
| --- | --- |
| `npm test` | Vitest: the engine, the model, every analyser, the observers and the popup's view layer |
| `npm run compile` | `tsc --noEmit` over `src/`, the configs and `scripts/` |
| `npm run verify` | The release gate, in order: icons, compile, test, build, local-only, size |
| `npm run test:e2e` | Builds, then runs the Playwright money test against local fixtures (section 6) |
| `npm run check:local-only` | Scans `src/` and every built file for network primitives, and checks the built manifest's permissions against an allow-list |
| `npm run check:size` | Measures the built extension against the 400 kB total / 200 kB per-file budget |
| `npm run icons:check` | Confirms the committed icons match what the generator produces |

`npm run verify` is the gate. If it is red, the extension does not ship.

A failing `check:local-only` is never silenced by adding an allow marker to a built file: that marker
exists for prose and tests that *mention* a primitive. The one real finding so far was Vite's
module-preload polyfill shipping a `fetch()` fallback into the popup chunk - dead code in an
extension - so `wxt.config.ts` switches the polyfill off rather than allow-listing it.

## 5. Adding a new signal

The order matters, because each step makes the next cheaper to check:

1. **Define the id and its budget** in `SIGNALS` (`src/core/scoring-model.ts`): `{ id, categoryId,
   title, rationale, remediation, maxImpact }`. Then rebalance the other signals in that category so
   they still sum to exactly 100. Add `severityFloor` only when a small deduction must still read as
   serious, and remember a floor does not apply to a zero-impact finding (D-005).
2. **Write the analyser** in `src/modules/trust-score/signals/`, or add to the existing one for that
   area. It must be pure: same context in, same assessments out, no I/O, no browser API. Report a
   0-100 quality value (100 = nothing wrong) and `measured: null` only when the fact could not be
   observed. Reuse the helpers in `signals/shared.ts` so the vocabulary stays identical.
3. **Test it** next to the analyser, with hand-built `PageObservation` fixtures (the tests already in
   that directory are the template). Cover the worst case, the clean case, and every path that
   produces `measured: null` - those are the paths that mislead if they are wrong.
4. **Wire it in** to `TRUST_SCORE_ANALYZERS` (`signals/index.ts`) if it is a new analyser.
5. **Check the explanation text**: `ExplanationBuilder` turns a finding's `detail` into the sentence a
   user reads, so the detail must be a complete sentence that stands alone - no bare counts, no
   jargon, no "see above".
6. **Update `docs/SCORING.md`** when weights, impact budgets, grades or severity rules change, and bump
   `MODEL_VERSION` when the change alters what a stored score means.
7. **Run `npm run verify`.** The model's invariants plus the analyser tests catch the arithmetic
   mistakes; `check:size` catches an accidentally bundled dependency.

## 6. The cookie safety contract (Phase 2)

The `cookies` permission is the most-scrutinised permission in Chrome Web Store reviews, and
D-007 in `docs/ARCHITECTURE.md` is its written justification. Three rules turn that document
into something the code can keep, and each rule is enforceable or testable:

1. **Never read `.value`.** `toCookieRecord` in `src/background/cookie-observer.ts` is the only
   place a raw browser cookie is touched; it destructures the value away and keeps
   `valueLength`. No downstream type (`CookieRecord`, `ClassifiedCookie`, `CookieReport`) even
   has a field to hold one, and `cookie-observer.test.ts` proves with a canary value that the
   secret appears nowhere in the output, including serialised forms.
2. **Never transmit values.** Cookies travel only inside `PageObservation` / `ScanResult` /
   `storage.session` / runtime messages — all in-process, all value-free by construction. If a
   code change needs the value for anything, it is by definition a change to D-007 and needs a
   written decision first.
3. **Set/remove only on explicit user action.** `browser.cookies.set()` is never called
   anywhere. `browser.cookies.remove()` is called in exactly one place: the background's
   `MSG_COOKIE_REMOVE` handler, reachable only from a popup button click. Deleting uses
   `removalUrlFor` (scheme from `Secure`, host from domain without the leading dot, the
   cookie's own path), which `cookie-classifier.test.ts` pins. Deletion is conservative: only
   cookies the knowledge base marks `safeToDelete: 'yes'`/`'will-log-out'` get a button, the
   bulk action needs an inline confirmation, and after any deletion the tab is re-enumerated
   and re-scored so the popup shows the truth.

Module-off is off: when the cookie module is disabled in settings
(`src/shared/settings.ts`), the background skips enumeration entirely
(`refreshCookiesForTab`), the observation reports `cookiesCollected: false`, the cookie
signals measure `null`, and the popup's Cookies tab explains itself instead of showing stale
data. No `chrome.cookies.getAll()` call occurs.

## 7. The Change Monitor recording rule (Phase 3)

D-008 in `docs/ARCHITECTURE.md` is the decision; this is the operational rule:

1. **A scan is recorded at most once per observation, and only when the content script has
   reported.** Partial scores (headers-only) would write phantom "headers disappeared" changes
   caused by Sentinel's own timing. `scoreTab` guards this with `state.report !== null` and a
   per-tab observation-id set (`recordedObservations` in the background) — the state's own flag
   is not authoritative, because the content script's two reports can race two state objects
   that both still look unrecorded. Scoring itself is serialised per tab (`enqueueScore`) so
   interleaved reports cannot publish out of order.
2. **Re-scores of a recorded observation re-attach the digest instead of re-recording.** The
   content script reports more than once per page (document_idle, then load); the second
   report's score must not overwrite the first one's digest, and must not inflate `scanCount`.
   This asymmetry is easy to break and the money test's cross-visit assertion catches it.
3. **Change findings are weightless.** They never enter the Trust Score or any category. If a
   change feels like it should move the score, the answer is a new scored signal, not a change
   finding.
4. **History is metadata only**: counters, host lists, hashes. Same safety contract as cookies
   — no paths, queries, titles, or values ever reach the profile.

## 8. The end-to-end harness (and its traps)

`npm run test:e2e` builds the extension, starts local fixture servers and drives the built extension
in headless Chromium. Everything below has bitten once.

- **Chromium must be the full build.** Playwright's plain `headless: true` launches
  `chrome-headless-shell`, which cannot load extensions. The harness passes `channel: 'chromium'` so
  the full browser runs in the new headless mode. Run `npx playwright install chromium` once.
- **The popup is opened as a tab.** Chrome renders a real popup *over* the page, so the active tab is
  the page. Opened as a tab, the popup itself becomes active, which would make the background describe
  the popup instead of the page. The harness therefore finds the page's tab id through the service
  worker and opens `popup.html?tabId=N`, which the popup supports explicitly (the message contract
  always allowed a `tabId`).
- **Fixed ports.** The fixture servers use 4173 (HTTPS pages), 4174 (HTTP) and 8788 (tracker stubs,
  which the committed fixture HTML hard-codes), so the suite runs in one worker.
  `--host-resolver-rules` maps every fixture and tracker hostname to 127.0.0.1, so nothing can reach
  the network even if a URL were wrong.
- **The self-signed certificate** lives in `tests/fixtures/certs`, and Chromium is launched with
  `--ignore-certificate-errors`.
- **"Settled" needs a definition.** `waitForSettled` waits for `data-status="ready"`, a numeric score,
  *and* no pending note. Waiting only for the note hides the race where the popup renders `pending`
  and nothing arrives to fix it.
- **First navigation races the service worker.** A cold worker may not have registered its
  `webRequest` listener before the very first fixture page responds, so the money test runs one
  throwaway warm-up navigation in `beforeAll` before any test asserts. It also re-runs reliably
  with `--repeat-each`, which is how the flake was caught.
- **Third-party cookies are seeded, not Set-Cookie'd.** Modern Chromium blocks third-party
  cookie *storage* by default, and the block is a browser policy that keeps moving. The money
  test therefore seeds the tracker cookies with `context.addCookies()` from
  `TRACKER_COOKIE_SEEDS` (scripts/e2e-server.mjs) before visiting the insecure fixture. What
  the test asserts is Sentinel's pipeline — tracker observer → cookie observer → classifier →
  popup — not Chromium's Set-Cookie policy. The stubs still send the headers for browsers that
  allow it.
- **A service worker cannot message itself.** `chrome.runtime.sendMessage` from the background does
  not reach the background's own listener, so a diagnostic has to go through an extension page.
- **`verify` rebuilds Chrome only.** `npm run build` targets `chrome-mv3`; the Firefox output
  (`.output/firefox-mv3/`, produced by `build:firefox`) is then checked as-is by
  `check:local-only` and `check:size`, which scan every built target. So the honest sequence
  after touching manifest-affecting code is `npm run build:all && npm run verify` — otherwise
  the gates vouch for a stale Firefox build (D-012). The Firefox target is not e2e-tested;
  the Playwright harness loads Chromium extensions only.
- **The e2e options test reads storage directly.** The options e2e asserts the stored
  `sentinel:settings` value (key hard-coded there, with a comment — importing
  `src/shared/settings.ts` into a Playwright spec would pull `wxt/browser` into Node).
- **The fixture servers start once per invocation, in the runner.** They moved out of
  `beforeAll` (`tests/e2e/global-setup.ts` + `global-teardown.ts`) because `--repeat-each`
  makes Playwright recycle workers: a recycled group's `beforeAll` raced the previous
  worker's teardown — whose Chromium keep-alive connections keep `server.close()` pending —
  and failed with EADDRINUSE on the fixed ports. Workers now share one set of servers.
  Relatedly, `launchExtension` identifies Sentinel's service worker by evaluating
  `chrome.runtime.getManifest().name` inside it, because a headless-Chromium *component*
  extension's worker URL can also end in `/background.js` and its stable id once 404'd the
  popup URL. If a run leaves ports bound, `netstat -ano | findstr "4173 4174 8788"` and kill
  the holder before re-running: back-to-back invocations in one shell can otherwise collide
  with a lingering runner process.
- **`responseHeaders` is opt-in, and Chrome does not warn when you forget.** `onHeadersReceived`
  only delivers `details.responseHeaders` if the listener passes `['responseHeaders']` as its
  third argument (`extraInfoSpec`). Phase 4's Header Dashboard e2e test caught this missing:
  the header list had been silently empty since Phase 1, every header signal reported
  `measured: null` ("could not look"), and the redistributed weights kept the scores plausible
  — so nothing failed until code actually read the raw header values. The trap generalises:
  an analyser that says "not measured" for a long time can hide a collection bug, which is
  why e2e tests should assert on raw observed data, not only on scores.
- **Cold-worker races apply to any new listener test.** The warm-up navigation in the money
  test's `beforeAll` exists because the first main-frame response can beat the service
  worker's listener registration; any new e2e test that asserts on observed traffic must run
  after that warm-up (or perform its own).

## 9. Tooling quirks worth knowing

- **The editor will not accept a huge write.** Anything much over ~6000 characters in one call is
  rejected or silently truncated; split a large file into a create plus a few appends, using a marker
  comment (`// __NAME_MORE__`) that the next call replaces.
- **`Get-Content` truncates the middle of long output.** Page through long files with explicit ranges
  instead of trusting the tail, and prefer `Select-String` with a pattern when you know the target.
- **Do not share a response between a write and a read of the same file.** Concurrent reads are fine,
  but a read that races a write sees the old text and sends you chasing a bug that does not exist.
- **Terminal output arrives with a shell banner and mangled emoji.** Match on plain ASCII fragments
  (`Tests`, `FAIL`, `AssertionError`) rather than on the pass/fail glyphs.
- **Emoji in source is transport-fragile.** The popup's marker glyphs are written as `\uXXXX` escapes
  in `src/entrypoints/popup/view.ts`, with each glyph named in a comment, so nothing can silently
  change what a user is told.
- **`tsconfig.json` deliberately does not include `tests/`.** There is no `@types/node`, and Playwright
  transpiles its own specs, so type-checking them inside `verify` would fail for reasons unrelated to
  the extension.