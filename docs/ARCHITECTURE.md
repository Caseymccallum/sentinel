# Sentinel architecture

Sentinel is a local-first MV3 extension that scores the page you are on and explains every
point it deducts. This document records how the pieces fit together and, more importantly,
*why* certain obvious-looking APIs were rejected. Decisions are numbered (`D-00x`) so code
comments and reviews can cite them.

## 1. Non-negotiables

1. **No network calls, ever.** Nothing in `src/` may use `fetch`, `XMLHttpRequest`,
   `WebSocket`, `EventSource`, `sendBeacon`, `navigator.send()`, `importScripts`, remote
   `import()`, `<script src>` injection or `update_url`. `scripts/check-local-only.mjs`
   scans both the source tree and every built bundle and fails the build on a match.
2. **Observation, never interference.** Sentinel reads what the browser already did. It
   never blocks, redirects, rewrites or delays a request or a response.
3. **Every number is inspectable.** Scoring is data plus arithmetic
   (`src/core/scoring-model.ts`), not conditionals buried inside analysers. A measurement
   the browser will not expose is reported as "not measured" and removes no points.
4. **Least privilege.** Permissions are allow-listed in the gate; adding one requires an
   entry in that allow-list *with a written reason*.

## 2. Runtime shape

```
background service worker            content script(s)
  webRequest.onHeadersReceived  ─┐     Performance API + DOM reads
  webRequest.onCompleted        ─┤            │
                                 ▼            ▼
                             PageObservation (src/shared/observation.ts)
                                          │
                              buildAnalysisContext (src/shared/analysis.ts)
                                          │
                             SignalAnalyzer[] (src/modules/trust-score/signals)
                                          │
                        ScoringModel ──► TrustScore (0-100 + letter grade)
                                          │
                 ExplanationBuilder ──► Explanation (headline, reasons, caveats)
                                          │
                             ScanResult ──► popup / session storage / domain profiles
```

The engine (`src/core/trust-engine.ts`) is pure apart from an injected clock. Collection is
the only impure part, which is why the whole scoring pipeline is unit-testable against a
hand-built `PageObservation`.

## 2.1 The collection layer, in order

Nothing above the collection layer knows where an observation came from, so the sequence is worth
pinning down. `src/entrypoints/background.ts` owns it, and `src/background/tab-state.ts` holds the pure
rules (no browser APIs, no timers, no storage), which is what makes the ordering testable.

1. **`webRequest.onHeadersReceived`, filtered to `main_frame`.** Response headers, status line, IP and
   cache state are folded into a per-tab record (`applyHeaderObservation`). The headers the brief names
   are guaranteed a place at the front of the list, and *every other* header is kept too: dropping them
   would turn "this header is absent" into a finding when the truth was "Sentinel did not keep it".
   Nothing here can block - `webRequestBlocking` is not requested and is on the gate's forbidden list.
2. **`tabs.onUpdated` with `status === 'complete'`.** The tab is scored *immediately* from what is
   already known - connection and response headers - and that score is written to
   `browser.storage.session` and broadcast. The content script is then asked for a page report
   (`MSG_COLLECT`), so the page gets a second, fuller score instead of the user waiting or reloading.
3. **The cookie observer** (`src/background/cookie-observer.ts`, Phase 2 / D-007) enumerates
   cookie *metadata* twice per page: once for the page's own URL at `tabs.onUpdated(complete)`,
   and again — after the content script's tracker report names the third-party origins the page
   contacted — for each of those origins via `getAll({ domain })`. The value is dropped in the
   first step; see the safety contract in `docs/DEVELOPMENT.md` section 6. When the cookie
   module is off, neither call happens at all.
4. **The content script** (`src/entrypoints/content.ts`) walks the DOM once and reads
   `performance.getEntriesByType('resource')`, then sends one combined `ContentReport`. It reports
   again on `load`, because `document_idle` can fire before slow subresources finish and the resource
   timings are the tracker signal's only input.
5. **`runtime.onMessage`** folds a report into the tab's state and re-scores (after the
   third-party cookie pass), then broadcasts
   `MSG_SCORE_UPDATED` so an open popup redraws itself. A report for a URL the tab has already left is
   ignored (`applyContentReport`): scoring the previous page's DOM against the new page's URL would
   attribute findings to the wrong site, which is worse than reporting nothing.
6. **`runtime.onMessage` for `MSG_GET_SCORE`** answers the popup from storage, never by re-running the
   engine, and answers `pending` - and starts collecting - rather than `none` when the popup opened
   before the page was observed. A popup must never be told "not seen yet" about a page Sentinel is
   about to score.
7. **`tabs.onRemoved`** deletes the tab's session record, so closing a tab leaves nothing behind.

Scores live in `browser.storage.session`, keyed by tab id (`sentinel:tab:<id>`), and are gone when the
browser closes. Persisted history is a different thing and belongs to the Change Monitor's domain
profiles, which never store a page URL with a query string.

`analysis.ts` folds the content script's resource timings into the same request list the analysers read
(`mergeRequests` in `src/shared/collect.ts`), once, so no analyser has to know which collector produced
a record and no caller can double-count.
## 3. Decision record

### D-001 - Tracker detection uses the Performance API in a content script, not declarativeNetRequest (accepted)

**Context.** Phase 1 needs to answer "which third-party hosts did this page contact, and
which of them are known analytics/advertising/social trackers?" The original brief proposed
`declarativeNetRequest` (DNR).

**Decision.** Trackers are detected from the page's own resource timings, collected by a
content script, and classified against a local JSON knowledge base. DNR is not used and
`declarativeNetRequest` remains on the gate's forbidden list.

**Rationale.**

- *Wrong shape of API.* DNR answers "should this request be blocked, allowed or modified?".
  Sentinel needs "what did this page load?". Reporting from a ruleset means shipping a
  filtering engine to answer an observation question.
- *Hidden cost: `declarativeNetRequestFeedback`.* DNR cannot report which rule matched
  without that additional debugging permission (the `getMatchedRules` surface), which also
  exposes user activity to the extension. Two extra permissions for data the page already
  hands us for free.
- *Accuracy on the question that matters.* `performance.getEntriesByType('resource')`
  reports the resources the page **actually fetched**, in the page's own context, including
  origins reached from inline scripts, dynamically inserted tags and iframes. That is the
  set of hosts that learned the user's IP address and `Referer`.
- *No new permission.* A content script runs with the host access the extension already
  declares; reading `performance` needs nothing.
- *Explainability.* A bundled mapping of hostname -> `{name, category, description,
  provenance}` can be read, audited and versioned by anyone. A DNR ruleset is a binary-ish
  artefact whose matching semantics are opaque to the user.
- *Consistency with the promise.* "We never touch your traffic" is easier to verify when no
  request-filtering API appears in the manifest at all - the gate enforces exactly that.

The knowledge base itself lives at `src/shared/trackers.ts`, not the `src/data/trackers.json`
sketched in the brief: it is a typed module (`TrackerCategory`, `TrackerMatch`), so a typo in a
category is a compile error, a service worker needs no runtime JSON parse, and the diff is
readable in review. Matching happens on DNS-label boundaries (`sub.doubleclick.net` matches
`doubleclick.net`; `notdoubleclick.net` does not) and each category carries a confidence level,
with optimisation and support tags reported as `medium` rather than `high`. Provenance: the list
is hand-curated from each vendor's own product documentation; there is no remote fetch, no
crowdsourcing and no user data involved in keeping it accurate.

**Corroboration, not a second source of truth.** The background's `webRequest` request
records (`PageObservation.requests`, folded by `summarizeRequests`) already carry the
resource `kind`, initiator and cache status of every request the page made. Those records
enrich the tracker evidence (how a tracker was reached, and whether it was served from
cache); they do not replace the content script's own view, and neither path leaves the
device.

### D-002 - `webRequest` is observational only (accepted)

**Decision.** Sentinel declares exactly one traffic-related permission, `webRequest`, and
uses it in read-only mode:

| Listener | Used for | Never used for |
| --- | --- | --- |
| `onHeadersReceived` (main frame) | response headers, `Strict-Transport-Security`, status line | modifying, reordering or suppressing headers |
| `onCompleted` / `onBeforeRequest` | request records: host, kind, initiator, cache status | blocking, redirecting, cancelling |
| `securityInfo` (where the browser exposes it) | negotiated TLS protocol and certificate facts | pinning, proxying, downgrading |

`webRequestBlocking` is not requested and is on the gate's forbidden list, and no listener
ever calls a blocking-capable method. When the browser refuses to expose TLS details,
`connection.tls-strength` and `connection.certificate` report `measured: null` - the class
of "the extension could not look" - rather than guessing.

### D-003 - Signals are graded per area, not split into `_PRESENT` / `_ABSENT` ids (accepted)

**Context.** The brief sketched signal ids such as `CONNECTION_HSTS_PRESENT`,
`HEADERS_XFO_ABSENT`, `HEADERS_CSP_WEAK`.

**Decision.** One graded signal per check area, each with a 0-100 quality value, one
`maxImpact` budget and one rationale in `SIGNALS`. The brief's intent is preserved; only the
encoding changes.

**Rationale.**

- "Present but weak" needs a number, not a boolean: `HSTS: max-age=0` actively *disables*
  HSTS, and a CSP containing `unsafe-inline` is barely better than none. Presence/absence
  ids force a second invented scale for the weak case.
- One id means one impact budget. Two ids would need their `maxImpact` kept in sync or a
  page could be double-charged for the same weakness.
- `measured: null` (not observable) stays distinct from `measured: 0` (observed and bad),
  which the paired-id encoding cannot express.
- The popup renders one reason per signal; paired ids would produce two lines ("HSTS
  present" / "HSTS absent") of which exactly one is ever true.

**Mapping from the brief to the model** (`SIGNALS` in `src/core/scoring-model.ts`):

| Brief sketch | Implemented signal | Phase |
| --- | --- | --- |
| `CONNECTION_HTTPS` / `CONNECTION_HTTP` | `connection.https` | 0 (done) |
| `CONNECTION_CERT_ERROR` | `connection.tls-strength` (`state: 'broken'`), `connection.certificate` | 0 (done) |
| `CONNECTION_HSTS_PRESENT` / `_ABSENT` | `connection.hsts` | 0 (done) |
| `HEADERS_CSP_PRESENT` / `_ABSENT` / `_WEAK` | `headers.csp` | 0 (done) |
| `HEADERS_XFO_PRESENT` / `_ABSENT` | `headers.frame-ancestors` (CSP `frame-ancestors` and `X-Frame-Options`, stronger wins) | 0 (done) |
| `HEADERS_REFERRER_POLICY_PRESENT` / `_ABSENT` | `headers.referrer-policy` | 0 (done) |
| `HEADERS_PERMISSIONS_POLICY_PRESENT` / `_ABSENT` | `headers.permissions-policy` | 0 (done) |
| (not in brief) | `headers.content-type-protection`, `headers.information-leakage`, `headers.cross-origin-policy` | 0 (done) |
| `TRACKERS_NONE` / `_DETECTED` / `_ADVERTISING_HEAVY` | `privacy.trackers` (counts, vendor names and categories carried in the detail and evidence), `privacy.third-party-surface` | 1 (done) |
| `FORM_PASSWORD_*`, `FORM_CROSS_ORIGIN_ACTION` | `hygiene.password-forms`, `hygiene.form-targets` | 1 (done) |
| (not in brief) | `privacy.referrer-leakage`, `privacy.background-beacons`, `hygiene.mixed-content`, `hygiene.embedded-content` | 1 (done) |

Because the privacy and hygiene signals were already declared in the model, Phase 1 added analysers
only - no new ids - and the weight-table change was made in the same pass, recorded in
`docs/SCORING.md` section 2. The eight signals now live in `privacy.ts` and `hygiene.ts`; the tracker
knowledge base that `privacy.trackers` reads is `src/shared/trackers.ts` (159 domains, matched on
DNS-label boundaries).

### D-004 - No reputation service in v1 (accepted)

Sentinel has no network access by design, so there is no reputation look-up to perform. The
popup must therefore show **"Reputation: not yet analyzed"** in the drill-down view, and the
score must not contain a reputation term. A later opt-in phase may exist; if it does, it will
be an explicit, per-request, user-triggered action and the only network call in the product -
which means it cannot live in `src/` as that tree is scanned today.

### D-005 - A severity floor only applies once a finding removes points (accepted)

`severityFor()` derives a severity from the share of a signal's impact budget that the
measurement used, then applies that signal's `severityFloor` and `severityCap`. A finding that
removes **zero** points - a perfect measurement, or one the browser would not let Sentinel take -
is always reported as `info`, however high its floor is.

Without that rule a page Sentinel could measure perfectly would be explained as
`100/100 (A+) - 1 finding rated serious or critical`, because `hygiene.password-forms` carries a
`high` floor and the explanation's summary counts by severity rather than by impact. Floors still
do their job the moment anything is actually deducted (a small tracker exposure still reads as at
least `low`). A cap is unaffected: `headers.cross-origin-policy` is `low` at most, even when it
loses its whole budget. `src/core/scoring-model.test.ts` locks in both halves of the rule.

### D-006 - "Observed and fine" is 100; `null` is reserved for "could not look" (accepted)

**Context.** Phase 1 added signals fed by the content script, where the absence of a thing (no
trackers, no password form, no frames) is itself a measurement. The obvious shortcut is to report
`measured: null` whenever there was nothing to find, on the grounds that there was nothing to check.

**Decision.** A signal that ran and found nothing wrong measures **100**. `measured: null` is used in
exactly two situations: the page load was never observed at all (`pageObserved()`), or the collector
that would have answered has not run (`resourcesCollected === false` for resource-derived signals, a
`null` DOM report for DOM-derived ones). The third case - the browser refusing to expose a fact, such
as TLS details - is also `null`, reported by the analyser that needed it.

**Rationale.**

- The two statements are not interchangeable: "no tracking host was contacted" is a *finding about the
  page*, while "nobody looked" is a *gap in Sentinel's view*. Collapsing them either credits every
  unexamined page with perfect privacy, or tells a genuinely clean page that its privacy is unknown.
- `null` removes no points and re-normalises the weights, so using it for a clean page would silently
  shrink the model's coverage on exactly the pages that deserve full coverage.
- The popup has to say something different in each case, and it can only do that if the engine keeps
  them apart: "Still checking third-party tracking" versus "Every subresource this page loaded came
  over HTTPS".

**Consequences.** `hygiene.mixed-content` reports `null` on an HTTP page rather than a deduction,
because mixed content is not a distinguishable fact there and the connection signals own that
finding; `hygiene.form-targets` ignores forms that contain a password field, because
`hygiene.password-forms` already charges that fact and D-003 exists to prevent double-charging. Both
are asserted in `src/modules/trust-score/signals/hygiene.test.ts`.

### D-007 - The `cookies` permission is requested for the Cookie Transparency module (accepted)

**Context.** Phase 2's Cookie Transparency module needs `chrome.cookies.getAll()` to enumerate
the cookies applicable to the active tab and to the third-party origins the tracker observer
detected. That API is gated behind the `cookies` permission, which was on the gate's forbidden
list through Phase 1. It is the single most-scrutinised permission in Chrome Web Store reviews,
so asking for it is a decision that has to be made in writing, before any code is written.

**Decision.** Sentinel requests `cookies`, justified as follows (this text is mirrored in the
`check:local-only` allow-list, so removing either half fails a gate):

> `cookies` — Required by `chrome.cookies.getAll()` to enumerate cookies for the active tab.
> Justified because: (1) the Cookie Transparency module's entire function is reading cookies;
> (2) no cookie value leaves the browser; (3) `chrome.cookies.set()` and
> `chrome.cookies.remove()` are only called in response to an explicit user action in the
> popup, never automatically.

**Rationale.**

- *No alternative exists.* Everything else Sentinel knows about cookies — `Set-Cookie` headers
  on observed responses, `document.cookie` in the content script — is partial: `webRequest` sees
  neither the cookie store's `HttpOnly` entries nor their expiry metadata, and `document.cookie`
  cannot see `HttpOnly` cookies at all. Reading cookie *metadata* accurately requires the API.
- *The value is never read.* The observer (`src/background/cookie-observer.ts`) immediately
  discards `cookie.value` and keeps only `valueLength`, so no code path — storage, messages,
  the popup, a future bug — can transmit what was never kept. A unit test pins this by feeding
  a canary value through a mock API and asserting it appears nowhere in the output.
- *Writes are user-gated by construction.* There is exactly one call site for
  `chrome.cookies.remove()` (the background's `MSG_COOKIE_REMOVE` handler), reachable only from
  a popup button the user clicks; `chrome.cookies.set()` is never called anywhere.
- *Scope is bounded by what the page did.* The module enumerates cookies for the page's own URL
  plus the third-party origins the tracker observer already saw the page contact — not the whole
  cookie store.

**Consequences.** The permission posture (section 4) moves `cookies` from forbidden to
allow-listed, and the gate's allow-list is the enforcement point: the built manifest is checked
against it on every `npm run verify`. The user-facing explanation ships in `README.md` and the
store listing: *"Sentinel reads cookies to explain what they are and how long they last. It
never sends cookie data anywhere. It never modifies cookies without your explicit action."*
The cookie module can be switched off in settings; when it is off, no `chrome.cookies.getAll()`
call is made at all.

### D-008 - The Change Monitor is informational and weightless (accepted)

**Context.** The per-domain profile store (`src/core/domain-profile.ts`, built in Phase 1) and
its `diffScans` change detector have existed since the start, but nothing recorded scans into
profiles and nothing showed the changes. Wiring them up forces a product decision that is
bigger than it looks: *what is a change finding, and what may it do?*

**Decision.**

1. **Change findings never move the Trust Score.** The score measures *the page in front of
   you*; the Change Monitor measures *the difference between your visits*. Mixing them would
   let a site farm points by merely being stable, and would make the number depend on
   Sentinel's own storage history rather than on the page — a different kind of fact wearing
   the same uniform. Change findings carry severity (for colour and ordering) but live in the
   Changes panel, outside the 0–100 composite and its categories. `docs/SCORING.md` records
   the same line from the model side: the `cookies` category is the newest weighted category,
   and there is no `changes` category.
2. **Recording happens at most once per page observation, and only for fully observed scans.**
   The background publishes a score as soon as response headers are known (D-006), but that
   partial score would pollute history with phantom "headers disappeared" and "trackers
   appeared" changes caused by Sentinel's own timing rather than by the site. So
   `scoreTab` records a scan into the profile only once the content script has reported, and a
   `profileRecorded` flag on the tab state guarantees one record per `observationId` no matter
   how many times the page is re-scored (rescans, cookie deletions).
3. **History stays local, bounded and metadata-only.** Profiles persist through
   `src/storage/profile-adapter.ts` into `browser.storage.local`, keyed by registrable domain,
   capped at `MAX_PROFILES` (500) with least-recently-seen pruning, and hold only counters,
   host lists and hashes — never paths, queries, page titles or cookie values (D-007's safety
   contract applies downstream of the observer unchanged). Clearing a site's profile is a
   user action, like cookie deletion.
4. **A "change" is a difference between consecutive recorded scans.** The detector compares
   the previous `ScanSummary` with the next one and suppresses everything when the
   security-relevant signature is identical, so a site that re-renders its HTML every minute
   does not produce noise.

**Consequences.** The popup grows a third tab (Changes) fed by `ScanResult.changes`; the
change-monitor module graduates from `planned` to `active` and is toggleable like the others —
off means nothing is recorded and the panel says so. The money test asserts a cross-visit
change on one registrable domain. `check:local-only` needs nothing new: `browser.storage.local`
is in-process storage, and the module makes no requests and blocks nothing.

### D-009 - The Header Dashboard is informational and weightless (accepted)

**Context.** Every response header the site sends is already collected (`mainDocument.headers`
keeps all of them, not just the scored ones, precisely so "absent" and "not kept" stay distinct).
Phase 4's Header Dashboard has to decide what it is: a second scorer of headers, or a display
for the headers the trust-score module already grades.

**Decision.**

1. **The dashboard never scores anything.** The `headers` category in the trust-score module
   already grades the security headers with 100 points of impact budget; duplicating that in
   another module would let one missing header cost points twice. The dashboard produces
   display data only (`ScanResult.headers`, built by `buildHeaderDashboard`), and nothing in
   it can enter the composite or any category.
2. **"Absent" is only reported when the response was actually observed.** `available: false`
   (no main document) renders as "Sentinel did not observe this page load", never as nine
   accusations a site may not deserve — D-006 applied to prose instead of points.
3. **The knowledge base is shared with the collection layer.** The recommended headers and
   their guidance mirror `SECURITY_HEADERS` in `src/background/tab-state.ts`, so the
   dashboard and the header analyser can never disagree about what counts as a security
   header.

**Consequences.** The header-dashboard module graduates from `planned` to `active`; the popup
grows a Headers tab showing the raw values next to recommended practice. Whether the module is
on or off changes nothing about any score, so `MODEL_VERSION` is untouched.

### D-010 - The Extension Auditor lists other extensions and never controls them (accepted)

**Context.** The auditor's whole job is to read what the browser already knows about the other
installed extensions — `browser.management.getAll()` — and that API lives behind the
`management` permission, which the gate had on its forbidden list ("other extensions are
listed, never controlled").

**Decision.**

1. **Read-only, mechanically enforced.** The permission is granted for `getAll()` only.
   `management.setEnabled`, `management.uninstall` and `management.uninstallSelf` are scanned
   for by `check:local-only` the same way network primitives are: one occurrence fails the
   build. The gate's forbidden-list entry for `management` moves to the allow-list with the
   written justification; the forbidden list keeps its meaning (control), not its string.
2. **Browser-scoped, not page-scoped.** The audit is not part of any page scan, never enters
   the Trust Score, and is not persisted: the popup requests it (`MSG_GET_EXTENSION_AUDIT`)
   when the user first opens the Extensions tab, and the answer is held in memory for the
   popup's lifetime. The auditor also excludes Sentinel itself from its own report.
3. **Severity grades capability.** A hand-written knowledge base translates each permission
   string into what it would let an extension do, and a missing entry is reported honestly as
   "not in Sentinel's knowledge base" rather than as safe. Broad host patterns (`<all_urls>`,
   `*://*/*`) are their own high-severity finding.

**Consequences.** The extension-auditor module graduates from `planned` to `active` and the
popup grows an Extensions tab. The e2e suite loads a deliberately over-permissioned fixture
extension and asserts it is audited correctly. `management` appears in the built manifest; the
gate asserts it stays justified on every `npm run verify`.

### D-011 - One settings store, two surfaces (accepted)

**Context.** With five real modules, the popup's per-panel checkboxes can no longer be the
only place settings are edited: a user who wants to switch three modules off at once should
not have to open five page reports to do it. But two editing surfaces invite two different
ideas of what "the enabled list" is.

**Decision.**

1. **There is exactly one settings store** (`sentinel:settings` in `browser.storage.local`,
   via `loadSettings`/`saveSettings`), and exactly one pure toggle (`withModuleEnabled`). The
   options page and the popup's panel switches are two views onto the same decision; neither
   is authoritative, and neither builds the enabled list from module metadata on its own.
2. **The options page explains; the popup acts in context.** The options page shows every
   module with its one-sentence description from the module registry and a toggle each; the
   popup keeps its per-panel switches because that is where a user is when they decide.
   A switched-off module is a gap in the report, never a bonus — the same rule everywhere.
3. **"Forget all site history" lives on the options page, confirmed.** Clearing data is a
   user action (D-008), and a bulk clear is the most destructive one Sentinel has, so it is
   armed with a first click and only runs on a second, separate confirmation button. It goes
   through `MSG_FORGET_ALL_PROFILES` to the background, which owns the profile store; module
   settings are untouched (preferences are not history). Live tab states are unmarked so the
   next scan records those sites fresh.
4. **No new permission.** The options page reads settings and sends one message; both are
   already-covered surfaces.

**Consequences.** `src/entrypoints/options/` ships (WXT writes `options_ui` into the
manifest), and the popup's footer gains a "Settings" button (`runtime.openOptionsPage()`).
The e2e suite drives the options page as a page: toggles a module and asserts the stored
settings, then arms-confirms the forget and asserts the profile keys are gone.

### D-012 - Firefox is a build target, not an e2e target (accepted)

**Context.** `build:firefox` has existed since Phase 1, but nothing asserted that the Firefox
output stays healthy — and "healthy" has changed twice since (the `cookies` permission in
Phase 2, `management` and the options page in Phase 5).

**Decision.**

1. **Firefox parity is mechanically checked by the existing gates.** `check:local-only` scans
   every built manifest under `.output/`, and `check:size` measures every built target, so a
   Firefox build is held to the same no-network and no-widened-permission contract as Chrome.
   A Firefox permission Chrome does not need therefore still needs an allow-list entry with a
   written reason.
2. **Firefox is not e2e-tested, and the docs say so.** The Playwright harness launches
   Chromium with extensions; there is no honest Firefox equivalent in this repo. The e2e
   column of the release checklist applies to Chrome only, and that limitation is stated
   rather than papered over.
3. **`verify` rebuilds Chrome only.** The Firefox output under `.output/firefox-mv3/` is
   produced by `build:firefox` and checked as-is on the next gate run. A changed Firefox
   build requires running `npm run build:firefox` (or `build:all`) before `verify` can vouch
   for it — this is a documented sequence, not an accident.

**Consequences.** The Firefox manifest carries the same four permissions, the same CSP, the
Gecko id `sentinel@caseymccallum.dev`, an event-page background (`background.scripts`, how
WXT renders MV3 for Gecko) and `data_collection_permissions: { required: ['none'] }`, which
asserts to Firefox 140+ that Sentinel collects nothing.

### D-013 - The options page can see what it stores (accepted)

**Context.** The options page could *forget* all site history but never *show* it — a
one-way door. Users were asked to trust a claim ("metadata only, never page paths or
titles") they could not inspect, which sits badly next to Sentinel's own rule that every
number is inspectable.

**Decision.**

1. **The "Your data" section lists what is recorded.** One row per registrable domain —
   scan count, last score, last seen — computed by the same `summarizeProfile` the popup's
   Changes panel uses, so the two surfaces can never disagree about what a profile says.
   The list is fetched read-only (`MSG_LIST_PROFILES`) when the page opens and refreshed
   after each destructive action; it is never persisted in the page.
2. **Per-site forget is one click; bulk forget keeps its confirmation.** Consistent with the
   popup's per-site forget (D-008): the destructive-but-scoped action is immediate, the
   destructive-and-broad action stays armed-then-confirmed (D-011). `MSG_FORGET_SITE`
   addresses a registrable domain and unmarks any live tab state for it, so the next scan
   records the site fresh.
3. **No new permission, no new data.** The list shows what `browser.storage.local` already
   holds, and nothing else is collected to fill the UI.

**Consequences.** `ProfileHistorySummary` travels to a second surface; the options e2e
asserts the recorded site appears, that a per-site forget empties it, and that the confirmed
bulk clear provably removes a freshly recorded profile.

## 4. Permission posture

Sentinel requests four permissions, and all of them are load-bearing:

| Permission | Reason it earns its place |
| --- | --- |
| `storage` | settings, and the session-scoped per-tab observations the popup reads |
| `webRequest` | read the response headers and status of requests the page *already made* |
| `cookies` | enumerate cookie *metadata* for the Cookie Transparency module — see D-007 |
| `management` | list the other installed extensions for the Extension Auditor — see D-010 |
| `<all_urls>` (host) | the product is "score the page you are on", for any page |

Three more are allow-listed in the gate but deliberately **not** requested, because the architecture
does not need them: `tabs` (tab id and URL come through the `<all_urls>` host access),
`scripting` (the content script is declared statically in the manifest, so nothing is injected on
demand) and `activeTab` (Sentinel acts on the page the user opened it from, which it already has host
access to). Adding any of them later requires editing the gate's allow-list *with a written reason*,
which is what makes widening permissions a visible decision rather than a quiet one.

Forbidden by the gate, with reasons: `webRequestBlocking`, `declarativeNetRequest`,
`identity`, `proxy`, `debugger`, `nativeMessaging`, `downloads`.
`cookies` graduated from this list to the allow-list in Phase 2 (D-007) and `management` in
Phase 4 (D-010) — the written decisions live above, and the gate's allow-list entries carry
the same justification, so removing either half fails `npm run verify`. The gate also scans
for the *control* calls (`management.setEnabled`/`uninstall`/`uninstallSelf`) as primitives,
so D-010's read-only promise is enforced, not just written down.
`optional_permissions` and `optional_host_permissions` are scanned identically, so a
permission cannot arrive "later".

## 5. Gates and testability

`npm run verify` runs, in order: `icons:check` -> `compile` (`tsc --noEmit`) -> `test`
(vitest) -> `build` (WXT, Chrome) -> `check:local-only` (source + built bundles + built
manifests) -> `check:size` (400 kB total, 200 kB per file).

`npm run test:e2e` is the second, heavier gate: it builds the extension and drives it in headless
Chromium against fixtures served from 127.0.0.1, asserting the popup's score, grade, reasons and
drill-down. It is separate from `verify` because it needs a Playwright Chromium download, and it is
the gate that must be green before Phase 1 is called done. `docs/DEVELOPMENT.md` section 6 documents
the harness and its traps.

Test seams that make the pipeline provable without a browser:

- `PageObservation` fixtures feed analyzers directly (`src/core/trust-engine.test.ts`,
  `src/modules/trust-score/signals/*.test.ts`).
- `TrustEngine` takes an injected analyzer list and clock.
- `DomainProfileStore` takes a `ProfileStorageAdapter`; `createMemoryProfileAdapter()` is the
  test double, so no `chrome.storage` is needed in unit tests.

## 6. Open items

Phase 1 closed items 1 and 2:

1. ~~Phase 1 analyzers for the reserved privacy/hygiene ids, then the weight rebalance to the Phase 1
   split.~~ **Done.** `privacy.ts` and `hygiene.ts` emit all eight reserved ids, the weights are
   25/25/30/20 and `docs/SCORING.md` records why.
2. ~~Playwright "money test".~~ **Done.** `npm run test:e2e` builds the extension, serves local
   fixtures and asserts the popup's score, grade, reasons and drill-down end to end. The traps that
   cost the most time (headless builds without extension support, and which tab the popup should
   describe) are written down in `docs/DEVELOPMENT.md` section 8.

Phase 2 closed the Cookie Transparency module (Task 2.x): the `cookies` permission with the
written D-007 justification, the metadata-only cookie observer, the 50-entry cookie knowledge
base (`src/shared/cookies.ts`), the classifier and summary, three cookie signals wired into the
rebalanced model (20/20/25/15/20, `MODEL_VERSION` 2.0.0), the popup's Trust Score / Cookies
tabs with per-cookie and bulk delete (user-action-gated, D-007), a settings store with the
module off-switch, and the money test extended to assert cookie counts on both fixtures. The
gates that had to be green for this: `npm run verify` (including `check:local-only` with the
D-007 allow-list entry and `check:size` under budget) and `npm run test:e2e`.

Phase 3 closed the Change Monitor module (D-008): the `browser.storage.local` profile adapter
(`src/storage/profile-adapter.ts`), the recording rule (once per fully-observed observation,
digest re-attached on re-scores), the popup's Changes tab with the history line, change rows
and a "Forget this site" action, and the money test extended to assert a cross-visit change on
one registrable domain.

Phase 4 closed the two remaining planned modules. The Header Dashboard (D-009) ships the
response headers the site actually sent next to the values good practice recommends —
informational and weightless, with `available: false` rendered as "did not observe". The
Extension Auditor (D-010) reviews the other installed extensions for over-broad permissions
behind a read-only `management` permission, fetched lazily from the popup, never persisted
and never scored. Phase 4 also fixed a latent collection bug the new Headers e2e test
exposed: `webRequest.onHeadersReceived` was registered without the `['responseHeaders']`
extraInfoSpec, so Chrome never delivered response headers at all — every header signal had
been reporting `measured: null` and redistributing its weight since Phase 1. With the fix,
the header category measures what it always claimed to measure, and scores on pages with
weak or missing headers are now (correctly) lower than they read before.

Phase 5 gave the settings a second, full-view surface and made the Firefox target a checked
one. The options page (D-011) lists every module from the registry with a toggle each, hosts
the confirmed "Forget all site history" action (`MSG_FORGET_ALL_PROFILES`), and the popup's
footer links to it; both surfaces toggle through the one pure helper (`withModuleEnabled`).
The Firefox build (D-012) is asserted by the same gates — `check:local-only` and
`check:size` cover every built target — while the e2e suite remains Chromium-only by
documented decision.

Phase 6 made the options page's "Your data" section two-way (D-013): the recorded sites are
listed — the same metadata-only summaries the Changes panel uses — with a one-click forget
per site beside the confirmed bulk clear. The release process now has its own checklist,
`docs/RELEASE.md`, which owns the two manual steps (the zero-outbound-requests DevTools
check and the Gecko smoke test) and the store listing copy.

Still open:

3. Manual release-checklist step: run the extension with DevTools open and confirm zero outbound
   requests originate from Sentinel itself. The automated gates (`check:local-only`) inspect the source
   and the built bundle, but only a human with the Network tab open can confirm the running product.
   The full step-by-step lives in `docs/RELEASE.md` §4.
4. TLS and certificate facts are `null` in Chrome (its `webRequest` does not expose them), so
   `connection.tls-strength` and `connection.certificate` report `measured: null` there. Filling them
   in needs a different source - the certificate transparency log is a network call, so it cannot be
   used - and until then the connection category rests on `connection.https` and `connection.hsts`.
5. The popup now has five real tabs (Trust Score, Headers, Cookies, Changes, Extensions) and no
   planned modules remain. All five modules can be switched off independently in settings; the
   trust-score module itself is deliberately not switchable wholesale (see `normalizeSettings`).
6. Firefox is built and gate-checked but not e2e-tested (D-012): the Playwright harness is
   Chromium-only. Before a Firefox release, run `npm run build:all` and then `npm run verify`
   (which re-checks both built targets), and load the Firefox build manually in a Gecko
   profile once — the automated gates cannot vouch for runtime behaviour they do not drive.
   The smoke-test steps live in `docs/RELEASE.md` §5.