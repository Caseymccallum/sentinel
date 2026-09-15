# Sentinel scoring model

This document is the contract for every number Sentinel shows. The arithmetic lives in
`src/core/scoring-model.ts` as data plus a few pure functions; nothing here is decided inside
an analyser. If this file and the code disagree, the code is the bug - and
`src/core/scoring-model.test.ts` pins the invariants so the disagreement is caught rather than
argued about.

## 1. Shape of the score

```
signal measurement (0-100, or null)
  -> impact   = maxImpact * (100 - measured) / 100 * confidenceMultiplier
  -> finding  = impact + severity + category
  -> category = 100 - Σ(impact of measurable findings), clamped 0-100
  -> composite = Σ(category score * effectiveWeight), clamped 0-100, then hard caps
  -> letter grade
```

`measured: null` means "Sentinel could not observe this". It contributes **no** impact, it
makes the score `partial`, and it is reported as a caveat. A browser that hides a fact must
never cost the user points.

The distinction runs the other way too: a check that *ran* and found nothing wrong measures
**100**, not `null`. "This page contacted no tracker" and "Sentinel could not look" are different
statements, and only one of them is a finding about the page (see D-006 in `docs/ARCHITECTURE.md`).

## 2. Weights

| Category | Module | Weight | What it covers |
| --- | --- | --- | --- |
| `connection` | trust-score | **20%** | transport encryption, TLS strength, certificate trust, HSTS |
| `headers` | trust-score | **20%** | CSP, framing, MIME sniffing, referrer policy, permissions policy, banners, cross-origin isolation |
| `privacy` | trust-score | **25%** | known third parties and trackers, third-party surface, referrer leakage, background beacons |
| `hygiene` | trust-score | **15%** | mixed content, password forms, form targets, embedded content |
| `cookies` | cookie-transparency | **20%** | tracking-cookie load, third-party cookies, cookie persistence |

Weights sum to exactly 1, and each category's signals sum to exactly 100 impact points of
budget. Both invariants are asserted by `validateScoringModel()` and by
`scoring-model.test.ts`, so a weight change that forgets to rebalance a category fails the
suite rather than shipping.

The Phase 2 rebalance (connection 25→20, headers 25→20, privacy 30→25, hygiene 20→15) funded
the new cookies category at 20% without growing the model: five categories, one score, and no
signal anywhere that a page can farm for points. `MODEL_VERSION` was bumped to 2.0.0 so every
stored score records which weighting produced it.

### 2.1 Why trackers still carry the highest weight (25%)

Of everything Sentinel can observe, what a page does to the user *unasked* is the part the
user cannot see and cannot undo. Serving a page over HTTP is bad, and loudly flagged by the
browser itself; loading eight advertising trackers before the first paint is silent, persists
across sites, and is the actual product being sold. It is also the signal Sentinel measures
most directly and most completely - a page's own resource timings name the hosts it contacted.

Trackers also sit above cookies for a principled reason: a tracker is an **actual network call
the page made** — a completed disclosure of your visit to a third party — while a cookie is
*potential future* tracking, a capability planted in the browser that may or may not be read.
Weighting the completed harm above the planted capability keeps the score honest about what
already happened versus what could happen next.

### 2.2 Why connection is 20%, not the largest, yet still fatal

Transport is binary in practice: either the connection is encrypted or it is not, and the
browser already tells the user the latter in red. More than 20% would let "HTTPS present" swamp
a page that ships forty trackers. But an unencrypted page is not merely a deduction - it
invalidates the premise of every other measurement, because anything Sentinel observes or the
user types can be read or rewritten in transit. So `connection.https` carries a **hard cap**:
if it measures zero, the composite score cannot exceed **20**, however well-behaved the rest of
the page looks. A cap is not a silent adjustment - the popup shows the reason next to the
score, and `TrustScore.cappedBy` records which signal applied it.

The cap is data (`SCORE_CAPS` in `src/core/scoring-model.ts`) plus one pure function
(`applyScoreCaps`), and `src/core/scoring-model.test.ts` pins the three cases that matter: an
otherwise-excellent HTTP page is held at 20 rather than averaging up to 89, a page already below the
ceiling is not told it was capped, and a signal that was never measured caps nothing.

### 2.3 The cookies category (20%)

The cookie category scores what the page and its third parties planted in the browser's cookie
store, across three signals with a 45/30/25 impact budget:

| Signal | maxImpact | Measures | Verdicts (brief vocabulary) |
| --- | --- | --- | --- |
| `cookies.tracking` | 45 | count of analytics/advertising/social cookies | `COOKIES_NONE_OR_ESSENTIAL` (measured 100), `COOKIES_TRACKING_PRESENT` (1–2, measured 75), `COOKIES_TRACKING_HEAVY` (3+, measured ≤60) |
| `cookies.third-party` | 30 | cookies set by hosts other than the page | `COOKIES_THIRD_PARTY_PRESENT` (evidence, measured <100 when any exist) |
| `cookies.persistence` | 25 | longest remaining lifetime | `COOKIES_LONG_PERSISTENCE` (measured 75 when any cookie outlives a year) |

Why 20%, equal to connection: cookies are the *persistence* half of the privacy story. A
tracker request discloses your visit once; a `_ga` cookie with a two-year lifetime turns every
future visit into a disclosure. It is deliberately lighter than `privacy` (cookies are
capability, not completed disclosure — see 2.1) and heavier than `hygiene` (a tracking cookie
is a fact about you; a missing sandbox attribute is a fact about a frame). Essential and
unknown cookies deduct nothing — Sentinel does not punish a CSRF token, and it does not guess
at names it does not know.

When the cookie module is switched off in settings, the observer never calls
`chrome.cookies.getAll()` (D-007), the cookie signals report `measured: null`, and the
category's weight is redistributed across the categories that did measure — a disabled module
is a gap in the report, never a bonus.

### 2.4 What the Change Monitor deliberately does not score

The Change Monitor (Phase 3, D-008) produces findings — "three tracking requests fewer than
last time", "trust score moved from 92 to 82" — and none of them touch the composite. This is
a line worth stating in the scoring document because it looks like an omission: a site that
ships four new trackers between visits does not lose points *for shipping them* (the privacy
category already scores the trackers on the page); the Change Monitor's job is the narrative —
what got better, what got worse — not the number. Folding change findings into the score would
let a site farm points by being stable, and would make the score depend on Sentinel's own
storage history rather than on the page being scored. Change findings carry severity for
colour and ordering in the Changes panel only.

### 2.5 What the Header Dashboard and Extension Auditor deliberately do not score

Phase 4 shipped the last two modules (D-009 and D-010), and both are informational by
decision — which is worth stating in the scoring document because neither produces a single
`SignalAssessment`, so a reader of the code might think they are unfinished rather than
deliberate.

- **The Header Dashboard shows; the trust-score module scores.** The `headers` category
  already carries the full 100-point impact budget for the security headers. The dashboard's
  rows (`ScanResult.headers`) are display data: the value the site sent, next to the value
  good practice recommends, and — only when the response was actually observed — the honest
  word "absent" for the ones it did not send. One missing header costs points once, in the
  `headers` category, never twice.
- **The Extension Auditor audits your browser, not the page.** Its findings grade what other
  installed *extensions* could do, which is a fact about the browser profile, not about the
  page in front of you; folding it into the score would make the same page score differently
  depending on what else is installed. The audit is fetched when the Extensions tab opens and
  never persisted.

Neither module changes a weight, an impact or `MODEL_VERSION`: five categories, one score,
unchanged from Phase 2.

## 3. Grades

Grades are assigned from the final score at 0.01 resolution (`scoreToGrade` in
`src/core/scoring-model.ts`), so 89.99 is a `B+` and 90 is an `A-`.

| Grade | Minimum score | | Grade | Minimum score |
| --- | --- | --- | --- | --- |
| A+ | 97 | | C+ | 77 |
| A | 93 | | C | 73 |
| A- | 90 | | C- | 70 |
| B+ | 87 | | D+ | 67 |
| B | 83 | | D | 63 |
| B- | 80 | | D- | 60 |
| | | | F | below 60 |

Thresholds are deliberately fixed rather than tuned per model version: a grade the user has
learned should not silently mean something else after an update. When weights or impacts change
materially, `MODEL_VERSION` is bumped and the version travels with every stored `ScanResult`, so
history can be read in context.