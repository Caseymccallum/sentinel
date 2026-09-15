# Contributing to Sentinel

Sentinel is a small, deliberate project, and its currency is not code volume — it is **argument and
enforcement**. A change earns its place by being justified and by being covered by something that
fails when it is wrong. That is the standard the thirteen decisions in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) are held to, and it is the standard a contribution is
held to as well.

## Read these first

1. [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what Sentinel is for, and what it explicitly does
   not protect against.
2. [`docs/SCORING.md`](docs/SCORING.md) — every weight, budget and cap, with the argument for each.
3. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §1 (non-negotiables) and §3 (the decision record).
4. [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — invariants, gates, and the traps that have already
   cost time once.

## The non-negotiables

These four are enforced by `npm run check:local-only` and the unit suite, so a pull request that
breaks one cannot merge regardless of how useful it is:

1. **No network calls, ever.** Nothing in `src/` may use `fetch`, `XMLHttpRequest`, `WebSocket`,
   `EventSource`, `sendBeacon`, `WebTransport`, `RTCPeerConnection`, `importScripts`, remote
   `import()` or a remote `<script src>`.
2. **Observation, never interference.** Sentinel reads what the browser already did. No blocking,
   redirecting, rewriting or delaying.
3. **Every number inspectable.** Scoring is data plus arithmetic in `src/core/scoring-model.ts`, not
   conditionals buried in analysers.
4. **Least privilege.** The permission list is allow-listed in `scripts/check-local-only.mjs`; adding
   a permission means editing that allow-list *with a written reason* and a decision in
   `docs/ARCHITECTURE.md`.

## The three easiest ways to contribute

### 1. Knowledge bases (smallest diffs, most valuable)

Three local lists decide what a user is told, and each entry is a claim they will read as fact:

| File | What it holds |
| --- | --- |
| `src/shared/trackers.ts` | known tracker hosts and what they do |
| `src/shared/cookies.ts` | cookie name patterns, purpose and lifetime |
| `src/modules/extension-auditor/permissions.ts` | how severe an extension permission is |

Add the entry, add or extend a test next to the file, and run `npm run verify`. Because a cookie entry
can change a count the popup displays, changing these lists usually means re-running
`npm run test:e2e` too — the money test asserts cookie counts on the fixtures.

Every entry needs **evidence a reviewer can check**: the vendor's own documentation, the cookie's
documentation, or the browser's permission reference. Not a blog post that repeats the claim.

### 2. Documentation corrections

If the docs and the code disagree, **the code is right and the doc is the bug** — except for
`docs/SCORING.md`, which is the contract and therefore the thing the code must match. Corrections are
genuinely welcome; a stale sentence in a document that asks to be trusted is a real defect.

### 3. A fixture that exposes a wrong-but-plausible answer

Sentinel's worst bug class is a finding that is wrong and still believable. `docs/DEVELOPMENT.md` §8
records one: a missing `responseHeaders` extraInfoSpec meant every header check reported "not
measured" for four phases, and redistributed weights kept the scores plausible. A fixture page that
makes a wrong answer visible is a high-value contribution.

## How a change lands

1. **Open an issue first** for anything that moves a number, adds a permission, or adds a module —
   the templates are there to ask for the argument before the code. Small fixes, documentation
   corrections and new knowledge-base entries do not need one.
2. **Fork and branch.** Keep the change to the thing you are changing.
3. **Run the gates.** `npm run verify` always; `npm run test:e2e` if the collection layer moved
   (background worker, content scripts, observers, the e2e harness); `npm run screenshots` if a change
   made an image in `README.md` inaccurate.
4. **Open the pull request** and fill in the template. Its first question is which gate covers the
   change. If the honest answer is "none", say that — it is a useful thing for a reviewer to know and
   sometimes the right answer (a documentation fix is covered by a reader, not a gate).
5. **Review looks for three things:** is it enforced by something that fails when it is wrong; is the
   decision written down with the alternatives rejected; does the sentence shown to a user stand
   alone. Everything else is negotiable.

## Invariants, and what fails if you break one

| Invariant | Enforced by |
| --- | --- |
| Category weights sum to exactly 1 (tolerance `1e-6`) | `validateScoringModel()`, `src/core/scoring-model.test.ts` |
| Every category has exactly 100 points of budget, so it reaches 0 only when every signal in it measured its worst value | same |
| Signal ids are unique and reference a real category | same |
| Grade boundaries are fixed and evaluated at 0.01 resolution | `scoreToGrade()` plus the model test |
| A hard cap is declared in one place, names a real signal, and carries a reason a user can read | `SCORE_CAPS`, model test |
| A cookie's *value* is never read, stored, logged or displayed | the canary test in `src/background/cookie-observer.test.ts` |
| `measured: null` means "could not look" and never removes points; "looked and it was fine" is 100 | analyser tests, per D-006 |
| The page cannot make the extension behave differently | `check:local-only` (no network, no injection, no `externally_connectable`) |
| Sentinel cannot affect the page | the same gate forbids blocking APIs; two tests assert the DOM is unchanged |

## Style

No formatter is enforced — deliberately. A reformat commit would bury the history of a repository
whose value is its reasoning, so the style is documented instead and the formatter decision waits
until it is actually painful:

- TypeScript, two-space indent, single quotes, semicolons, trailing commas in multiline literals,
  wrapped near 100 columns. **Match the file you are editing.**
- Comments explain *why*, above the thing they explain. A comment that restates the code is deleted in
  review.
- No emoji in source. The popup's marker glyphs are written as `\uXXXX` escapes with the glyph named
  in a comment, so nothing can silently change what a user is told.
- Prose and identifiers keep the British spellings already in the codebase (`normalise`, `behaviour`,
  `analyse`). Follow the file; do not convert it.
- Tests live next to the code as `*.test.ts`, describe behaviour rather than implementation, and cover
  every path that produces `measured: null` — those are the paths that mislead when they are wrong.
- Keep the diff to the change. If you reflow whitespace on lines you did not need to touch, expect to
  be asked to shrink it.

## What will be declined

- A new permission without a decision in `docs/ARCHITECTURE.md` and an allow-list entry in
  `scripts/check-local-only.mjs` with a written reason.
- Anything that puts the extension on the network, including "just a version check".
- Blocking, redirecting or rewriting traffic. That is a blocker's job; Sentinel observes, and the
  forbidden-API list in the gate is not negotiable.
- Reputation data or any lookup against an external service — the deliberate consequence of D-004.
- Formatting-only pull requests (see Style).
- A second module that duplicates an existing one's job, or a weight change with no argument.

## Reporting a vulnerability

Sentinel's threat model is public and narrow, so read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)
first — much of what looks like a gap is a documented limit. For a real defect in Sentinel itself
(anything that lets a page influence the extension, or data leaving the browser), use GitHub's private
vulnerability reporting on this repository rather than a public issue.

## Licence

Sentinel is MIT-licensed ([`LICENSE`](LICENSE)). By contributing you agree your contribution is
licensed on the same terms — no CLA, no copyright assignment.

