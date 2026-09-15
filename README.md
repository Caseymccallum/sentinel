# Sentinel

**Local-first trust and privacy analysis for websites.** Sentinel scores the page you are on,
explains every point it deducts in plain language, and never phones home. No accounts, no
telemetry, no network calls — ever.

## What it does

- **Trust Score** — a 0–100 score with a letter grade, built from five categories:
  connection security (20%), response hardening (20%), privacy exposure (25%), page hygiene
  (15%) and cookie transparency (20%). Every finding is inspectable: what was measured, how
  much it cost, and what the site owner could fix.
- **Cookie Transparency** — lists every cookie the page and its third parties set, explains
  what each one is for, who set it, how long it lasts, and whether deleting it is safe. You can
  delete individual tracking cookies or all of them at once, with a confirmation first.
- **Changes** — remembers what each site looked like on your last visit (locally, per domain,
  metadata only) and reports when its security posture changed: a score drop, new trackers, a
  header that disappeared. Change findings never alter the Trust Score.
- **Modules you control** — every module can be switched off in settings. Switching cookies off
  means Sentinel never reads the cookie store at all; switching Changes off means it keeps no
  site history.

## Privacy: what Sentinel does and does not do

Everything Sentinel knows stays in your browser. It makes no requests, ships no remote code,
and stores nothing beyond your own browser's session and settings storage.

**About the `cookies` permission:**

> Sentinel reads cookies to explain what they are and how long they last. It never sends
> cookie data anywhere. It never modifies cookies without your explicit action.

Concretely:

- Sentinel reads cookie **metadata only** — names, domains, lifetimes and flags. It never
  reads, stores or displays a cookie's *value*. A unit test feeds a canary value through the
  reader and proves the secret appears nowhere in the output.
- `chrome.cookies.set()` is never called. `chrome.cookies.remove()` runs only when you click a
  Delete button in the popup, and a bulk delete always asks for confirmation first.
- Every permission is justified in writing in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
  (decision D-007 for cookies) and enforced by the `check:local-only` gate, which fails the
  build if the manifest ever requests anything else.

## Development

```bash
npm install
npm run dev          # build with live reload
npm run verify       # icons → typecheck → unit tests → build → local-only gate → size gate
npm run test:e2e     # the money test: builds, serves local fixtures, drives the popup
```

Documentation lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (why the system is shaped
this way), [`docs/SCORING.md`](docs/SCORING.md) (every number behind the score) and
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) (invariants, gates and hard-won traps).

## License

MIT
