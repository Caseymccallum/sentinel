# Sentinel threat model

Sentinel's promise is narrow and specific: it *tells you* things. This document says which things it
can tell you, what it cannot, and where it would be wrong to rely on it. It exists because the
failure mode of a privacy tool is not being hacked — it is being trusted for something it never
claimed to do.

Every claim below is either enforced by a gate (see `README.md` → *Verify the claims yourself*) or
named as a limitation. If this file and the code disagree, the code is the bug.

## 1. What Sentinel is for

Answering one question about the page in front of you: **what is this page doing, and why should I
care?** It observes the transport, the response and the document the browser already received, and
turns that into a score with a written reason for every point removed.

## 2. What it protects against

- **Silent collection by the page you are on.** Third-party hosts contacted, tracking cookies and
  their lifetimes, insecure transport, missing hardening headers, and forms that mishandle
  credentials. These are the things a user cannot see without being told.
- **Decisions made without information.** You cannot consent to a cookie you cannot inspect. The
  Cookies panel names each one, its setter, its lifetime and its purpose before you decide.
- **Change over time.** A site that quietly loses a header or gains a tracker between your visits
  says so, from locally stored metadata, without the score being involved.
- **Over-broad *other* extensions.** The Extension Auditor lists what else is installed and which
  permissions it holds — read-only, on demand, never persisted (D-010).
- **Sentinel's own honesty.** The three claims in the README are enforced by `check:local-only` and
  `check:size` against both the source and the built bundles, so a betrayal of the promise fails the
  build rather than shipping quietly.

## 3. What it does not protect against

**Sentinel is not a blocker.** It never blocks, redirects, rewrites or delays a request or a
response; `webRequestBlocking` and `declarativeNetRequest` are forbidden by the gate. If you want
tracking stopped, use a blocker alongside Sentinel.

- **A malicious extension in the same browser profile.** The Extension Auditor grades *permissions*,
  not behaviour, and it cannot read another extension's code or stop it from running. A strong
  report about a hostile extension is a hint, not a defence — and an extension that asks for little
  and abuses it can look clean.
- **A compromised browser or operating system.** Sentinel runs inside the browser it is reporting on,
  in the same trust domain as the thing that would lie to it.
- **Server-side and account-level tracking.** A login, a server log, a hashed email or a first-party
  identifier that never sets a cookie is invisible here. Sentinel sees the client side of the
  conversation and nothing beyond it.
- **Fingerprinting that leaves no trace in the APIs it reads.** Canvas, audio, font and timing
  fingerprinting leave no cookie and contact no third-party host, so there is nothing observable to
  report.
- **What a network path does with traffic it can already read.** Sentinel reports that a page was
  loaded over HTTP, which is exactly the fact that matters — but it cannot tell you who was watching.
- **Reputation and known-bad sites.** Deliberately absent (D-004): no reputation service means no
  network call, so Sentinel will never warn that a domain is "known malicious". It describes what it
  observed on this page, this time.
- **Malware, phishing semantics, or the intent behind a page.** Sentinel reads transport and page
  structure, not motives. A hostile page can be technically well-behaved and score well.
- **Any page Sentinel cannot see into.** `chrome://` pages, other extensions' pages, PDFs and
  sandboxed documents are out of reach; those reports say so rather than guessing.

## 4. Trust boundaries

- **The page cannot make Sentinel behave differently.** The content script reports facts; the score
  is computed in the background worker from a hand-built `PageObservation` by pure analysers. The
  page cannot reach the extension (no `externally_connectable`, and extension pages run under
  `script-src 'self'`), cannot widen its own report, and cannot ask for a different score.
- **Sentinel cannot affect the page.** Collection is read-only: response headers are read after the
  fact by an observational `webRequest` listener, and the content script only reads the DOM. Two
  tests assert the document is byte-identical after an observation.
- **The score comes from observation, never from the page's claims about itself.** A page that
  declares a Content Security Policy in a `<meta>` tag is not credited with one; the header the
  browser actually received is what counts.
- **Stored data stays local and bounded.** Settings and per-domain profiles live in the browser's own
  storage, are metadata-only, and can be forgotten per site or entirely (D-013).

## 5. Where Sentinel can be wrong

Honesty about scoring cuts both ways, and two of these are deliberate trade-offs rather than bugs:

- **"Not measured" never costs points** (D-006). A check that could not run is a gap, not a bonus —
  but the consequence is real: a page that prevents observation, or a browser that will not expose a
  fact, can score *higher* than a page whose behaviour was visible and mildly bad. The score
  describes what could be observed, and nothing else.
- **Chrome does not expose TLS or certificate facts** to extensions, so two connection checks report
  "not measured" there and the category rests on HTTPS and HSTS alone. Filling that in would need a
  network call, which this design does not have.
- **Knowledge bases are finite.** Trackers, cookies and permission grades come from local lists
  (`src/shared/`, `src/modules/extension-auditor/permissions.ts`). A host that is not on the list is
  still reported for being contacted; it is simply not labelled with a purpose. Adding an entry is a
  reviewable change, and stale lists are a maintenance cost rather than a hidden one.
- **Grades are calibrated, not certified.** The weights are argued for in `docs/SCORING.md` and
  fixed by tests. They are a considered opinion about relative risk and reasonable people can
  disagree about them — which is why every finding shows its arithmetic instead of asking for trust.

## 6. Changing this document

A change to what Sentinel can see or claim needs a numbered decision in
[`ARCHITECTURE.md`](ARCHITECTURE.md) with the alternatives that were rejected (D-001 … D-013 are the
record). A new permission, a new network-adjacent API, or a new class of stored data each changes
this file *first*, because this file is what the promise means.

