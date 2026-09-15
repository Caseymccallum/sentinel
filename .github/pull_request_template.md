<!--
  Sentinel's answer to "trust me" is a gate. The first thing this template asks is which gate covers
  your change — if the honest answer is "none", that is worth saying out loud in the PR.
-->

## What this changes

<!--
  One paragraph. If it changes what a user is told, say what they are told now and what they will be
  told instead.
-->

## Gate coverage

- [ ] `npm run verify` is green (icons, typecheck, 440 unit tests, Chrome build, `check:local-only`, `check:size`)
- [ ] `npm run test:e2e` is green — **required** if this touches the collection layer (background worker, content scripts, observers, the e2e harness)
- [ ] `npm run screenshots` was re-run, if a change made an image in `README.md` inaccurate

## Does it move a number?

- [ ] `MODEL_VERSION` in `src/core/scoring-model.ts` was bumped if weights, impacts or thresholds changed — and *not* bumped for UI or module work that cannot move a number
- [ ] `docs/SCORING.md` was updated if a weight, impact budget, grade boundary or severity rule changed

## Does it change what Sentinel can see or claim?

- [ ] No new permission, host permission or network-adjacent API was added. (A new one needs a decision in `docs/ARCHITECTURE.md` **and** a written entry in the `scripts/check-local-only.mjs` allow-list, or the gate will fail the build — which is the point.)
- [ ] `docs/THREAT-MODEL.md` was updated if this changes what Sentinel can observe, store or claim

## Decisions

- [ ] Any non-obvious choice here is written down as a decision (`D-00x`) in
      `docs/ARCHITECTURE.md`, including the alternatives that were rejected — the same standard the
      existing thirteen are held to. Formatting-only pull requests are asked to shrink; see the
      `CONTRIBUTING.md` note on the formatter.
