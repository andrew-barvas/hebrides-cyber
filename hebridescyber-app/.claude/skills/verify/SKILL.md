---
name: verify
description: Run this app's full local CI gate (lint, type check, unit tests, e2e) in the same order deploy.yml runs it, before claiming a change is done or ready to commit/deploy.
---

# Verify

Reproduces `deploy.yml`'s pre-deploy gate locally, in the same order, so a
change is validated the same way CI validates it — see CLAUDE.md's
"Testing strategy" section for what each gate catches and why the order
matters (type check is separate from build; e2e needs the hardcoded
`example-project` Supabase ref, never real credentials).

Run from `hebridescyber-app/`:

```bash
npm run lint
npx tsc --noEmit
npm run test:unit
```

Then, only if browsers aren't already installed (`npx playwright install --with-deps chromium` is a one-time-per-machine cost, skip if a prior run already did this):

```bash
npx playwright install --with-deps chromium
```

```bash
npm test
```

## Interpreting results

- **Lint**: zero tolerance for errors. Pre-existing `react-hooks/set-state-in-effect`
  warnings on a handful of components (`TicketIntegration.tsx`, `TwoFactor.tsx`,
  `Webhooks.tsx`, others) are known and not a regression — don't attempt to
  fix them as a side effect of an unrelated change.
- **tsc**: any output at all is a failure. `next build` does not catch these.
- **Unit tests**: coverage thresholds in `vitest.config.mts` are a floor, not
  a target — a failure here on threshold means something dropped, not that
  the bar needs lowering.
- **E2E**: builds the app and starts its own server automatically (slow,
  ~1 minute). If it fails on a change that didn't touch marketing pages,
  the dashboard login flow, or pricing, treat that as a signal something
  broader broke.

Only run the subset relevant to what changed if iterating quickly (e.g.
lint+tsc while mid-edit), but run all four before calling a change done —
this mirrors what will actually gate the real deploy.
