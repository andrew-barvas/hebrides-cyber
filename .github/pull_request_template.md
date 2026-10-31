## What and why

<!-- One or two sentences. Link the plan item (NEXT-STEPS.md, LAUNCH-PRIORITY.md, ENHANCEMENTS.md E-nn) or the OWNER-TODO.md item (OT-nn). -->

## How it was checked

<!-- Commands run from hebridescyber-app/ and their exit codes, plus anything checked by hand. -->

- [ ] `npm run lint` (0 errors)
- [ ] `npx tsc --noEmit` (no output)
- [ ] `npm run test:unit:coverage` (no `Errors` line, thresholds not lowered)
- [ ] `npm test` (Playwright), or a note on why it was skipped

## Safety checklist

- [ ] No secrets, keys, tokens, connection strings or real customer data in the diff, fixtures or PR text.
- [ ] Anything new that stores data from a scanned site is bounded and redacted at capture (see `src/lib/findingEvidence.ts`), and is deleted with the scan.
- [ ] New configuration is read from env / secrets and degrades safely when unset (no throw at import; `/api/health` stays honest).
- [ ] New failure paths report to Sentry (`@sentry/nextjs` in the app, `workerSentry.ts` in the worker) rather than being swallowed.
- [ ] A new scanner check follows `docs/SCANNER-CONVENTIONS.md`: real evidence, `error` not "clean" when the tool didn't run.
- [ ] A new migration takes the next free number and the RLS test suite (`npm run test:db`) covers any new table.
- [ ] Docs updated in the same change; anything only the owner can do is added to `docs/OWNER-TODO.md` as an OT item.
