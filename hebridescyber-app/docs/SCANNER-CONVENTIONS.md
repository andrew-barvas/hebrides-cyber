# Scanner conventions

Normative rules for writing or extending a check in `src/lib/scanners/` or
`src/worker/tools/`. Six source files point here for exactly this reason —
if you're editing one of them, read this first. Kept short deliberately:
this is a rulebook, not a tutorial. For *what already exists* — every tool,
service and check, with its checkIds, severities and profiles — see
`docs/SCANNER-INVENTORY.md`, which is the single source of truth for
per-check detail, plus `docs/FUNCTIONALITY-MATRIX.md` for plan-gating and
test coverage. For *how the pipeline is wired* (base vs. extended tiers,
`runAllChecks()`, `runExtendedTools()`, the order of the final passes), see
`docs/ARCHITECTURE-NOTES.md`'s "Scanner pipeline" section.
The always-applicable rules are numbered in `CLAUDE.md`; the `/new-scanner-check`
skill walks the whole flow.

1. **Export the result type from the module**; add it to `ScanResults` in
   `src/lib/scanners/index.ts` (base tier) or the `extended` object in
   `src/lib/scanExecution.ts` (extended tier).
2. **Push findings with `severity`, `title`, `detail`, `remediation`, and
   `checkId`.** `checkId` is the stable identity `findingsDiff.ts` and
   `ticketLinks.ts` both match on across scans — format
   `"<module>.<check-name>"`, or `"<module>.<check-name>:<key>"` in a loop.
   An untagged finding can never participate in New/Fixed diffing or ticket
   dedupe, so don't skip it.
3. **Put remediation prose in `src/lib/scanners/remediationText.ts`**, not
   inline in the check — keeps the check readable and the fix text
   reviewable/reusable in one place.
4. **Never report a finding you cannot evidence.** If the server's
   behaviour is ambiguous, return nothing — a false positive costs more
   trust than a missed low-severity finding earns. This is the product's
   stated differentiator (see `docs/USER-GUIDE.md` §6, `/what-we-check`'s
   "How we avoid false positives"); it isn't optional per-check judgement.
5. **Every outbound request gets `AbortSignal.timeout()`.** A hung third
   party must not hang a scan — see `httpProbe.ts` for the shared
   false-positive/timeout-hardening helpers most path-probing checks should
   reuse rather than reimplementing.
