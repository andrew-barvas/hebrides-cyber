---
name: new-scanner-check
description: Add or extend a scanner check in src/lib/scanners/ (base passive tier) or src/worker/tools/ (extended active tier) — the wiring, the evidence rules, the aliases, the bench fixture and the test, in the order that keeps CI and the finding lifecycle correct. Use for any new check, a new finding/checkId on an existing check, or a new extended tool.
---

# Add a scanner check

The most common change in this repo and the easiest to get subtly wrong: a
check that reports an empty result instead of an error will make the next scan
mark last scan's findings fixed and auto-close their tickets.

Read `docs/SCANNER-CONVENTIONS.md` first (short, normative, five rules). For
what already exists and how it's gated, `docs/SCANNER-INVENTORY.md` and
`docs/FUNCTIONALITY-MATRIX.md`. For how the pipeline is wired,
`docs/ARCHITECTURE-NOTES.md`'s "Scanner pipeline".

## Which tier

| | Base passive suite | Extended active tier |
|---|---|---|
| Lives in | `src/lib/scanners/` | `src/worker/tools/` |
| Runs | every scan, every plan | only when the resolved profile isn't `safe` — in practice scheduled jobs |
| Registered in | `runAllChecks()` + `ScanResults` (`src/lib/scanners/index.ts`) | the `extended` object + `runExtendedTools()` (`src/lib/scanExecution.ts`) |
| Needs a binary | no (Chromium aside) | usually yes — installed only in `.github/workflows/scheduled-scans.yml` |
| Profile gating | none | `ExtendedToolName` / `EXTENDED_TOOL_NAMES` in `src/lib/scanProfiles.ts` |

A check that needs a connected GitHub repo, stored cloud credentials or a saved
target credential is extended tier regardless of whether it shells out.

## Steps

1. **Export the result type from the module** and add it to `ScanResults`
   (base) or the `extended` object (extended). A check not in that type is
   invisible to everything downstream.

2. **Register it** — base: into `runAllChecks()`'s `Promise.all` batch, unless
   it consumes another check's output (like `wpvdb.ts` needing
   `webapp.wordpress.plugins`), in which case run it after that one resolves.
   Extended: add the tool name to `scanProfiles.ts` and the profiles it belongs
   to.

3. **Push findings with a stable `checkId`** — `"<module>.<check-name>"`, or
   `"<module>.<check-name>:<key>"` in a loop. This is the identity
   `findingsDiff.ts`, `findingLifecycle.ts`, `finding_triage` and `ticket_links`
   all match on. Severity, title, detail and remediation come with it.

4. **Add the alias if the namespace doesn't normalise to the key.** Base-suite
   prefix → `BASE_ALIASES`; extended tool → `TOOL_ALIASES` in
   `findingLifecycle.ts`. Without it, `isCovered` can't tell that this tool ran,
   and the lifecycle either never resolves the finding or resolves it when the
   tool didn't run.

5. **Remediation prose goes in `remediationText.ts`**, attached as
   `Finding.remediation` at the point the finding is created — never
   re-derived later by string-matching a title.

6. **Compliance mapping**, if the check has a genuine angle: add its base
   checkId to `COMPLIANCE_MAP` in `compliance.ts`. No entry means "not yet
   categorised", which is a fine answer — never force a mapping.

7. **Test it.** A `*.test.ts` colocated next to the module. Prefer a pure
   function fed real captured output over a mocked network —
   `sqlmapOutput.ts` against `fixtures/sqlmap/` is the model. For a real
   binary, an integration test that produces its input at run time
   (`badsecrets.integration.test.ts`).

8. **Bench fixture, if it probes paths.** Add a site to
   `bench/fixtures/sites.ts` and `mustFind`/`mustNotFind` checkIds to
   `bench/expectations/<target>.json`, then `npm run bench`. Loopback only, no
   internet. `.github/workflows/benchmark.yml` runs it on every
   `src/lib/scanners/**` change, so a missing expectation surfaces as a CI
   failure later rather than now.

9. **Gate**: `npm run lint`, `npx tsc --noEmit`, `npm run test:unit`,
   `npm test` — or the `/verify` skill. Then `/ship`.

## The rules that break things

- **A failed lookup is `status: "error"`, never an empty "checked".** No
  evidence either way is not "clean". This is the single most important rule
  here — `findingLifecycle.ts` reads silence as "fixed".
- **Never report a finding you cannot evidence.** Ambiguous server behaviour →
  return nothing. A false positive costs more trust than a missed low
  earns, and this is the product's stated differentiator, not per-check taste.
- **Every outbound request gets `AbortSignal.timeout()`.**
- **Shell out via `src/lib/execTool.ts`'s `execTool`**, never bare
  `execFile`/`promisify(execFile)` — it closes the child's stdin, without which
  nuclei and gospider hang until their timeout.
- **A path-probing check reuses `fetchBaseline`/`normaliseBody`
  (`httpProbe.ts`)** rather than trusting a 200. Without it every SPA that
  serves its shell for unknown paths reports an exposed `.env`.
- **Import the pipeline as `@/lib/scanners`** (the directory). Never create
  `src/lib/scanners.ts` — it shadowed the directory and silently ran an old
  4-check version.
- **A new pinned binary is verified by version *and* SHA-256**, and the install
  step must fail loudly. An install that only logs its failure hides a tool
  that never installed — how gospider, kiterunner and trivy silently did
  nothing until 2026-10-06.
- A check needing a repo/credential/cloud config returns a clean
  `not_applicable` / `not_configured`, never an error, when the input is absent.
