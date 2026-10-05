# Next steps — session handoff

**Last updated: 2026-10-05.** Read this first in any new session (local or
cloud), after `CLAUDE.md` and `docs/SCANNER-CONVENTIONS.md`. It says where
things stand, the rules that kept biting, and the next five features with
enough detail to start each one cold.

To resume in a cloud session: open the repo `andrew-barvas/hebrides-cyber`,
branch from `master`, and prompt *"Read hebridescyber-app/docs/NEXT-STEPS.md
and implement item N (E-7x)."* Do one item per session.

## Where things stand

Everything below is merged to `master`, passed CI, and is deployed.
Database migrations: files exist through **047**; the next free number is **048**. Deploys now apply pending files through `src/scripts/apply-migrations.ts` (ledger table `schema_migrations`, checksum drift check). **One-time step:** production was migrated by hand, so run the Deploy workflow manually (workflow_dispatch) with `baseline_up_to` = `047` before the next push to master, otherwise the migration job refuses the unrecorded database and blocks the deploy.

| Shipped | Where |
|---|---|
| Emerging-threat alerts (E-68) | PR #1 — `emergingThreats.ts`, `emergingThreatAlerts.ts`, `emerging-threats.yml` (every 6 h), migration 045 |
| Lockfile + transitive dependency scanning, inventory SBOM (E-67) | PR #2 — `dependencyLockfiles.ts`, `lockfileSyntax.ts`, `ecosystemVersion.ts`, `osv.ts` querybatch |
| SAST with Opengrep + our own 34-rule pack (E-69) | PR #3 — `src/worker/tools/sast.ts`, `sast-rules/`, `repoClone.ts`, `sast-rules.yml` |
| Third-party script inventory, PCI 6.4.3/11.6.1 (E-62) | PR #4 — `scriptInventory.ts`; `info` on ordinary pages, `low` on payment pages (owner decision) |
| Finding triage: accept/authorise, false positive, snooze (E-64) | PR #5 — `finding_triage` (046), `/api/findings/triage`, report UI; only false positives leave the score |
| Signed-in crawl, slice 1 (E-70 follow-up) | `authenticatedCrawl.ts`, `crawl.auth.*` findings, design + safety rules in `docs/AUTHENTICATED-CRAWL.md`; uses the saved cookie/Basic credential |
| GraphQL exposure check in every scan | `graphql.ts` rewritten (it existed but was never wired in, and its checks were unevidenced) and wired into `runAllChecks`: open introspection (`graphql.introspection:<path>`, with type count), field-suggestion leakage when introspection is off (`graphql.suggestions`), public GraphiQL/Playground/Sandbox (`graphql.ide`). An endpoint counts only if the response has GraphQL's own shape; "no auth" and "no depth limit" findings were dropped as unevidenced. Bench: `graphql-open`, `graphql-locked`, and every SPA/catch-all trap must not report `graphql.*` |
| Confirmed-exploitable findings | `enrichWithProofOfExploit` now runs in `executeScan()` for every profile except `safe` (cap 20 per scan; `DISABLE_PROOF_OF_EXPLOIT=1` turns it off): open redirect, CORS, exposed file and reflected XSS (api-spec and ZAP alerts, which now carry url+parameter metadata). "Confirmed exploitable" badge, sort rank, `proof_of_exploit` in the API, flag in the executive report |
| "Fixed" needs coverage | `diffFindings(…, { canDetect })` + `canDetectFromResults()`: a scan that couldn't have run a finding's tool (passive scan after a full scan, errored base check) no longer reports it fixed, which also stops ticket auto-close firing on it |
| Scanner inventory | `docs/SCANNER-INVENTORY.md`: every tool, service and check family, derived from the code, with the discrepancies found against the docs |
| Executive PDF report | `executiveReport.ts` (pure HTML: score, severity counts, top priorities, compliance snapshot incl. SOC 2/HIPAA, all findings, accepted risks, checks that did not finish; false positives left out; white label removes every "Hebrides Cyber"), rendered by `/api/generate-report`, "↓ Executive PDF" button on the scan page (`executiveReportClient.ts`). Not plan-gated yet (the route never was) |
| Reflected-XSS confirmation | `xssConfirm.ts` + `validateExploit` (`proofOfExploit.ts`): one harmless GET probe, context-aware verdict (body / quoted attribute confirmed; encoded, comment, script, textarea, title not), optional browser check. **Not yet called from a scan**: `enrichWithProofOfExploit` has no production caller, so wiring it (opt-in) is the next step |
| Page metadata for client-component routes | `pricing/`, `contact/`, `login/` layouts (own title/description; login noindex); `/agencies` added to the sitemap |
| commix parser from a real run | `commixOutput.ts`, `fixtures/commix/`; unfinished/unreachable runs are `error`, nothing to test is `not_applicable` |
| Site crawler with page-level checks on every page (E-70) | `crawler.ts`, `crawlFindings.ts`, `crawl` in `ScanResults`; script inventory merges inner-page origins |
| Pull-request dependency checks (E-71) | `POST /api/v1/dependency-diff`, `dependencyDiff.ts`, Action `mode: dependencies` |
| End-of-life detection; certificate checks (incl. subdomains); TLS now reads broken certs | `endOfLife.ts`, `subdomainCerts.ts`, `tls.ts` |
| Fix-PR repo-ownership check; multi-repo scans; Playwright on scan runners | commit 3180aa6 |
| Report fixes: security.txt not an "exposed file"; one compliance badge per framework | commit a91ad40 |

Coverage floor (`vitest.config.mts`): **67 / 60 / 68 / 68** (statements /
branches / functions / lines). Lint: 0 errors (31 known warnings).

## Rules that kept biting — follow these

1. **Gate = four commands, check exit codes, not summary lines.** From
   `hebridescyber-app/`: `npm run lint` (0 errors), `npx tsc --noEmit` (no
   output), `npm run test:unit:coverage`, `npm test`. Vitest prints
   "N passed" even when an *unhandled error* fails the run — a line
   `Errors  1 error` means failure. CI type-checks PRs merged into master,
   so rebase onto the latest master before trusting a local pass.
2. **Never return a value from a `beforeEach`/`afterEach` arrow.**
   `beforeEach(() => mock.mockReset())` returns the mock, and Vitest runs a
   returned function as a cleanup hook — it called the mock with no
   arguments and failed CI. Use a block body.
3. **Windows line endings.** Many files are CRLF; string-replace scripts that
   assume `\n` silently miss. Use the Edit tool, and avoid passing `\n`
   escapes through shell heredocs (they get mangled).
4. **Evidence discipline.** A failed lookup is `status: "error"`, never an
   empty "checked" — `findingLifecycle.ts` would otherwise mark last scan's
   findings fixed and close their tickets. New base-suite checkId prefixes
   that don't normalise to their `ScanResults` key need a `BASE_ALIASES`
   entry; extended tools need `TOOL_ALIASES` (see CLAUDE.md).
5. **Coverage floor only goes up**, to the measured value, after merging.
6. **Generate `www` URLs** (`process.env.NEXT_PUBLIC_SITE_URL ??
   "https://www.hebridescyber.co.uk"`); the bare domain only redirects.
7. **One build at a time.** Parallel subagents exhausted the usage limit
   three times; local and cloud sessions share the same allowance. Give any
   scratch file a unique name — two builds overwrote each other's PR body.
8. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
   PR bodies end with the Claude Code attribution line. Draft PR, wait for
   CI, squash-merge, watch the `Deploy` run.

## The next three features, in order

### ~~1. E-70 — Site crawler~~ — shipped (see "Where things stand")

Kept for reference; not yet covered by the crawler: login recording for the signed-in crawl (slice 1 uses a saved cookie/Basic credential, see docs/AUTHENTICATED-CRAWL.md), JS-rendered link discovery (a SPA's client-side routes), per-page SRI/cookies for pages behind forms.

**Why:** most checks look only at the homepage. Headers, error disclosure,
SRI, script inventory, cookies and mixed content never see `/login`,
`/checkout` or `/contact`. Intruder, Detectify and Invicti crawl first. This
is the biggest single detection gain available.

**Design:**
- New base module `src/lib/scanners/crawler.ts`: breadth-first from the
  target, same registrable origin only, **read-only GETs**, honours
  `robots.txt` (reuse `webapp.ts`'s robots parsing), cap ~50 pages and depth
  3, concurrency ≤4, per-request `AbortSignal.timeout`, total time budget
  (~45 s on-demand). Sources: `<a href>`, `<form action>` (record, never
  submit), sitemap.xml URLs (`robots.sitemapUrls`), and the existing
  Wayback live URLs. Skip logout/delete-looking links and binary types.
  Normalise URLs (strip fragments, sort/limit query params) to avoid traps.
- Store `ScanResults.crawl = { status, pages: [{url, status, contentType, title}], truncated }`.
- Run the page-level checks per crawled page and aggregate by **checkId
  key + page**, de-duplicated so one site-wide header gap is one finding
  listing affected pages (not 50 findings). Start with: security headers
  (`headers.ts` `buildHeaderAnalysis`), cookie flags, mixed content, SRI and
  script inventory (`scriptInventory.ts` per page, origins merged), error
  disclosure on real 404s, forms posting over HTTP / password fields
  without HTTPS.
- Keep checkIds stable: site-wide findings keep their current ids; new
  page-specific ones use `<module>.<check>:<path>` capped at N pages.
- Lifecycle: `crawl` status `partial`/`error` must not resolve page findings.

**Tests:** fixture site via stubbed `fetch` (links, loops, robots
disallows, off-origin links, sitemap, traps), caps and budget, aggregation.
**Done when:** a scan of a multi-page fixture reports issues found only on
inner pages; our own site still scores the same or better; docs updated.

### ~~2. E-71 — Pull-request dependency checks~~ — shipped (see "Where things stand")

Not yet covered: lockfile-less PRs (manifest-only changes), a GitHub App for fork PRs' comments, and pinning a PR's finding to the exact changed line.

### ~~3. E-72 — Fix sqlmap result reading~~ — shipped; xsser retired; commix parser outstanding

`sqlmap.ts` now reads sqlmap's real output (`sqlmapOutput.ts`, tested against
captured output in `src/worker/tools/fixtures/sqlmap/`): an unreachable target
or unfinished run is `error`, nothing to test is `not_applicable`, never clean.
`tool-integration.yml` runs the real sqlmap against `tests/fixtures/test-app`
(passed on a GitHub runner) and captures commix output into the job log.
**xsser was retired**: the CI capture showed it is not installable on the runner
image (no apt package on Ubuntu 24.04; the pip build of 1.9 crashes at import
because it only runs from inside its source checkout), so it had only ever
returned `not_configured`. ZAP covers XSS; reflected-XSS confirmation is planned
for `proofOfExploit.ts`.
**Next:** write `commixOutput.ts` + fixtures from the captured commix v4.2 run
(negative case: `[warning] GET parameter 'q' does not seem to be injectable`,
`[critical] All tested parameters do not appear to be injectable…`; needs
`--batch`), with the same evidence rules as `sqlmap.ts`.

### 4. E-73 — Scanner accuracy benchmark suite

**Why:** "industry grade" needs measured precision/recall, and every recent
bug here was a false positive or a silent miss that tests built on
assumptions didn't catch.
**Design:** `bench/` with a corpus of targets that exercise known findings:
local containers (OWASP Juice Shop, a Next.js/Express/PHP fixture app with
seeded misconfigurations), badssl.com hosts for TLS, and recorded HTTP
fixtures for anything external. An expectations file lists, per target,
checkIds that **must** appear and ones that **must not**. A workflow runs it
weekly and on scanner changes, and prints precision/recall per module,
failing on regressions.
**Done when:** the suite runs in CI with a baseline report, and at least
one known false positive class (e.g. SPA catch-all) is a must-not case.

**Status (E-73):** first slice built on branch `claude/e73-benchmark`: `bench/`,
`npm run bench`, `.github/workflows/benchmark.yml`. It covers the base checks
that run offline against 12 local fixture sites (SPA catch-all, soft-404 and
redirect-all must-not cases included); the Juice Shop / badssl.com job is
opt-in and informational (`bench:network`). It already surfaced two real
defects, tracked as `knownIssues`: nginx autoindex is missed (`directoryListing.ts`
requires "Parent Directory") and `no-rate-limit` fires on redirect-everything
sites. Not yet covered: DNS, ports, recon and the extended tools.

### 5. E-74 — Cross-site findings view with bulk triage

**Why:** everything is per scan. Agencies and anyone with several sites
need one list: all open findings across all sites, filterable and
groupable, with bulk actions.
**Design:** new `/dashboard/findings` page reading `finding_lifecycle`
(open rows) joined with the latest scan's finding detail and
`finding_triage`; filters by site, severity, KEV/EPSS, category, triage
state, age/SLA; group by check (e.g. "missing HSTS on 7 sites"); bulk
triage via the existing bulk `PUT /api/findings/triage`; CSV export.
Add to `AppNav.tsx` `NAV_ITEMS`. Authenticated e2e for it (see below).
**Status:** page, API (`GET /api/findings`), bulk triage and CSV export are built with unit/component tests (see CLAUDE.md "Cross-site findings view"); only the authenticated e2e is outstanding, owned by the e2e branch.
**Done when:** one page shows every open finding across sites, a bulk
"authorise these 5 script sources" works, and it has e2e coverage.

## Next five (planned 2026-10-05, from the competitor analysis and the DeepSeek/Copilot reviews)

1. **Confirmed-exploitable findings**: done (see "Where things stand").
2. **Guided onboarding and dashboard UX**: one add-site, verify, scan flow; Run scan disabled with a reason until the domain is verified; prominent empty-state "Start scan"; dashboard quick actions; Trends and SLAs grouped under Compliance. About 1.5 sessions.
3. **Continuous attack-surface monitoring**: wire `easmDiscovery.ts` into the scheduled pipeline, keep a per-site asset ledger, alert on new and disappeared assets, feed `takeover.ts`. About 1.5 sessions.
4. **Lookalike-domain and phishing watch**: typo and homoglyph permutations checked with passive DNS, flag registered ones, MX records first. Pro and Agency. About 1 session.
5. **Cyber Essentials evidence pack**: a self-attested checklist for the controls a scan can't see, kept apart from the automated score, exported alongside the scan results through `executiveReport.ts`. About 2 sessions. Runner-up: DMARC aggregate-report processing.

Not code (owner's call): hero copy, an NCSC Web Check / Mail Check replacement landing page, separate SaaS and local-business entry points.

## Also queued (smaller, pick up between the five)

- **Authenticated e2e tests** for the dashboard, report and triage (today's
  9 e2e tests cover public pages only).
- **Real Postgres tests** for RLS and migrations: done as `tests/db/` + `db-tests.yml` on plain Postgres with a Supabase shim, see CLAUDE.md "Testing strategy". Remaining: extend the RLS matrix to the tables not yet covered (ticket_integrations, sla_policies, organisations/RBAC, report_shares).
- ~~Authenticated e2e tests~~ — done: dashboard, scans/start-scan, report and
  triage run signed-in and hermetic (`tests/e2e/*-auth.spec.ts`; how it works
  is under "Testing strategy" in `CLAUDE.md`). Not yet covered: `/account`,
  `/admin`, `/dashboard/assets|sla|integrations`, the report's Fix Wizard and
  the `/diff` page.
- **Real Postgres tests** for RLS and migrations (Supabase CLI local stack in CI).
- **Cross-tool duplicate findings** (nuclei, ZAP and our checks reporting the same issue).
- **Evidence on findings** — the request/response that proves each one.
- `findingsDiff.ts` passive-after-full gap: an on-demand scan after a
  scheduled one reports active-tool findings as "Fixed" (affects ticket
  auto-close; lifecycle is already correct).
- E-63 continuous EASM, E-65 lookalike domains, E-66 DMARC reports.
- `/methodology` page; the five-part briefing document (marketing/).
- Per-target repo mapping (today the newest connected repo is scanned).

**Cross-tool duplicates (done, `claude/dedupe-findings`):** `findingConsolidation.ts` merges extended-tool duplicates into the canonical finding (`corroboratedBy`). Still open: the table covers only issues with a confident id mapping (headers/HSTS/CSP, TLS, a few exposures, CVE-bearing library findings) — extend `EQUIVALENCES` as real nuclei/ZAP output confirms more ids; sqlmap/xsser/ZAP injection findings need parameter/URL evidence in their checkIds before they can be matched; our own overlapping checks (`tls.hsts-missing` vs `headers.missing-critical`) are deliberately not merged.
- SAST: Koa `ctx`, FastAPI typed params, more languages (E-69 follow-ups).
- Emerging threats: WordPress plugin matching; re-alert when
  "possibly affected" becomes "affected".
- `deploy.yml`'s post-deploy health step uses `if: env.SITE_URL != ''` with
  `SITE_URL` set only in the step's own `env`, which the step `if` can't
  see — check the step actually runs once the `SITE_URL` secret exists.

## Owner actions pending (not code)

- Add DNS **CAA** record at GoDaddy: `0 issue "digicert.com"` → own site 100/100.
- **Replay** the own-site scan (the 61/100 report predates the fixes; current code scores 98).
- GitHub secret **`SITE_URL`** = `https://www.hebridescyber.co.uk`.
- Optional secret **`NVD_API_KEY`** (faster emerging-threat lookups).
- **Stripe (E-07)** — `/api/health` is "degraded" until it's configured; blocks paid sign-ups.
- Sentry DSN (E-03), staging Supabase, branch protection (needs GitHub Pro).
