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
Database migrations are applied through **046**; the next free number is **047**.

| Shipped | Where |
|---|---|
| Emerging-threat alerts (E-68) | PR #1 — `emergingThreats.ts`, `emergingThreatAlerts.ts`, `emerging-threats.yml` (every 6 h), migration 045 |
| Lockfile + transitive dependency scanning, inventory SBOM (E-67) | PR #2 — `dependencyLockfiles.ts`, `lockfileSyntax.ts`, `ecosystemVersion.ts`, `osv.ts` querybatch |
| SAST with Opengrep + our own 34-rule pack (E-69) | PR #3 — `src/worker/tools/sast.ts`, `sast-rules/`, `repoClone.ts`, `sast-rules.yml` |
| Third-party script inventory, PCI 6.4.3/11.6.1 (E-62) | PR #4 — `scriptInventory.ts`; `info` on ordinary pages, `low` on payment pages (owner decision) |
| Finding triage: accept/authorise, false positive, snooze (E-64) | PR #5 — `finding_triage` (046), `/api/findings/triage`, report UI; only false positives leave the score |
| Site crawler with page-level checks on every page (E-70) | `crawler.ts`, `crawlFindings.ts`, `crawl` in `ScanResults`; script inventory merges inner-page origins |
| Pull-request dependency checks (E-71) | `POST /api/v1/dependency-diff`, `dependencyDiff.ts`, Action `mode: dependencies` |
| End-of-life detection; certificate checks (incl. subdomains); TLS now reads broken certs | `endOfLife.ts`, `subdomainCerts.ts`, `tls.ts` |
| Fix-PR repo-ownership check; multi-repo scans; Playwright on scan runners | commit 3180aa6 |
| Report fixes: security.txt not an "exposed file"; one compliance badge per framework | commit a91ad40 |

Coverage floor (`vitest.config.mts`): **65 / 59 / 67 / 67** (statements /
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

Kept for reference; not yet covered by the crawler: authenticated crawling, JS-rendered link discovery (a SPA's client-side routes), per-page SRI/cookies for pages behind forms.

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

### ~~3. E-72 — Fix sqlmap result reading~~ — sqlmap shipped; xsser outstanding

`sqlmap.ts` now reads sqlmap's real output (`sqlmapOutput.ts`, tested against
captured output in `src/worker/tools/fixtures/sqlmap/`): an unreachable target
or unfinished run is `error`, nothing to test is `not_applicable`, never clean.
`.github/workflows/tool-integration.yml` runs the real sqlmap against
`tests/fixtures/test-app` and uploads xsser's raw output as an artifact.
**Next session:** download that artifact, write `xsserOutput.ts` + fixtures from
the real text, and apply the same evidence rules to `xsser.ts` (and `commix.ts`,
also unverified).

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
**Done when:** one page shows every open finding across sites, a bulk
"authorise these 5 script sources" works, and it has e2e coverage.

## Also queued (smaller, pick up between the five)

- **Authenticated e2e tests** for the dashboard, report and triage (today's
  9 e2e tests cover public pages only).
- **Real Postgres tests** for RLS and migrations (Supabase CLI local stack in CI).
- **Cross-tool duplicate findings** (nuclei, ZAP and our checks reporting the same issue).
- **Evidence on findings** — the request/response that proves each one.
- `findingsDiff.ts` passive-after-full gap: an on-demand scan after a
  scheduled one reports active-tool findings as "Fixed" (affects ticket
  auto-close; lifecycle is already correct).
- E-63 continuous EASM, E-65 lookalike domains, E-66 DMARC reports.
- `/methodology` page; the five-part briefing document (marketing/).
- Per-target repo mapping (today the newest connected repo is scanned).
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
