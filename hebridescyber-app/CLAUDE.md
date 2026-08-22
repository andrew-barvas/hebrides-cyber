# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev          # Start dev server (Next.js 16 + Turbopack, port 3000)
npm run build        # Production build
npm run lint         # ESLint
npx tsc --noEmit     # TypeScript check — build does NOT run tsc, always run this separately
npm test             # Playwright e2e (builds app + starts server automatically — slow, hermetic)
npm run scan:local   # Run a real scan against a URL and persist to Supabase (needs SCAN_OWNER_ID)
npm run seed:users   # Create demo accounts in Supabase (admin, basic/pro/agency/no-plan)
```

## Environment

Copy `.env.example` to `.env.local`. Minimum to boot locally:

```
NEXT_PUBLIC_SUPABASE_URL=https://<project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon-key>
```

Without those, the app boots but all auth/data calls fail. The Supabase client logs a warning and uses a placeholder rather than throwing.

## Architecture

### One API layer

**`src/pages/api/`** — every server-side route, including the scan pipeline (`run-scan`, `verify-ownership`, `generate-report`, `generate-fix-pr`), Stripe webhooks/checkout/portal, admin panel endpoints, and the contact form. Runs as Next.js API routes deployed to Azure Static Web Apps (Oryx auto-deploys them as managed Functions behind the CDN) — there is no separate standalone Azure Functions app. The daily blog and weekly newsletter are **not** API routes — see "Content generation" below for why. There used to be one (`src/functions/`); it was never actually deployable (no `host.json`, no real `@azure/functions` registration) and got fully consolidated here — see `src/pages/api/run-scan.ts`'s header comment and `docs/PLATFORM-ROADMAP.md`'s "17 Aug" note. All of `src/pages/api/` has access to `NEXT_PUBLIC_*` env vars alongside server-only vars, and uses `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (server-only) directly for privileged operations — never the anon key.

### Two routers in one Next.js app

- **App Router** (`src/app/`) — all pages and layouts
- **Pages Router** (`src/pages/api/`) — API routes only

### Supabase access pattern

| Context | Client | Key used |
|---------|--------|----------|
| Browser (dashboard, login) | `src/lib/supabaseClient.ts` | anon key — RLS enforced |
| API routes & Functions | `createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)` | service role — bypasses RLS |
| Admin API routes | service role for writes; anon client to verify the caller's JWT | both |

`SUPABASE_SERVICE_ROLE_KEY` must never appear in a `NEXT_PUBLIC_*` var or any client bundle.

### Scan flow (two-step proof of ownership, queue-backed)

1. Dashboard POSTs `{ targetUrl }` to `/api/run-scan` → creates a `scans` row (status `pending`) and returns `{ scanId, proofToken }`. Rejected with 402 if the caller is on the free tier and has already used their one free scan (`src/lib/freeTier.ts`) — admins exempt.
2. Dashboard POSTs `{ scanId }` to `/api/run-scan` → verifies domain ownership (real DNS/file verification, required by default — admins exempt, see `src/lib/ownership.ts`'s `isDomainVerified`), then **enqueues** a `scan_jobs` row and returns `202 { status: "queued" }`. It does not run the scan pipeline inline — a real production scan once exceeded Azure Static Web Apps' Free-tier Functions execution ceiling and returned a proxy error instead of JSON, so nothing calls `executeScan()` synchronously from an HTTP request anymore. `src/lib/onDemandScanTrigger.ts`'s `triggerOnDemandWorkflow()` immediately dispatches `.github/workflows/on-demand-scan.yml` via the GitHub API (needs `GITHUB_PAT`) so the job is usually picked up within about a minute; if that dispatch fails or the token isn't set, the job still gets picked up by the next `scheduled-scans.yml` cron as a fallback. The dashboard polls step 2 again to see `queued` → `running` → `completed`/`failed`. Replaying step 2 against an already-`completed` scan returns the cached result instead of re-queuing.

`POST /api/v1/scans` (the public API) enqueues the same way and also returns `202` immediately — `action/index.js` (the packaged GitHub Action) and `docs/API.md` both poll `GET /api/v1/scans/{id}` rather than expecting a synchronous report.

`executeScan()` (`src/lib/scanExecution.ts`) is the single implementation that actually runs a scan, called only by the queue workers (`src/scripts/run-queued-scan-jobs.ts`) — never directly from a request handler. It always runs the base passive check suite; pass `runExtendedTools: true` to also run the active-tool suite (see "Scanner pipeline" below). Only jobs enqueued by `scheduled-scans.yml` get that flag — on-demand jobs from `run-scan.ts`/`v1/scans.ts` stay passive-only, distinguished by whether `scan_jobs.scan_id` arrives pre-set (see `run-queued-scan-jobs.ts`'s `runOne()`).

`ALLOW_DEV_TOKEN_VERIFICATION` defaults to unset/`false` (real DNS/file verification required). Set it `true` only for local dev, to use the `X-Scan-Token` echo shortcut instead.

### Scheduled + on-demand queue (Postgres, no Redis)

Both scan-triggering paths share one Postgres-backed queue (`sql/migrations/008_scan_jobs.sql`) worked by ephemeral GitHub Actions runners — deliberately not BullMQ/Redis (an earlier `src/worker/` attempt along those lines was built, never wired to a real Redis instance, and later deleted once this replaced it).

- **Scheduled**: `.github/workflows/scheduled-scans.yml` cron → `src/scripts/enqueue-scheduled-scans.ts` inserts one `scan_jobs` row per verified target that's due (see "Scan cadence by plan" below), then a matrix of worker shards (`src/scripts/run-queued-scan-jobs.ts`) claim jobs via the `claim_scan_job()` RPC (`SELECT ... FOR UPDATE SKIP LOCKED` — needed because PostgREST can't express locking clauses) and run them with `runExtendedTools: true`. This is the only place the real active-scanning tools run — the workflow installs nmap/sqlmap/nuclei/testssl.sh/gitleaks and starts a ZAP daemon fresh each time.
- **On-demand**: `.github/workflows/on-demand-scan.yml`, a lighter sibling that skips those tool installs, dispatched immediately by `triggerOnDemandWorkflow()` (see above). Jobs it picks up run passive-only.

### Scan cadence by plan

`src/lib/scanCadence.ts`'s `isScanDue(plan, lastCompletedScanAt, now)` — Basic gets weekly, Pro/Agency get daily (matching the once-a-day `scheduled-scans.yml` cron; there's no faster-than-daily tier without a second cron). Pure/sync so it's unit-testable without touching Supabase — `enqueue-scheduled-scans.ts` does the DB lookup and passes the result in.

### Scanner pipeline

`src/lib/scanners/` — two tiers, not one flat list.

**Base passive suite** — always runs, on every scan regardless of plan or repo connection. Wired into `runAllChecks()`/`summariseResults()` in `src/lib/scanners/index.ts`:
- `tls.ts` — certificate grade and expiry
- `headers.ts` — security header presence, CSP grading, cookie flags, CORS, info disclosure
- `dns.ts` — SPF, DMARC, DKIM (best-effort selector guessing), MTA-STS (DNS record + live policy-file fetch), TLS-RPT, CAA, DNSSEC. MTA-STS/TLS-RPT only get evaluated when the domain has MX records — silent otherwise, not a false "missing"
- `exposure.ts` — sensitive paths (.env, .git, phpinfo, etc.), security.txt presence
- `directoryListing.ts` — autoindex detection, reuses `httpProbe.ts`'s baseline/masking
- `cloudMisconfig.ts` — public S3/Azure Blob/GCS buckets, but only ones the target's own page source references
- `fingerprint.ts` — technology detection (WordPress etc.)
- `ports.ts` — common open ports via Shodan InternetDB
- `recon.ts` — IP resolution, Shodan CVEs, crt.sh subdomain enumeration
- `webapp.ts` — robots.txt, HTTP OPTIONS, error disclosure, WordPress/Joomla/Drupal deep scan, CORS reflected-origin, JS library versions (CVE-enriched via `osv.ts`), Subresource Integrity on cross-origin `<script>`/`<link rel=stylesheet>` tags (same-origin resources are never flagged — SRI protects against a compromised third party, not the site's own origin)
- `safeBrowsing.ts` — Google Safe Browsing malware/phishing check (needs `GOOGLE_SAFE_BROWSING_API_KEY`; `not_configured` without it)
- `waybackDiscovery.ts` — checks historical URLs from the Wayback Machine CDX API that still resolve live, surfacing forgotten endpoints a fresh crawl can't find
- `hibp.ts` — HaveIBeenPwned domain breach check (needs `HIBP_API_KEY`; `not_configured` without it)
- `wpvdb.ts` — matches `webapp.ts`-detected WordPress plugin versions against the real WPScan Vulnerability Database (needs `WPSCAN_API_TOKEN`; `not_configured` without it). Runs after `webapp` resolves, not in the main `Promise.all` batch, since it needs `webapp.wordpress.plugins` as input — enrichment only, does no detection of its own.
- `playwright.ts` — headless browser checks (needs Playwright's browser binaries installed — CI installs them explicitly; a bare local `tsx` run of this without `npx playwright install` will show `status: "error"`, not a real bug)
- `zap.ts` (inline in `index.ts`, not its own file) — kicks off an async ZAP spider if `ZAP_API_URL` is set; the real active ZAP *scan* is a separate module below

**Extended active-tool suite** — opt-in only, via `runExtendedTools()` in `src/lib/scanExecution.ts`, gated behind `ExecuteScanOptions.runExtendedTools` (only `run-queued-scan-jobs.ts` sets it, only for scheduled jobs — see "Scan flow" above). Real binaries/daemons that only exist in that GitHub Actions job:
- `src/worker/tools/{nuclei,zap,sqlmap,nmap}.ts` — real active scans, ported out of the deleted BullMQ worker
- `subdomains.ts` — Subfinder subdomain discovery (supersedes `recon.ts`'s lighter crt.sh-only finding when it finds anything)
- `deepTls.ts` — testssl.sh
- `secretScan.ts`, `dependencyManifest.ts`, `dockerBaseImage.ts` — all three require a connected GitHub repo (`repo_connections` table, `sql/migrations/009_repo_connections.sql`, set via `src/pages/api/account/connect-repo.ts`); each returns a clean `not_applicable`/`not_configured` result with no repo rather than an error. `secretScan.ts` runs Gitleaks against repo contents; `dependencyManifest.ts` checks whichever of `package.json` (npm), `requirements.txt` (pip), and `composer.json` (Composer) exist at the repo root — all three independently, findings combined — reading each manifest's declared ranges (no lockfile fetch) and checking the lowest resolvable version against OSV.dev via `lookupCveIds(ecosystem, ...)`, which accepts any OSV ecosystem string (`"npm"`/`"PyPI"`/`"Packagist"`); `dockerBaseImage.ts` extracts a `Dockerfile`'s base image tag and checks it the same OSV.dev-backed way.

When adding a new check to either tier: export its result type from the module, add it to `ScanResults` (base) or the `extended` object (extended tier), and push `Finding` entries with a stable `checkId` (`"<module>.<check-name>"`, or `"<module>.<check-name>:<key>"` in a loop) — `src/lib/findingsDiff.ts` matches on this to tell "new" from "unchanged" between two scans of the same target, so an untagged finding never participates in diffing.

Import the base pipeline as `@/lib/scanners` (the directory). A single-file `src/lib/scanners.ts` used to sit alongside it and **shadowed the directory in module resolution**, so every entry point silently ran an old 4-check version. It has been deleted — do not recreate a file at that path.

**Remediation text** lives in `src/lib/scanners/remediationText.ts` and is attached to each finding as `Finding.remediation` at the point the finding is created, where the check result is still in scope. The field is optional because scans stored before it existed deserialise without it, so any consumer must guard. Never re-derive which fix applies by string-matching a finding's title.

**False positives.** `exposure.ts` fetches a random-slug URL alongside the site root to learn what a "not found" response looks like, masks the probed path out of both bodies, and discards any probe whose body matches that baseline. Without this, every SPA that returns its shell for unknown paths reports an exposed `.env`. Any new check that probes for a file must reuse `fetchBaseline`/`normaliseBody` (`httpProbe.ts`) rather than trusting a 200 status.

### Real remediation PRs vs AI-tailored fixes vs static remediation text

Three distinct, non-overlapping "help me fix this" features — don't conflate them:
- `remediationText.ts` — static markdown, attached to every finding unconditionally (see above).
- `src/lib/aiRemediation.ts` / `POST /api/scans/[id]/ai-fix` — on-demand, per-finding, sends the finding + detected tech stack to Azure OpenAI for a stack-specific fix (only live if `AZURE_OPENAI_*` is configured).
- `POST /api/generate-fix-pr` — opens a real GitHub pull request. Auth resolves via `src/lib/githubApp.ts`'s `resolveGithubAuth(githubRepo)` (see below); for dependency findings it bumps the actual version in `package.json` (via `osv.ts`'s `lookupOsvFixInfo`), not just a recommendations file.

### GitHub access for customer repos

`src/lib/githubApp.ts`'s `resolveGithubAuth(githubRepo)` is the one function every customer-repo-touching module calls (`generate-fix-pr.ts`, `secretScan.ts`, `dependencyManifest.ts`, `dockerBaseImage.ts`, `connect-repo.ts`) — never read `process.env.GITHUB_PAT` directly in a new one. It tries a GitHub App installation token first (per-repo, expires in an hour, resolved live via `GET /repos/{owner}/{repo}/installation` — no webhook or install-callback flow needed), falling back to the shared `GITHUB_PAT` when the App isn't configured or isn't installed on that repo. `GITHUB_PAT` is also used, unrelated to any of this, by `src/lib/onDemandScanTrigger.ts` to dispatch this repo's own `on-demand-scan.yml` — don't conflate the two concerns when reasoning about that token's scope.

### Content generation: daily blog + weekly newsletter

Two genuinely separate, independently-scheduled posts — not one replacing the other — sharing real-event sourcing in `src/lib/newsletter.ts`:
- **Daily** (`generateDailyBlogPost`, run by `src/scripts/generate-daily-blog.ts`, `.github/workflows/daily-blog.yml` at 07:00 UTC every day) — narrower lookback (KEV 7d / NVD 1d / news 2d), slug `cyber-brief-YYYY-MM-DD`.
- **Weekly** (`generateWeeklyNewsletterPost`, run by `src/scripts/generate-weekly-newsletter.ts`, `.github/workflows/weekly-newsletter.yml` at 07:00 UTC every Monday) — full 7-day window on everything, fuller own-scan-stats section, slug `week-of-YYYY-MM-DD`.

Both real-event sources, no fabrication: CISA's Known Exploited Vulnerabilities catalog (`fetchRecentKevEntries`), high-severity CVEs from the NVD API (`fetchRecentHighSeverityCves`, CVSS ≥ 7.0, no key needed at this volume), and a curated set of security-news RSS feeds parsed with hand-rolled regex extraction, not a dependency (`fetchRecentSecurityNews` — The Hacker News, BleepingComputer, Krebs on Security), de-duplicated by normalised title across feeds. AI narrative write-up if `AZURE_OPENAI_*` is configured, otherwise a deterministic templated post from the same fetched data — either path always publishes something rather than silently skipping a day/week.

**Not API routes.** Both used to be `POST /api/generate-daily-blog` / `POST /api/generate-newsletter`, curled from their workflows with a shared `NEWSLETTER_SERVICE_TOKEN` — the same "GitHub Actions → Next.js API route on Azure" pattern the scan pipeline used before it hit Azure Static Web Apps' Free-tier Functions execution ceiling. A real run of `daily-blog.yml` hit the identical failure (`"Backend call failure"` after 46s — see `src/scripts/generate-daily-blog.ts`'s header), so both were converted the same way `run-scan.ts` was: the workflow runs the script directly against Supabase (`SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY`, same credentials pattern as `run-queued-scan-jobs.ts`), no HTTP hop through Azure at all. The two API routes are deleted, not kept as a fallback. `NEWSLETTER_SERVICE_TOKEN` is still live — `send-monthly-digest.ts` uses it for a different, deliberately-still-HTTP route (it sends real customer email, so stays gated behind an endpoint rather than becoming a bare script).

Deliberately not a Supabase Edge Function either: this app has exactly one pattern for scheduled work now (GitHub Actions running a script directly against Supabase — matches `scheduled-scans.yml`), and a second execution environment with its own secrets to keep in sync is a cost already paid once (the deleted standalone Azure Functions app) and not worth reintroducing.

### Audit log

`src/lib/audit.ts`'s `logAuditEvent(supabaseAdmin, event)` is the one shared writer for the `audit_logs` table, called from `scanExecution.ts` (`scan.started`/`scan.completed`/`scan.failed`) and the Stripe webhook (which also (ab)uses the same table as an idempotency ledger for Stripe event ids). Best-effort by design — logging a security event must never be the reason the action it describes fails, so every call site `await`s it but never lets its result gate anything. `action` values follow a stable `"<resource>.<verb>"` vocabulary since the admin Audit tab's search filters on it — keep new call sites consistent with existing ones rather than inventing new verb shapes.

### Vertical landing pages

`src/app/{tourism,churches,local-trades}/page.tsx` — SEO/positioning content, not scanner or pricing logic. Reuses the same components and CSS tokens as the rest of the marketing site; no new abstractions were introduced for these.

### Theme system

Tailwind `darkMode: 'class'`. `ThemeScript` in `src/app/layout.tsx` adds `dark` to `<html>` on load unless `localStorage.getItem('hc-theme') === 'light'`. Default is dark (cyber theme).

**The cyber tokens are CSS variables, not fixed hex.** `tailwind.config.cjs` maps them to `rgb(var(--c-*) / <alpha-value>)`, and the `:root` / `.dark` blocks in `src/app/globals.css` hold the two palettes. This is what makes light mode work: any surface built from these tokens re-themes automatically, with no `dark:` variant on any of the ~700 usages.

| Token | Role | Light | Dark |
|-------|------|-------|------|
| `cyberbg` | page background | `#F6F7F9` | `#070B14` |
| `cyberpanel` | card/panel background | `#FFFFFF` | `#0D1524` |
| `cyberborder` | borders on panels | `#D6DCE4` | `#1C2940` |
| `cybertext` | primary body text | `#2F3A44` | `#FFFFFF` |
| `neon` | accent, links, glow | `#067A5B` | `#39FFC0` |

Rules when adding UI:

- **Never use `text-white` on a themed surface** — it cannot follow the theme and turns invisible in light mode. Use `text-cybertext`. `text-white` is correct only on a permanently dark background such as `bg-atlantic`.
- Same for `bg-white/N` and `border-white/N` overlays — use `bg-cybertext/N`.
- Fixed brand colours (`atlantic`, `seafoam`, `heather`, `slatedark`, `slatelight`) do not change between themes. Pair them with an explicit text colour rather than letting text inherit.
- Low-opacity steps of `cybertext` and `neon` get an alpha boost in light mode (the parity block in `globals.css`). Alpha tuned for white-on-black reads far too faint as dark-on-light — `/40` would otherwise sit at ~2.1:1 contrast.
- `shadow-glow` / `shadow-glowsm` vary by theme too; the neon bloom is dialled right down in light mode.

### Database schema

Key tables (all in `sql/migrations/`):
- `users` — profile data keyed to `auth.users`; `is_admin` grants admin panel access
- `subscriptions` — plan, status, slack_webhook_url, brand_logo_url/brand_name (white-label, Agency-gated in app code not schema); kept in sync by Stripe webhooks
- `scans` + `scan_results` — scan records and findings/score; RLS-protected by owner
- `scan_jobs` — the on-demand + scheduled queue (`008_scan_jobs.sql`); `claim_scan_job()` RPC does the `SKIP LOCKED` claim
- `repo_connections` — one GitHub repo per user, gates `secretScan.ts`/`dependencyManifest.ts`/`dockerBaseImage.ts` (`009_repo_connections.sql`)
- `monitored_targets` — agency-tier sites for nightly scheduled scans
- `contact_enquiries` — contact form submissions; service-role only (no browser RLS policy)
- `verifications` — domain ownership tokens
- `blog_posts` — both the daily blog and weekly newsletter live here, differentiated only by slug prefix (`cyber-brief-` vs `week-of-`); a row needs both `status = 'published'` and `published_at` non-null to be publicly visible
- `audit_logs` — see "Audit log" below

RLS is enabled on all tables. The only code path that bypasses it is server-side code using the service role key.

### Rate limiting

`src/lib/rateLimit.ts` uses Upstash Redis (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`) for shared-state rate limiting across Function instances. Falls back to an in-memory `Map` in dev — not safe across instances; don't rely on it in production.

### Payments

Stripe webhooks at `src/pages/api/stripe/webhook.ts` update `subscriptions` on `checkout.session.completed`, `invoice.payment_failed`, and `customer.subscription.deleted`. Requires `STRIPE_WEBHOOK_SECRET` and the three `STRIPE_PRICE_*` env vars (see `.env.example`).

### E2E tests

Playwright config (`playwright.config.ts`) hardcodes `NEXT_PUBLIC_SUPABASE_URL=https://example-project.supabase.co` for all test runs — tests seed `localStorage` with `sb-example-project-auth-token` and mock `*.example-project.supabase.co` network requests. Never use real Supabase credentials in e2e tests; the hardcoded project ref must stay `example-project`.

### Deployment

Azure Static Web Apps hybrid mode (not pure static export). Every route (App Router pages, `pages/api/*`) is served by the managed Next.js server (Oryx-provisioned Functions), which bypasses `staticwebapp.config.json`'s `globalHeaders` entirely — confirmed by curling production and finding CSP/X-Frame-Options/etc. absent even on a 404, with only platform-level HSTS coming through. **Security headers are set in `next.config.mjs`'s own `headers()`**, which runs inside the Next.js response path and is what actually applies in production; `staticwebapp.config.json`'s `globalHeaders` is kept in sync as a fallback for any file served as a pure static asset without hitting the Next server, but is not load-bearing. Keep both files in sync if the header policy changes. `next.config.mjs` also sets `poweredByHeader: false`.
