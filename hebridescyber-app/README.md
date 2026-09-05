# Hebrides Cyber

Automated website security scanning for small businesses, SaaS teams, and
agencies: real TLS/header/DNS/exposure/CMS/dependency checks, scored
reports with specific remediation, scheduled monitoring, and a public API.
Marketing site, client dashboard, and every API route are one Next.js app
on Supabase, deployed to Azure Static Web Apps (Oryx auto-deploys the API
routes as managed Functions behind the CDN — no separate Functions app).

This is a live, production system, not a prototype. **See
[`docs/README.md`](docs/README.md) for a full documentation map** — which
doc answers which question. Quick pointers: what it actually does
(features, workflows, user stories) is
**[`docs/USER-GUIDE.md`](docs/USER-GUIDE.md)**; technical architecture is
[`docs/architecture.md`](docs/architecture.md); the security model is
[`docs/security.md`](docs/security.md); the public API is
[`docs/API.md`](docs/API.md); day-to-day development conventions are in
this same folder's `CLAUDE.md` (not the git root — this repo has two
roots, see below). The `marketing/` folder (one level up, outside this app
folder, alongside the primary `.github/workflows/`) has homepage copy,
pricing, and branding source material.

## Local Development

### Prerequisites
- Node.js 20+
- A Supabase project (free tier is fine) — [supabase.com](https://supabase.com)

### Setup

```bash
cd hebridescyber-app
npm install
cp .env.example .env.local
# then edit .env.local — at minimum set NEXT_PUBLIC_SUPABASE_URL and
# NEXT_PUBLIC_SUPABASE_ANON_KEY from your Supabase project's API settings
```

### Run the dev server

```bash
npm run dev
```

Visit http://localhost:3000. The marketing pages (`/`, `/services`,
`/pricing`, `/contact`, `/what-we-check`) work with no configuration.
`/dashboard` shows a "sign in required" state until you connect a real
Supabase project and sign in.

### Set up the database

In your Supabase project's SQL editor, run every file under
`sql/migrations/` **in order** (`001_init.sql` through the highest-numbered
file present) — each is additive and safe to re-run. Never edit an already-
applied migration; add a new numbered file instead.

### Run a scan locally without the dashboard

```bash
npm run scan:local -- https://example.com
```

Runs the real base passive scanner suite (`src/lib/scanners/`) directly,
no Azure/queue involved — useful for iterating on scanner logic. Prints
JSON + a 0–100 score to the console. Set `SUPABASE_URL`,
`SUPABASE_SERVICE_ROLE_KEY`, and `SCAN_OWNER_ID` to also persist the run
(handy for seeding test data). The extended active-tool suite
(nmap/nuclei/sqlmap/xsser/commix/ZAP, secret/dependency/Docker scanning) needs the real
binaries installed locally to do anything — see
`.github/workflows/scheduled-scans.yml` for exactly what it installs and
how, since that's the only environment that runs them today.

### Seed demo data

```bash
npm run seed:users     # admin + basic/pro/agency/no-plan demo customers (real, sign-in-able accounts)
```

Then run `sql/seed/001_blog_posts.sql` in the Supabase SQL editor to
populate `/blog` with sample posts.

`seed:users` prints an email list and a shared password at the end — sign
in at `/login`, toggle to password sign-in, and use those.
`admin@hebridescyber.com` has `is_admin` set and can see `/admin`. The
other four are pre-populated with different subscription tiers (or none)
so the dashboard's plan-aware upsell renders differently for each.

### Run the tests

```bash
npx playwright install --with-deps chromium   # first time only
npm run test                 # Playwright e2e
npm run test:unit            # Vitest unit/integration tests (see below)
npm run test:unit:coverage   # same, with a coverage report — see the
                              # threshold comment in vitest.config.mts
```

Playwright starts its own `next dev` server and runs against it — no
separate dev server or real Supabase project required for the
unauthenticated flows it covers. See `tests/e2e/` for what's exercised.
Vitest unit/integration tests are colocated as `*.test.ts`/`*.test.tsx`
next to the module they cover (e.g. `src/lib/scanCadence.test.ts`), except
API-route tests, which live under `src/__tests__/api/` — Next.js's Pages
Router treats every file under `src/pages/api/` as a route candidate
regardless of extension, so a test file can't live there without breaking
`npm run build`.

## Running a Scan via curl (the run-scan flow)

`run-scan` is a two-step, curl-able, **queue-backed** flow — see
`src/pages/api/run-scan.ts` and `docs/architecture.md` for the full
rationale (it used to run synchronously and hit Azure's Free-tier
Functions execution ceiling on a slow scan; every scan-running path was
moved off that pattern as a result). Replace `$SITE_URL` below with
wherever you're running it (`http://localhost:3000` for local dev — though
locally there's no queue worker running unless you start one manually with
`npm run queue:run-worker`).

**Step 1 — create the scan and get a proof token:**

```bash
curl -X POST "$SITE_URL/api/run-scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -d '{"targetUrl": "https://example.com"}'
# → { "scanId": "...", "status": "awaiting_verification", "proofToken": "..." }
```

**Step 2 — verify domain ownership first** (see below), then:

```bash
curl -X POST "$SITE_URL/api/run-scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -d '{"scanId": "<scanId from step 1>"}'
# → 202 { "ok": true, "scanId": "...", "status": "queued", "message": "..." }
```

Poll the same endpoint (same body) again to see `queued` → `running` →
`completed`, at which point it returns the score and summary. The
dashboard does all of this automatically, including showing the domain-
verification UI.

**Verify domain ownership** (required before step 2 succeeds, unless
`ALLOW_DEV_TOKEN_VERIFICATION=true` — local dev only, never production):

```bash
curl -X POST "$SITE_URL/api/verify-ownership" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -d '{"action": "start", "targetUrl": "https://example.com"}'
# → { "dnsRecord": {...}, "file": {...}, ... } — add the DNS TXT record or upload the file, then:
curl -X POST "$SITE_URL/api/verify-ownership" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -d '{"action": "check", "targetUrl": "https://example.com"}'
# → { "verified": true, "method": "dns" }
```

**Generate a PDF report** once a scan has completed (caller must own the
scan, or be an admin):

```bash
curl "$SITE_URL/api/generate-report?scan_id=<scanId>" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -o report.pdf
```

(Returns `{ url }` with a SAS link instead of raw PDF bytes if
`AZURE_STORAGE_CONNECTION_STRING` is configured.)

For the full public REST API (listing scans, exporting findings, score
trends, webhooks), see `docs/API.md`.

## How to Extend This App

- **Add a new marketing page:** create a folder under `src/app/<name>/`
  with a `page.tsx`, and add a link in `src/components/Header.tsx`.
- **Add a new base-suite scanner check:** add a `checkXyz()` function to
  `src/lib/scanners/`, call it from `runAllChecks()` in
  `src/lib/scanners/index.ts`, and push findings with a stable `checkId`
  in `summariseResults()`. Consider whether it maps to a compliance
  framework (`src/lib/scanners/compliance.ts`) and whether it belongs on
  `/what-we-check`.
- **Add a new extended-tool check:** wire it into `runExtendedTools()` in
  `src/lib/scanExecution.ts` instead — that tier only runs on the
  scheduled-scan path, where real binaries/credentials are available.
- **Change the report format:** edit `renderReportHtml()` in
  `src/pages/api/generate-report.ts`.
- **Add a pricing tier or Stripe product:** update
  `src/app/pricing/page.tsx`, create the corresponding Product/Price in
  the Stripe Dashboard, and handle the new plan in
  `src/pages/api/stripe/webhook.ts`.
- **Add a database table or column:** create a new file
  `sql/migrations/0NN_<description>.sql` — never edit an already-applied
  migration.

## Provisioning Azure Resources

Two options, see `azure/`:

- **Terraform** (`azure/terraform/main.tf`) — infrastructure as code.
  Needs a remote state backend configured before first use.
- **CLI script** (`azure/cli-scripts/provision.sh`) — faster for a first
  manual pass, including the GitHub-linked Static Web App setup that
  Terraform's provider doesn't fully cover.

`.github/workflows/terraform-security-scan.yml` runs Checkov against
`azure/terraform/` on every change to it, printing the full per-check
breakdown to the job's console log. **Not** also uploaded as SARIF to
GitHub's Security > Code scanning tab — that was tried and failed, because
Code Scanning requires GitHub Advanced Security on a private repo (a paid,
per-committer feature this account doesn't have); see the workflow file's
own header comment for the full story. Every current finding is triaged
directly in `main.tf`'s own comments (fixed, mitigated, or explicitly
accepted with a reason) — the scan passes clean, so a red run means a real,
untriaged finding.

There is also a ready-to-use prompt for handing this provisioning step to
a Claude agent with shell access: see `09-azure-provisioning-prompt.md`
one level up from this folder.

## GitHub Secrets

Set these under Settings > Secrets and variables > Actions on the repo:

| Secret | Used by |
|---|---|
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | `deploy.yml` — the whole app's deploy (site + every API route) |
| `NEXT_PUBLIC_SUPABASE_URL` | `deploy.yml` — build-time |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `deploy.yml` — build-time |
| `SUPABASE_URL` | `scheduled-scans.yml`, `on-demand-scan.yml`, `daily-blog.yml`, `weekly-newsletter.yml`, `monthly-digest.yml`, `data-retention-cleanup.yml` — all run scripts that query/write Supabase directly, no API route in between |
| `SUPABASE_SERVICE_ROLE_KEY` | same workflows, plus needed by any CI step that seeds/reads data |
| `GH_PAT`, `GH_APP_ID`, `GH_APP_PRIVATE_KEY` | `scheduled-scans.yml`'s extended tool suite (Gitleaks/dependency-manifest/Docker-base-image checks). **Not** named `GITHUB_PAT`/`GITHUB_APP_*` — GitHub hard-rejects any Actions secret starting with `GITHUB_`, so the workflow remaps these to that env var name internally. `GH_APP_ID`/`GH_APP_PRIVATE_KEY` are optional (GitHub App path, preferred); `GH_PAT` is the fallback |
| `WPSCAN_API_TOKEN`, `GOOGLE_SAFE_BROWSING_API_KEY`, `HIBP_API_KEY` | `scheduled-scans.yml` and `on-demand-scan.yml` — optional, each check degrades to `not_configured` when unset |

Also set a `NEXT_PUBLIC_SITE_URL` repo **variable** (Settings > Secrets and
variables > Actions > Variables — not a secret) — baked into Slack/Teams
alert links and the build.

The daily blog, weekly newsletter, and monthly digest run
`src/scripts/generate-daily-blog.ts` / `generate-weekly-newsletter.ts` /
`send-monthly-digest.ts` directly against Supabase — not API routes. They
used to be, and a real production run hit Azure's Free-tier Functions
execution ceiling (`"Backend call failure"` after 46s — the same failure
class the scan pipeline hit and was fixed for first). The monthly digest
was the last holdout (`docs/ENHANCEMENTS.md` E-11, 2026-09-05) — its
`DIGEST_SERVICE_TOKEN` and the HTTP route it gated are both deleted, not
kept as a fallback.

Server-only secrets used by the API routes themselves
(`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
`AZURE_OPENAI_KEY`, `AZURE_STORAGE_CONNECTION_STRING`, `GITHUB_PAT`,
`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`) belong in the Static Web App's
own application settings, not GitHub Secrets — note these use the real
`GITHUB_*` names there, since Azure has no equivalent naming restriction;
only the GitHub Actions secret store does. See `docs/security.md`. The
`SUPABASE_*`/`WPSCAN_API_TOKEN`/`GOOGLE_SAFE_BROWSING_API_KEY`/
`HIBP_API_KEY`/`GH_*` GitHub Secrets above
are the exception: used directly *inside* a GitHub Actions job, never
deployed anywhere — a reasonable place for them, but rotate them the same
as any other service-role credential if the repo's secret store is ever
compromised.

## Deployment

1. Provision Azure resources (above).
2. Set GitHub Secrets (above).
3. Push to `master` — `.github/workflows/deploy.yml` builds and deploys
   the whole Next.js app (site + every API route) to Azure Static Web
   Apps.
4. Configure the custom domain on the Static Web App and wait for the
   managed SSL certificate to provision.

## Operational Checklist

Things worth confirming are actually in place on a given deployment —
not a "getting started" list, since this system is already live:

- [ ] Confirm every migration under `sql/migrations/` has run against
      production Supabase, in order
- [ ] Confirm `ALLOW_DEV_TOKEN_VERIFICATION` is unset (or `false`) in
      production — real DNS/file ownership verification must be required
- [ ] Confirm `UPSTASH_REDIS_REST_URL`/`TOKEN` are set — the in-memory
      rate-limiter fallback does not survive Function instance recycling
- [ ] Confirm the Resend sending domain is verified in Resend's own
      dashboard — a valid `RESEND_API_KEY` alone doesn't guarantee mail
      actually delivers
- [ ] Confirm `WPSCAN_API_TOKEN`/`GOOGLE_SAFE_BROWSING_API_KEY`/
      `HIBP_API_KEY` are set if those checks should be live (each degrades
      silently to `not_configured` when unset — easy to not notice)
- [ ] Confirm a GitHub App is registered (`GH_APP_ID`/`GH_APP_PRIVATE_KEY`)
      before onboarding real customers who connect a repo — the `GH_PAT`
      fallback is one shared token across every connected repo, a real
      blast-radius risk if it leaks
- [ ] Business/legal: professional indemnity insurance before selling
      manual pen-test engagements, NDA/MSA templates, VAT/registration
      status confirmed before publishing prices
- [ ] Confirm `STRIPE_PRICE_BASIC`/`PRO`/`AGENCY` are real Stripe Dashboard
      Price IDs — unset, paid signup 500s end to end (`docs/ROADMAP.md`
      POC-B1, `docs/ENHANCEMENTS.md` E-07)
- [ ] Confirm `SENTRY_DSN`/`NEXT_PUBLIC_SENTRY_DSN` are set — error tracking
      code is live (`docs/ENHANCEMENTS.md` E-03) but silently captures
      nothing until a real Sentry account/DSN exists
- [ ] Publish Terms of Service and link it from checkout — currently
      doesn't exist while the app takes card payments
      (`docs/ROADMAP.md` BETA-B1, `docs/ENHANCEMENTS.md` E-09)
- [ ] Confirm error tracking is wired up (Sentry/App Insights) — today a
      failed scan in production leaves no way to find out why after the
      fact (`docs/ROADMAP.md` BETA-1, `docs/ENHANCEMENTS.md` E-03)
- [ ] Confirm a data-deletion path exists matching what `/privacy` promises
      customers — it doesn't yet, and `docs/security.md`'s retention figure
      currently disagrees with `/privacy`'s (`docs/ROADMAP.md` BETA-3/BETA-B2,
      `docs/ENHANCEMENTS.md` E-10)

See `docs/ROADMAP.md` for the full readiness ladder this checklist is a
summary of, and `docs/FUNCTIONALITY-MATRIX.md` for exactly which advertised
plan features are (and mostly aren't) actually server-enforced today.
