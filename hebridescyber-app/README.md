# Hebrides Cyber

Developer-grade security audits and an automated "Security Score" monitoring
product, for small businesses and SaaS teams. Marketing site + client
dashboard built on Next.js and Supabase; scanning and reporting run as Azure
Functions.

See also: `docs/architecture.md`, `docs/security.md`, and the `marketing/`
folder (one level up, outside this app folder) for homepage copy, pricing,
branding, and the business plan this app implements.

## Status

This is a working local MVP with real functionality behind most of it, not
just marketing copy describing services:

- **Real scanning** — `src/lib/scanners/` does live TLS/certificate
  inspection, HTTP security header checks, passive tech fingerprinting,
  a real headless Chromium page load (Playwright), Nmap port scanning
  (if installed), and OWASP ZAP integration (if a ZAP daemon is
  configured) — see the file header for exactly what's real vs. limited.
- **Real ownership verification** — DNS TXT / file-upload domain proof
  (`src/lib/ownership.ts`, `src/functions/verify-ownership`), with a
  dev-only token-echo fallback you can disable via
  `ALLOW_DEV_TOKEN_VERIFICATION=false`.
- **Real report generation** — PDF via Playwright, optionally uploaded to
  Azure Blob Storage with a SAS URL.
- **Real remediation** — `generate-fix-pr` opens an actual GitHub pull
  request with concrete fix snippets from a scan's findings.
- **Real billing** — Stripe Checkout Session creation + webhook that
  updates the `subscriptions` table.
- **Real auth** — passwordless magic link + Google OAuth login
  (`/login`), auth-aware header, bespoke dashboard content by plan.
- **Real weekly content** — an automated blog/newsletter
  (`src/lib/newsletter.ts`) grounded in aggregate scan data, published to
  `/blog` on a GitHub Actions cron.
- **Real MFA** — TOTP two-factor via Supabase Auth's built-in `auth.mfa`
  API (`/account/security` to enroll, `/login/mfa-challenge` enforced
  automatically on sign-in once a factor exists — see `src/lib/auth.ts`).
- **Real analytics** — GA4 via `src/components/GoogleAnalytics.tsx`,
  gated behind an accept/decline cookie consent banner
  (`src/components/CookieConsent.tsx`) since analytics cookies need opt-in
  consent under UK/EU rules. Set `NEXT_PUBLIC_GA_MEASUREMENT_ID` to enable.

What's still a deliberate stub or requires infrastructure this repo can't
provision for you: full SCA/dependency scanning against a real package
manifest (current check is passive HTML fingerprinting only), waiting for
and attaching ZAP scan results (currently fire-and-forget), and running
scanners in isolated containers rather than inline in the Function. See
TODOs throughout, `docs/security.md`, and `PRODUCTION-ROADMAP.md`.

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
`/pricing`, `/contact`) work with no configuration. `/dashboard` will show a
"sign in required" state until you connect a real Supabase project and sign
in.

### Set up the database

In your Supabase project's SQL editor, run the contents of
`sql/migrations/001_init.sql`. This creates the `users`, `scans`,
`scan_results`, `subscriptions`, and `audit_logs` tables with row-level
security policies already applied.

### Run the local scanner stub

```bash
npm run scan:local -- https://example.com
```

This runs the same stubbed steps as the `run-scan` Azure Function (shared
via `src/lib/scanners/`), but locally with no Azure dependency — useful
for iterating on scanner logic. Prints JSON + a 0-100 score to the console.
Set `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `SCAN_OWNER_ID` to also
persist the run to your Supabase project (handy for seeding test data).

### Seed demo data

```bash
npm run seed:users     # admin + basic/pro/agency/no-plan demo customers (real, sign-in-able accounts)
```

Then run `sql/seed/001_blog_posts.sql` in the Supabase SQL editor (after
`001_init.sql`) to populate `/blog` with sample posts — a mix of real,
sourced recent security incidents and evergreen articles tied to this
app's own features.

`seed:users` prints an email list and a shared password at the end —
sign in at `/login`, toggle to password sign-in, and use those. One
account (`admin@hebridescyber.com`) has `is_admin` set and can see
`/admin`, a cross-customer overview gated server-side by that flag (see
`src/pages/api/admin/overview.ts`). The other four are pre-populated with
different subscription tiers (or none) so the dashboard's plan-aware
upsell renders differently for each — sign in as `basic-customer@example.com`
vs `agency-customer@example.com` to see it change.

### Run the tests

```bash
npx playwright install --with-deps chromium   # first time only
npm run test
```

Playwright starts its own `next dev` server and runs against it — no
separate dev server or real Supabase project required (the dashboard
"authenticated" test mocks the session; see
`tests/e2e/dashboard.spec.ts` for how, and its TODO about the mock's
fragility).

## Running a Scan (the run-scan / X-Scan-Token flow)

`run-scan` is a two-step, curl-able flow — see
`src/functions/run-scan/index.ts` and `docs/security.md` for the full
rationale. In short:

**Step 1 — create the scan and get a proof token:**

```bash
curl -X POST "$AZURE_FUNCTIONS_URL/api/run-scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -d '{"targetUrl": "https://example.com"}'
# → { "scanId": "...", "status": "awaiting_verification", "proofToken": "..." }
```

**Step 2 — run it, proving you received the token from step 1:**

```bash
curl -X POST "$AZURE_FUNCTIONS_URL/api/run-scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <supabase-access-token>" \
  -H "X-Scan-Token: <proofToken from step 1>" \
  -d '{"scanId": "<scanId from step 1>"}'
# → { "ok": true, "scanId": "...", "status": "completed", "score": 78, "summary": "..." }
```

The dashboard (`src/app/dashboard/page.tsx`) does both calls automatically
when you submit the "Run scan" form. **This token-echo flow is a stub** —
it proves the caller received a response from step 1, not that they
control DNS/hosting for the target. Before enabling real (non-stub)
scanning, replace it with the DNS TXT / file-upload verification flow
described in `docs/security.md`.

**Generate a PDF report** once a scan has completed:

```bash
curl "$AZURE_FUNCTIONS_URL/api/generate-report?scan_id=<scanId>" -o report.pdf
```

(Returns a `{ url }` JSON body with a SAS link instead of the raw PDF if
`AZURE_STORAGE_CONNECTION_STRING` is configured.)

## How to Extend This App

- **Add a new marketing page:** create a folder under `src/app/<name>/` with
  a `page.tsx`, and add a link in `src/components/Header.tsx`.
- **Add a new scanner check:** add a `checkXyz()` function to
  `src/lib/scanners/`, call it from `runAllChecks()`, and fold its
  findings into `summariseResults()`. Both `run-scan` and
  `npm run scan:local` pick it up automatically since they share this
  module.
- **Change the report format:** edit `renderReportHtml()` in
  `src/functions/generate-report/index.ts`. The target structure to match
  is in `marketing/04-security-score-template.md`.
- **Add a pricing tier or Stripe product:** update
  `src/app/pricing/page.tsx`, create the corresponding Product/Price in the
  Stripe Dashboard, and handle the new plan in
  `src/pages/api/stripe/webhook.ts` and the `subscriptions` table `plan`
  check constraint in `sql/migrations/001_init.sql` (you'll need a new
  migration file to alter the constraint, don't edit 001 after it's been
  run against a real database).
- **Add a database table:** create a new file
  `sql/migrations/002_<description>.sql` — don't edit `001_init.sql` once
  it's been applied anywhere real.

## Provisioning Azure Resources

Two options, see `azure/`:

- **Terraform** (`azure/terraform/main.tf`) — infrastructure as code,
  recommended once you're past the prototype stage. Needs a remote state
  backend configured before first use (see TODO in the file).
- **CLI script** (`azure/cli-scripts/provision.sh`) — faster for a first
  manual pass, including the GitHub-linked Static Web App setup that
  Terraform's provider doesn't fully cover. Edit the variables at the top
  before running.

There is also a ready-to-use prompt for handing this provisioning step to a
Claude agent with shell access: see `09-azure-provisioning-prompt.md` one
level up from this folder.

## GitHub Secrets

Set these under Settings > Secrets and variables > Actions on the repo:

| Secret | Used by |
|---|---|
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | `deploy.yml` — static site deploy |
| `AZURE_FUNCTIONAPP_PUBLISH_PROFILE` | `deploy.yml` — Functions deploy |
| `NEXT_PUBLIC_SUPABASE_URL` | `deploy.yml` — build-time |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `deploy.yml` — build-time |
| `AZURE_FUNCTIONS_URL` | `scheduled-scans.yml` |
| `GITHUB_ACTIONS_TOKEN` | `scheduled-scans.yml` — auth to run-scan (`X-Service-Token`) |
| `SUPABASE_URL` | `scheduled-scans.yml` — `fetch-targets` job queries Supabase directly |
| `SUPABASE_SERVICE_ROLE_KEY` | `scheduled-scans.yml` — same, plus needed by any CI step that seeds/reads data |

Server-only secrets used by the Functions app itself
(`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
`AZURE_OPENAI_KEY`, `AZURE_STORAGE_CONNECTION_STRING`) belong in Azure Key
Vault / Function App settings, not GitHub Secrets — see `docs/security.md`.
The two `SUPABASE_*` GitHub Secrets above are the exception: they're used
directly *inside* a GitHub Actions job (not deployed anywhere), which is a
reasonable place for them, but rotate them the same as any other
service-role credential if the repo's secret store is ever compromised.

## Deployment

1. Provision Azure resources (above).
2. Set GitHub Secrets (above).
3. Push to `main` — `.github/workflows/deploy.yml` builds and deploys the
   Next.js site to Azure Static Web Apps and the Functions to Azure
   Functions.
4. Configure the custom domain (`hebridescyber.com`) on the Static Web App
   and wait for the managed SSL certificate to provision.

## Checklist Before Production

- [ ] Register `hebridescyber.com` and point DNS at Azure Static Web Apps
- [ ] Create the real Supabase project and run `001_init.sql` against it
- [ ] Provision Azure resources (Static Web App, Functions, Storage, Key
      Vault) — fill in the TODOs in `azure/terraform/main.tf` /
      `provision.sh` with real names
- [ ] Apply for and configure Azure OpenAI access (approval step, not
      instant)
- [ ] Create Stripe products/prices matching `src/app/pricing/page.tsx` and
      connect Stripe Checkout
- [ ] Set all GitHub Secrets listed above
- [ ] Set `ALLOW_DEV_TOKEN_VERIFICATION=false` once customers are expected
      to complete real DNS/file ownership verification
- [ ] Set `UPSTASH_REDIS_REST_URL`/`TOKEN` — the in-memory rate limiter
      fallback does not survive Function instance recycling
- [ ] Enable the Google provider in the Supabase Dashboard (Authentication
      > Providers) if you want `/login`'s "Continue with Google" to work
- [ ] Create Stripe Products/Prices and set `STRIPE_PRICE_BASIC/PRO/AGENCY`
- [ ] Replace the shared `GITHUB_PAT` in `generate-fix-pr` with a GitHub
      App (per-installation tokens) before onboarding real customers — see
      the TODO at the top of that file about blast radius
- [ ] Deploy an OWASP ZAP daemon and set `ZAP_API_URL` if you want that
      check to run (it's a no-op stub without it); install `nmap` in the
      Functions container (not present by default) for the port-scan check
- [ ] Move scanner execution into isolated containers (Azure Container
      Instances) per `docs/security.md`, rather than inline in the Function
- [ ] Write a real `/privacy` page — linked from the cookie consent banner
      but doesn't exist yet — before enabling `NEXT_PUBLIC_GA_MEASUREMENT_ID`
- [ ] Get professional indemnity insurance before offering pen test
      engagements
- [ ] Obtain SSL (handled automatically by Azure Static Web Apps once the
      custom domain is verified)
