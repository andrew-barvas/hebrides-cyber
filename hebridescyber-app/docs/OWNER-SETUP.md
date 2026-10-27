# Owner setup runbook

Step-by-step for the configuration tasks only the account owner can do — these
are **secrets and dashboard settings, not code**, so they can't be done from a
pull request. Ordered by urgency. Each item says *why*, *where*, and *how to
verify it worked*.

Status legend: 🔴 security-urgent · 🟠 blocks a core feature · 🟡 important · 🟢 nice-to-have

---

## 🔴 1. Rotate the Supabase database password (do this first)

**Why.** The `DATABASE_URL` connection string (which contains the Postgres
password) was pasted into a chat on 2026-10-14 during migration setup. Treat it
as compromised. It grants direct, RLS-bypassing SQL access to all customer data.

**Steps.**
1. Supabase dashboard → your project → **Settings → Database → Database password → Reset database password**. Copy the new password.
2. Rebuild the connection string with the new password (same host/port/db, e.g.
   `postgresql://postgres:<NEW_PASSWORD>@<host>:5432/postgres`). Supabase shows
   the full string under **Settings → Database → Connection string → URI**.
3. GitHub → repo → **Settings → Secrets and variables → Actions** → update the
   **`DATABASE_URL`** secret with the new string.
4. If `DATABASE_URL` is also set anywhere else (local `.env.local`, Azure), update it there too.

**Verify.** Trigger a deploy (any push to `master`, or Actions → **Deploy → Run
workflow**). The "Apply migrations + verify schema" job should connect and report
`N applied, 0 pending`. If it fails to connect, the string is wrong.

**Also rotate anything else ever pasted into a chat** (service-role key, Stripe
keys) on the same principle — see items below for where each lives.

---

## 🟠 2. Stripe price IDs — unblocks paid signup (E-07)

**Why.** Paid signup is impossible and `GET /api/health` returns 503
("degraded") until the three price IDs and the webhook secret are set. This is
the single biggest commercial blocker.

**Steps.**
1. Stripe dashboard → **Products** → create a recurring Product+Price for each tier:
   Basic £20/mo, Pro £35/mo, Agency £75/mo (and Tier A if selling it). Copy each `price_…` id.
2. **Developers → Webhooks → Add endpoint**:
   - URL: `https://www.hebridescyber.co.uk/api/stripe/webhook`
   - Events: `checkout.session.completed`, `invoice.payment_failed`, `customer.subscription.deleted`
   - Copy the **Signing secret** (`whsec_…`).
3. Azure Portal → your Static Web App → **Settings → Environment variables** → add:
   - `STRIPE_SECRET_KEY` = `sk_live_…`
   - `STRIPE_PRICE_BASIC`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_AGENCY` (+ `STRIPE_PRICE_TIER_A` if used)
   - `STRIPE_WEBHOOK_SECRET` = `whsec_…`
   - **Save** (this restarts the app).

**Verify.** `https://www.hebridescyber.co.uk/api/health` returns 200 with
`stripe: { ok: true }`. Then do one real test checkout per tier (Stripe test
mode first if you prefer) and confirm the `subscriptions` row updates.

---

## 🟠 3. Sentry DSN — makes production failures visible (BETA-1 / E-03)

**Why.** The error-tracking code is wired but a no-op until a DSN exists. Right
now a failed scan is only visible as `scans.status = 'failed'` (plus the new
`error_detail` column) — no stack trace, no alerting.

**Steps.**
1. Create a Sentry account → **Create project** → platform **Next.js**. Copy the DSN.
2. Azure SWA → Environment variables → add `SENTRY_DSN` = the DSN (server side, read at runtime).
3. GitHub → Settings → Secrets and variables → Actions → add **two repository secrets**, both set to the same DSN:
   - `NEXT_PUBLIC_SENTRY_DSN`: `deploy.yml` passes it to the Azure build, because `NEXT_PUBLIC_*` is inlined at build time and SWA app settings are not visible to that build. Setting it only in Azure does nothing for the browser.
   - `SENTRY_DSN`: used by the scan worker (`workerSentry.ts`).
4. Push to `master` (or re-run Deploy) so the browser bundle is rebuilt with the DSN.

**Verify.** Hit `/global-error` paths or trigger a canary error; it appears in
Sentry within ~60s with a request id. For the worker, a failed job in
**Actions → Scheduled scans** appears in Sentry tagged with its `scan_id`.

---

## 🟡 4. SITE_URL + branch protection

### 4a. `SITE_URL` — completes the post-deploy health check (BETA-2)
**Why.** `deploy.yml`'s post-deploy curl of `/api/health` needs the base URL.
**Steps.** GitHub → Actions secrets → add `SITE_URL` = `https://www.hebridescyber.co.uk`.
**Verify.** Next deploy's final "health check" step runs and passes (not skipped).

### 4b. Branch protection — a failing check blocks merge (BETA-5)
**Why.** The `check` job (lint/tsc/test/e2e) runs on PRs, but nothing *enforces*
it before merge yet. (Requires GitHub Pro for a private repo.)
**Steps.** GitHub → **Settings → Branches → Add branch ruleset** (or classic
protection) for `master`:
- Require a pull request before merging.
- **Require status checks to pass** → select the **`Lint, typecheck, test`** check.
- Optionally: require branches up to date, require linear history.
**Verify.** Open a deliberately-failing PR; the merge button is blocked until the check passes.

---

## 🟢 5. Lower-priority owner actions (from NEXT-STEPS §"Owner actions pending")

- **Encrypt stored secrets** — ✅ *already done this session* (`CREDENTIALS_ENC_KEY`
  set in Azure + GitHub; the "Encrypt stored secrets" dry run found 0 rows, so
  nothing to migrate yet). Nothing further needed unless you rotate the key.
- **Restore drill (E-13 / LIVE-4):** restore a Supabase backup into a scratch
  project and record it in `BACKUP-RESTORE.md`; consider Supabase Pro for PITR.
- **Publish the GitHub Action** from a public repo (this repo is private, so
  customers can't `uses:` it); until then the `/docs/ci` templates are the route.
- **Domains:** register `hebridescyber.com` defensively; add a
  `security@hebridescyber.co.uk` alias for `security.txt` / `SECURITY.md`.
- **ToS solicitor review** (BETA-B1) and **PI insurance** before selling the
  manual pen-test tiers (BETA-B3).
- **NCSC replacement campaign:** run `sql/seed/002_ncsc_web_check_retirement_post.sql`
  then send the drafts in `marketing/16-ncsc-replacement-campaign.md`.
- **CAA DNS record** at the registrar (`0 issue "digicert.com"`), then replay the own-site scan.
- Optional service keys (all degrade gracefully if unset): `UPSTASH_REDIS_REST_URL`/`_TOKEN`
  (**security-relevant** — rate limiting fails open without it), `RESEND_API_KEY`
  (all outbound email), `AZURE_STORAGE_CONNECTION_STRING` (report/image hosting),
  `AZURE_OPENAI_*` (AI remediation), `GOOGLE_SAFE_BROWSING_API_KEY` / `HIBP_API_KEY`
  / `WPSCAN_API_TOKEN` (extra scan coverage), `GITHUB_PAT` or GitHub App (customer-repo scanning).

All env-var names are documented in `.env.example`.

- `TRUSTED_PROXY_HOPS` (default `2`, Azure SWA): how many proxies sit in front of the app. It decides which
  `X-Forwarded-For` entry is the client IP, which feeds rate limits **and** API-key IP allowlists. After any
  hosting change, probe `GET /api/client-ip` with a forged `X-Forwarded-For` and confirm it returns your real address.

## Optional: AI triage and out-of-band server

Both off or default until you choose. In GitHub **Settings → Secrets and variables → Actions**:

- Variable `AI_TRIAGE` = `1` to let the scan workers triage unproven findings with Azure OpenAI
  (needs the three `AZURE_OPENAI_*` secrets). Read `AI-TRIAGE-DESIGN.md` (data handling) first and
  evaluate the output by hand on a few of your own sites. Variable `DISABLE_AI_TRIAGE` = `1` forces it
  off everywhere regardless of `AI_TRIAGE`.
- Variable `INTERACTSH_SERVER` (a bare host) and secret `INTERACTSH_TOKEN` to point nuclei's
  SSRF/OAST templates at your own interactsh server instead of ProjectDiscovery's public pool;
  variable `DISABLE_OAST` = `1` to send nothing out-of-band at all (loses blind-SSRF coverage).

## Sentry for the scan worker

The same `SENTRY_DSN` now also covers the GitHub Actions scan worker. Add it as a repository **secret** named `SENTRY_DSN` (in addition to the Azure setting) or worker failures stay invisible. Filter by tag `correlation_id` (the scan id) or `scan_id` to follow one scan from the API request to the worker.

