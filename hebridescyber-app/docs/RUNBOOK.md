# Operations runbook: incidents and disaster recovery

What to do when something is broken in production, from a stuck scan to losing
the whole platform. Written for one person on call who may not have touched
the system for weeks: every playbook says how to **confirm**, what to **try in
order**, how to **verify** it worked, and when to **escalate**.

How this file is organised
1. [Principles](#1-principles) and [severity](#2-severity-and-response-targets)
2. [System map](#3-system-map): what runs where, and what each failure looks like
3. [First 15 minutes](#4-first-15-minutes-triage): symptom → playbook
4. [Diagnostics toolbox](#5-diagnostics-toolbox)
5. [Playbooks](#6-playbooks), one per failure
6. [Security incidents](#7-security-incidents), including secret rotation
7. [Disaster recovery](#8-disaster-recovery): RPO/RTO, rebuild from nothing, drills
8. [Communication templates](#9-communication) and the [post-incident review](#10-after-every-incident)
9. [Vendor contacts](#11-vendors-and-contacts) and [maintenance](#12-keeping-this-runbook-true)

Companion docs: `BACKUP-RESTORE.md` (Supabase restores), `OWNER-SETUP.md` and
`OWNER-TODO.md` (owner-only steps), `ARCHITECTURE-NOTES.md` (how it works),
`NEXT-STEPS.md` (current state), `security.md` and `../SECURITY.md` (security
posture and disclosure).

**Honesty about this document.** Steps marked **(verify)** come from reading
the code and docs, not from having done them in an incident. Steps marked
**(owner-held)** depend on settings that live in a vendor dashboard and are
not in this repository. The restore drill (OT-12) has not been done, so
nothing in the disaster-recovery section has been proven end to end yet.

---

## 1. Principles

1. **Stop the bleeding before finding the cause.** Disable the failing tool,
   pause the workflow, revert the deploy. Diagnose afterwards.
2. **Never make a failure look like a clean result.** A tool that errors is
   reported as not-run, and the finding lifecycle will not mark last scan's
   findings fixed. Do not hand-edit scan rows, findings or `scan_jobs` to
   "tidy up" during an incident; it breaks that guarantee and the SLA clocks.
3. **Do not restore over production.** Restore into a scratch project, compare,
   then decide.
4. **Prefer forward fixes.** Migrations are forward-only and a code revert does
   not un-apply one. A reverted commit is a fix; an edited applied migration is
   a new incident (the drift check fails every deploy).
5. **Write things down as you go**, with times. The note becomes the review.
6. **Tell customers early and plainly** when they are affected (section 9).
7. **Test on `https://www.hebridescyber.co.uk`.** The bare domain only
   redirects to `www`; a bare-domain check proves nothing about the app.

## 2. Severity and response targets

These are targets for one-person operations, not customer commitments (the
hosting tiers carry no SLA).

| Level | Meaning | Examples | Aim to start |
|---|---|---|---|
| **SEV1** | Customer data at risk, or the product is unusable for everyone | suspected breach, leaked service-role key, site down, database gone, wrong data shown across accounts | at once; update customers within 2 hours |
| **SEV2** | A core feature is broken for many | sign-in fails, scans not running, payments or webhooks failing, alerts not sent | same day |
| **SEV3** | Degraded, with a workaround | one tool failing, one workflow missed, slow pages, a vendor warning | next working day |
| **SEV4** | Cosmetic or internal | docs, dashboards, a flaky test | backlog |

When unsure, pick the higher level and downgrade later.

## 3. System map

| Part | What it is | Where it runs | If it fails | Watched by |
|---|---|---|---|---|
| **Web app and API** | One Next.js app: pages, `/api/*` routes | Azure Static Web Apps (hybrid mode, managed Functions) | site or API down | `/api/health`, post-deploy check, uptime monitor, Sentry |
| **Database and auth** | Postgres, Supabase Auth, RLS | Supabase | sign-in, dashboard and the scan queue fail | `/api/health` (`supabase`) |
| **Scan queue** | `scan_jobs` rows claimed by workers | Postgres + GitHub Actions | scans stay queued | `/api/health` (queue depth), Admin → Queue |
| **Scan workers** | `scheduled-scans.yml`, `on-demand-scan.yml` | GitHub Actions runners | no scans run | Actions run history, Sentry (worker) |
| **Payments** | Checkout, webhook, billing portal | Stripe + `/api/stripe/webhook` | no upgrades; plan state drifts | `/api/health` (`stripe`), Stripe dashboard |
| **Email** | Alerts, scan-complete, reports, newsletters | Resend | alerts silently not sent | Admin email health (`/api/admin/email-health`) |
| **Rate limiting** | Shared counters | Upstash Redis | **fails open** (no throttling) | none: check configuration |
| **Error tracking** | Web, API and worker errors | Sentry | blind | none: it is the monitor |
| **Uptime** | External pings of `/api/health` | `uptime.yml` (every 10 min; opens a GitHub issue, which emails repo watchers, when the site is down or degraded, and closes it on recovery), customers' own UptimeRobot | late detection (Actions cron is best-effort) | the issue / email it sends |
| **PDF reports and files** | Report PDFs, uploads | Azure Blob Storage | reports fail | worker and API errors |
| **AI features** | Triage, blog and newsletter write-ups | Azure OpenAI (optional) | those features off | feature is off unless configured |
| **Source and CI** | Repository, workflows, secrets | GitHub | cannot deploy or scan | GitHub status |
| **DNS and domain** | `hebridescyber.co.uk`, `www` | GoDaddy (owner-held) | site unreachable | uptime monitor |

**Where secrets live.** GitHub Actions secrets (build-time and worker values:
see section 7.2), the Azure Static Web App's application settings (runtime
values for the API routes; **owner-held**, not visible from the repo), and the
Supabase, Stripe and Resend dashboards. The credential-encryption key
`CREDENTIALS_ENC_KEY` must be the **same value** in GitHub and in the Azure
app settings.

**Scheduled work** (all UTC, all GitHub Actions; a missed run is SEV3 unless
it is the scan or report job):

| Workflow | When | What it does |
|---|---|---|
| `scheduled-scans.yml` | daily 03:00 | enqueue due targets, run the full-tool scan worker |
| `uptime.yml` / `uptime-sync.yml` | every 10 / 15 min | ping `/api/health` / sync customer UptimeRobot monitors |
| `scheduled-reports.yml` | hourly :15 | send due scheduled reports |
| `publish-scheduled-posts.yml` | hourly :12 | publish scheduled blog posts |
| `emerging-threats.yml` | every 6 h (:40) | emerging-threat alerts |
| `easm-discovery.yml` | every 6 h (:25) | new-hostname sweep and alerts |
| `data-retention-cleanup.yml` | daily 04:00 | enforce published retention windows |
| `deletion-requests.yml` | daily 06:47 | alert before the 30-day erasure deadline |
| `daily-blog.yml` | daily 07:00 | generate the daily post |
| `weekly-newsletter.yml` | Mondays 07:00 | generate the newsletter |
| `monthly-digest.yml` | 1st of month 07:30 | monthly digest |
| `benchmark.yml`, `tool-integration.yml`, `dependency-audit.yml` | weekly (Mondays) | accuracy, real-binary tool tests, production dependency audit |

## 4. First 15 minutes: triage

1. **Write the time and what you saw.**
2. **Open `https://www.hebridescyber.co.uk/api/health`.**
   - Does not answer, or non-200 → [6.2 Site down](#62-the-site-is-down)
   - `supabase: false` → [6.5 Database](#65-the-database-is-unavailable-or-degraded)
   - `stripe: false` and the rest healthy → [6.8 Payments](#68-payments-and-stripe)
   - queue depth large and growing → [6.1 Scans stuck](#61-scans-are-stuck-or-not-running)
3. **Look at the last Deploy run** (GitHub → Actions → Deploy). An outage that
   began just after a deploy is a bad deploy until proven otherwise → [6.3](#63-a-bad-deploy-and-rolling-back).
4. **Look at Sentry** for a spike or a new error.
5. **Is it just you?** Check the vendor status pages in section 11 before
   spending an hour debugging someone else's outage.
6. **Pick a severity** (section 2) and, if SEV1 or SEV2 and customers can see
   it, post a first status update (section 9) even if you do not know the cause.

| Symptom | Go to |
|---|---|
| Pages or `/api/health` fail | 6.2, then 6.3 |
| "Scanning" for hours, queue growing | 6.1 |
| Only one tool failing or flapping | 6.4 |
| Deploy red, or migrations failing | 6.6, 6.7 |
| Cannot sign in, magic link missing, MFA loop | 6.9 |
| Upgrade did not apply, wrong plan, `past_due` confusion | 6.8 |
| Customers say no alert or report email arrived | 6.10 |
| A scheduled job did not run | 6.12 |
| Certificate warning, wrong domain, bare domain not redirecting | 6.14 |
| A key or token is exposed; suspected breach | **section 7, now** |
| Data lost, corrupted or wrong | 6.17, then section 8 |
| Everything is gone | section 8 |

## 5. Diagnostics toolbox

**Health endpoint.** `GET /api/health` (rate limited to 120 an hour per IP;
`HEAD` also works) returns booleans and a number only: `supabase` (a real
query), `stripe` (a real API call), and the pending `scan_jobs` count. A queue
count is informational and never turns the overall status red on its own. The
app answers **503 with those booleans** when a sub-check fails ("degraded"); no
answer, or a 5xx without that body, means "down". The uptime workflow uses the
same distinction.

**GitHub Actions.** Workflow runs, logs and "Run workflow" (manual dispatch).
The scan workers print a prefix per job; a scan's id is its **correlation
id**, so searching a scan id finds its log lines, its `scan_jobs` row, its
Sentry events and, for on-demand scans, the API request that created it.

**Sentry.** Web and API errors (needs `NEXT_PUBLIC_SENTRY_DSN` at build and
`SENTRY_DSN` in the Azure settings; OT-08) and scan-worker errors (`SENTRY_DSN`
GitHub secret; done, OT-26). Worker events are tagged by host only, never the
full URL, and credential-looking fields are scrubbed before sending.

**Admin area** (`/admin`, admin accounts only): **Queue** (jobs; Retry a failed
job; Recover stuck jobs), **Scans**, **Tools** (global kill switch per tool),
**Customers** (plan, status, caps, manual plan override), **Audit** (filter by
`resource.verb`), **GDPR** and deletion requests, **Email** health, **Metrics**.

**Migration state** (needs `DATABASE_URL`, the direct Postgres string, never
the pooled or REST URL). From `hebridescyber-app/`:

```bash
npx tsx src/scripts/apply-migrations.ts status
```

It reports applied and pending files and exits 1 on **drift** (a file edited
after it was applied) or on a database that has tables but no ledger.

**Run the queue worker by hand** (needs the worker environment):

```bash
npm run queue:run-worker
```

**Quick checks**

```bash
curl -s -L --max-redirs 3 -m 20 -o /dev/null -w "%{http_code}\n" https://www.hebridescyber.co.uk/api/health
curl -sI https://hebridescyber.co.uk | head -5     # bare domain: expect a 301 to www
gh run list --workflow deploy.yml --limit 5
gh secret list                                       # names and dates only
```

---

## 6. Playbooks

### 6.1 Scans are stuck or not running

**Signs:** scans sit in "queued" or "scanning"; queue depth grows; customers
report no results; no scheduled results since yesterday.

**How scans flow:** `run-scan` creates a `scans` row and **enqueues** a
`scan_jobs` row. GitHub Actions workers claim jobs. Nothing runs in the web
app itself, so a web outage and a scan outage are independent.

**Try, in order**
1. **Is a worker running?** Actions → "Scheduled Scans" and "On-demand scan".
   No recent run means the cron or the dispatch failed. Check the workflow is
   enabled and re-run it ("Run workflow"). On-demand scans are dispatched with
   `GH_PAT`; if that token expired, dispatch silently stops (6.13).
2. **Did the worker fail on every run?** Open a failed run. A missing or
   expired repository secret (`SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_URL`,
   `CREDENTIALS_ENC_KEY`) fails every job the same way, early.
3. **Is a job orphaned?** A runner killed mid-scan (out of memory, restart)
   leaves a `scan_jobs` row in `running` indefinitely. `reset_stale_scan_jobs()`
   returns such rows to `pending` only after **390 minutes**, deliberately
   longer than GitHub's 360-minute job ceiling so a live scan is never run
   twice (`041_reset_stale_scan_jobs.sql`). It runs at the start of every worker
   run. To run it now: Admin → Queue → **Recover stuck jobs**. **Do not shorten
   the threshold** to speed recovery: it causes duplicate results, alerts,
   pages and tickets.
4. **One job failed:** Admin → Queue → **Retry** on that job.
5. **Every scan is slow or one tool is in every error:** switch that tool off
   (6.4) so the rest complete.
6. **Actions minutes or runners exhausted:** see 6.13.
7. **The database refuses the claim:** see 6.5. Jobs resume when it returns.

**Verify:** a new on-demand scan moves queued → running → completed; queue depth
returns to near zero; the next scheduled run produces results.

**Escalate** if jobs fail on every worker run after the secrets are confirmed:
it is a code or dependency change. Look at the last merges to `master` and revert
(6.3).

### 6.2 The site is down

**Signs:** `/api/health` times out or is non-200; pages 5xx; the uptime monitor
or the Deploy health check warns.

**Try, in order**
1. **Right host?** Test `www`. A failing bare domain with a healthy `www` is a
   DNS or redirect issue, not an outage (6.14).
2. **Whole site or only some pages?** Only some → Sentry for that route's error
   first; the rest of this list is for a whole-site outage.
3. **Was there a deploy?** Deploy run failed before the deploy step → production
   is still on the previous build, so look elsewhere. Deploy succeeded and the
   health step warned → the new build is unhealthy → 6.3.
4. **Azure Static Web Apps itself.** Check the Azure status page and the SWA
   resource in the portal (**owner-held**). Nothing in this repository can fix an
   Azure incident; say so on the status page and wait. If it is prolonged, the
   alternative deploy path exists (section 8.6) but it was never put into
   service, so treat it as a last resort.
5. **Free-tier limits.** The Free tier has Functions execution and bandwidth
   limits. A 5xx or proxy error only on long-running routes points to the
   execution ceiling (this is why scans were moved to the queue).
6. **Environment settings changed.** A missing or rotated `SUPABASE_URL`,
   `SUPABASE_SERVICE_ROLE_KEY` or similar in the Azure application settings
   makes every API route fail while static pages still load.

**Verify:** `/api/health` is 200 on `www`; sign in; open the dashboard; start a scan.

### 6.3 A bad deploy and rolling back

1. Identify the commit: the Deploy run that preceded the failure.
2. **Revert it on `master`** and push:
   ```bash
   git revert <sha>        # a merge-squashed PR is one commit
   git push
   ```
   The push redeploys. Prefer this to force-pushing or resetting `master`.
3. **If the commit added a migration, stop and read 6.7 first.** Migrations
   already applied stay applied; the old code must still work against the new
   schema, or you need a forward fix instead of a revert.
4. If CI blocks the revert on an unrelated red check, fix that check or re-run
   it; do not bypass protections (6.6).
5. Watch the Deploy run, including the post-deploy health check (it waits 45 s
   for warm-up, follows the redirect, and only **warns** on a non-200).

**Verify:** `/api/health` 200; the thing that broke works again; Sentry quiet.

### 6.4 One tool is failing, flapping, or abusive

A scan tool (nuclei, ZAP, sqlmap, WPScan and so on) that crashes, hangs, floods
findings or misbehaves against a customer's site.

1. **Switch it off globally:** Admin → **Tools** → disable the tool. It takes
   effect on the next scan with no deploy (`055`). Findings from other tools are
   unaffected.
2. **What customers see:** a disabled or failing tool is reported as not-run.
   Its earlier findings stay open; they are not marked fixed. That is
   deliberate: do not "clean up" findings by hand.
3. **A tool producing false positives:** disable it, keep the evidence (scan id,
   the finding's detail), and fix the check; remember it needs a `checkId` and a
   test (`SCANNER-CONVENTIONS.md`).
4. **A tool that was never installed:** install steps that only log a failure
   hide this; check the worker log for the install step and the tool's version
   line. WhatWaf, for example, is not on PyPI, so a plain `pip install` never
   worked.
5. **A scan hitting a customer's site too hard** (they complain of load or
   blocking): disable the offending tool, tell the customer which checks ran,
   and review the throttle and timeout for that tool.

**Re-enable** after the fix and run one on-demand scan of your own site to confirm.

### 6.5 The database is unavailable or degraded

**Signs:** `/api/health` has `supabase: false`; sign-in and dashboard fail;
workers cannot claim jobs; Sentry shows connection errors.

**Try, in order**
1. **Supabase status page and the project dashboard.** Paused (a free project
   pauses after inactivity), out of disk, over its connection limit, or
   restarting?
2. **Resume or scale** if paused or out of resources (**owner-held**).
3. **Credentials.** `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` in the Azure
   settings were changed, or the key was rotated. A wrong key looks identical to
   an outage from `/api/health`.
4. **`DATABASE_URL`** (the direct Postgres string) is separate from the REST
   keys. If the database password was rotated, update the `DATABASE_URL` GitHub
   secret too, or migrations and the deploy fail (OT-01).
5. **Slow rather than down:** look for a long-running query or a missing index in
   the Supabase dashboard (Reports → Query performance). Cancel the offender.
6. **Data wrong or lost:** do not restore over production → 6.17 and section 8.

**While it is down:** scans in flight fail and are reported as failed (not clean);
jobs resume when it returns. Sign-ins fail. Stripe webhooks will be retried by
Stripe; see 6.8 for reconciling afterwards.

**Verify:** `/api/health` `supabase: true`; sign in; a scan completes; the queue
drains.

### 6.6 The deploy pipeline is failing

The gate is lint, type-check, unit tests with a coverage floor, and Playwright
end-to-end; then, on `master` pushes, **Apply migrations + verify schema**,
**Deploy to Azure Static Web Apps**, and the health check.

| Failing step | Usual cause | Do |
|---|---|---|
| Lint / type-check | a real error, or a merge that CI type-checked together | fix on a branch; rebase on `master` first |
| Unit tests | a real regression, or a worker timeout on a loaded machine | re-run once; if it passes alone it was load; if it repeats, fix it |
| Coverage | coverage fell below the floor | add tests. **Never lower a floor** |
| Playwright | a real UI break, or a flake | run `npm test` locally; do not skip |
| Apply migrations | SQL error, drift, or a database with no ledger | 6.7 |
| Deploy (SWA) | an expired `AZURE_STATIC_WEB_APPS_API_TOKEN`, or an Azure outage | regenerate the token in the portal, update the secret (7.2); check Azure status |
| Health check warns | the new build is unhealthy | 6.3 |

Branch protection on `master` (OT-07) is not yet enabled, so a red check does
not physically block a merge. The discipline is: merge only when green.

### 6.7 A migration broke something, failed, or drifted

Migrations auto-apply on push to `master` through `apply-migrations.ts`, which
records each file in the `schema_migrations` ledger with a checksum.

- **A migration failed to apply:** the deploy stops before the SWA step, so
  production code is unchanged but the database may be half-changed if the file
  was not transactional. Read the error, then fix **forward** with a new file
  (next free number, idempotent: `create or replace`, `if not exists`). The
  `/migration` skill walks the flow.
- **Drift** ("edited after it was applied"): someone changed an applied file.
  Restore the file to what was applied (`git log -p` on it) and put the change
  in a new migration. Never re-record a checksum to silence it.
- **A migration applied and is wrong:** a new forward migration. A code revert
  does not un-apply it, and there are no down scripts.
- **A new database with tables but no ledger:** `status` exits 1. Record what is
  already applied with `baseline`, then apply the rest (8.5).
- **Numbering collisions:** two branches both took the next number. The second to
  merge renumbers; the sequence already skips 023 on purpose.
- **Policy recursion (Postgres 42P17):** a policy must never sub-select its own
  table; use a `SECURITY DEFINER` function as migration 047 does.

**Verify:** `status` reports `0 pending` and no drift; `db-tests` passes in CI.

### 6.8 Payments and Stripe

- **Checkout returns 503 `checkout_unavailable`:** the `STRIPE_PRICE_*` variables
  are not set (customer-safe message; the missing name is in the server log).
- **Upgrade paid but plan did not change:** Stripe dashboard → Developers →
  Webhooks → the endpoint's recent deliveries. A failing delivery shows the
  response. Common causes: a wrong `STRIPE_WEBHOOK_SECRET` (signature
  rejected), the endpoint URL pointing at the bare domain, the app down at the
  time. **Resend the event** from the Stripe dashboard. The handler is
  idempotent (an event id already processed is skipped), so resending is safe.
  A checkout event with no plan metadata is **audited and not applied** rather
  than defaulting to Basic (so it will not silently downgrade or upgrade; fix the
  metadata and resend).
- **A customer is `past_due` or `cancelled` but still has features:** the webhook
  sets the status and leaves `plan` unchanged, and every gate honours
  `status === "active"` only. If features persist, a gate is comparing `plan`
  alone: that is a code bug (`planAccess.ts` is the one place to gate).
- **Lapsed Tier A and the others:** Tier A includes Agency and Pro; check a
  customer with Admin → Customers before reasoning about their access.
- **Manual override** (comps, pilots, goodwill): Admin → Customers plan override.
  It is tagged as admin-granted, and a real Stripe checkout later overwrites it.
- **After a database restore:** Stripe state may be newer than the restored data.
  See 8.4 to reconcile.
- **Never** paste or log Stripe secret keys; rotate per 7.2 if exposed.

### 6.9 Sign-in, magic links, MFA and OAuth

- **Magic link never arrives:** Supabase Auth sends it through its own email
  settings (**owner-held**); check Supabase Auth logs, the email provider limits
  and the spam folder before changing code.
- **"Redirect not allowed" / lands on the wrong site:** the Supabase Auth **Site
  URL** and **Redirect URLs** must list the `www` domain (**owner-held**).
- **Google sign-in fails:** the provider's client id and secret and redirect URI
  in the Supabase dashboard (**owner-held**); the button is only present when
  the provider is enabled.
- **MFA step-up loop:** the app shell sends users who have enrolled a factor to
  step up (AAL2) on every dashboard and account route. A loop usually means the
  session cannot reach AAL2 (a lost authenticator). The owner of the account can
  remove the factor in the Supabase dashboard after verifying who they are (see
  the identity check in 9.3).
- **Everyone is signed out:** the JWT secret or keys were rotated. Expected
  after a rotation; tell users to sign in again.
- **Admin cannot reach `/admin`:** `users.is_admin` is false for that account.

### 6.10 Email is not being sent

Alerts, scan-complete emails, scheduled reports, the SLA and deletion-deadline
notices and the newsletters go through Resend.

1. **Admin → Email** (`/api/admin/email-health`) shows whether the sender is
   configured and recent results.
2. **`RESEND_API_KEY` missing** from a workflow's environment means that
   workflow's emails are silently not sent. The scan workers need it (OT-02
   records that it was missing). `gh secret list` shows only that the name
   exists, not that the value is valid.
3. **Resend dashboard:** bounces, suppressions, a revoked key, an unverified
   sending domain (DNS records at the registrar; **owner-held**).
4. **One customer only:** their address bounced or is suppressed; ask them to
   check spam and confirm the address on file.
5. After fixing, nothing is replayed automatically. Alerts missed during the
   outage were not sent; say so (section 9) rather than implying they were.

### 6.11 Rate limiting and abuse

- Rate limiting uses Upstash Redis. If `UPSTASH_REDIS_REST_URL` / `_TOKEN` are
  missing or Redis is unreachable it **fails open**: requests are allowed, so
  login, scan-start and health limits stop protecting you. Restore it, and
  meanwhile watch for abuse in the Audit tab and Sentry.
- **Hammering of `/api/health`:** it limits itself; the response is a 429 once
  exceeded.
- **A client IP looks wrong or forgeable:** only `getClientIp(req)` may read it
  (Azure appends to `X-Forwarded-For`; the entry taken is
  `TRUSTED_PROXY_HOPS` from the right). After any hosting change, probe
  `GET /api/client-ip` with a forged header.
- **A customer scanning targets they do not own:** scans require verified
  domain ownership (DNS TXT or file). If verification was bypassed or a customer
  is abusing it, suspend the account (Admin → Customers) and review the Audit tab.

### 6.12 A scheduled workflow did not run

GitHub cron is best-effort: runs can be delayed by many minutes, and a run is
occasionally skipped.

1. Actions → the workflow → recent runs. A delay of minutes is normal.
2. **Disabled workflow?** Re-enable it; then "Run workflow" to catch up.
3. **Failing on every run?** Read the log; usually a missing or expired secret.
4. **Catch-up by job:**
   - scans: run "Scheduled Scans" manually (cadence is per plan, so it enqueues
     only targets that are due);
   - reports: the next hourly run picks up due reports;
   - emerging-threat and EASM alerts: the next 6-hourly run;
   - retention, deletion deadlines: the next daily run. **A missed
     `deletion-requests` run matters** because erasure requests have a 30-day
     legal deadline; check Admin → GDPR for anything close.
5. Do not run a workflow twice in a hurry if it sends email; check its log first.

### 6.13 GitHub-side problems

GitHub is the build system, the scan runner and the scheduler, so its outages
hit scanning and deploys together (the site keeps running).

- **GitHub outage:** nothing to fix; wait. Scans queue and resume.
- **Actions minutes exhausted** (private repo): scans, reports and uptime pings
  stop. Check Settings → Billing. Reduce schedules or buy minutes. Prioritise
  keeping `uptime.yml` and `scheduled-scans.yml` alive.
- **`GH_PAT` expired:** on-demand scans are queued but never dispatched. Renew
  the token and update the secret. Scheduled scans still run.
- **GitHub App (`GH_APP_ID` / `GH_APP_PRIVATE_KEY`):** customer-repo features
  (fix PRs, secret and dependency scans) fail with an auth error. Regenerate the
  private key in the App's settings and update the secret. Access to customer
  repos goes through `resolveGithubAuth` only.
- **A secret was committed or logged:** section 7.
- **Repository access lost** (account locked, repo deleted): section 8.7.

### 6.14 DNS, the domain, and TLS

- **Records:** the bare domain `hebridescyber.co.uk` redirects to `www` through
  an A record at GoDaddy and the SWA default domain; `www` points at the static
  web app. Both are **owner-held**.
- **Certificate warning or expired:** SWA issues and renews the managed
  certificate; if it fails, the usual cause is that a DNS record changed or the
  custom domain was removed from the SWA resource. Re-add/validate the custom
  domain in the portal.
- **Bare domain not redirecting:** the A record or the SWA custom-domain binding
  changed.
- **Domain expiry:** the registration lives at GoDaddy. Auto-renew and a valid
  card are the only protection (OT-19 covers CAA and a second domain).
- **After any DNS change:** test both hosts, the redirect, `www/api/health`, and
  that `security.txt` still resolves.

### 6.15 AI features misbehaving

AI triage, blog and newsletter write-ups use Azure OpenAI and are **off unless
configured** (`AI_TRIAGE=1` plus the Azure keys). If output is wrong, cost
spikes, or the endpoint is down: unset `AI_TRIAGE` (or the Azure keys) and the
feature turns off; scans are unaffected because triage only adds evidence and
never changes severity or score. Check the Azure OpenAI quota and key before
blaming the code.

### 6.16 We are blind (monitoring is down)

- **No Sentry events at all:** check the DSN secrets exist and were built into
  the last deploy (`NEXT_PUBLIC_*` values are baked in at build time). Throw a
  test error.
- **Uptime pings stopped:** `uptime.yml` and `uptime-sync.yml` are Actions
  workflows; see 6.12 and 6.13. An independent monitor outside GitHub is worth
  having (a status page and monitor on a different provider; OT-27).
- **The status page is also down:** it must be hosted off this stack. The footer
  link appears only when `NEXT_PUBLIC_STATUS_PAGE_URL` is set.

### 6.17 Data is wrong, lost, or corrupted

1. **Stop writes if the damage is spreading** (disable the writing tool or
   workflow; for a bad migration, 6.7).
2. **Establish scope and time:** which tables, which customers, since when. The
   Audit tab and the `scans` / `scan_results` timestamps help.
3. **Do not restore over production.** Restore a backup into a scratch project
   and compare (section 8.3), then copy back only the affected rows, or decide
   on a full restore.
4. **A single customer's data deleted by mistake:** restore into scratch, export
   that owner's rows, reinsert. Tell them.
5. **Cross-account exposure (one customer sees another's data):** this is a
   **security incident** (section 7.3), not a data fix. RLS is on for every
   table; the only bypass is server code using the service-role key.
6. **Retention job deleted too much or too little:** `data-retention-cleanup.yml`
   enforces the windows published on `/privacy` (scan results 12 months, report
   PDFs 90 days, contact enquiries 12 months). Check its log before reacting.
7. **Erasure requests:** a request is tracked with a 30-day deadline
   (`deletion-requests.yml` alerts before it). The erase script takes an email or
   a user id and cancels the Stripe subscription by default. Do not delete a
   customer's data by hand.

---

## 7. Security incidents

Treat any of these as **SEV1** until proven otherwise.

### 7.1 First moves for any security incident

1. **Contain first.** Rotate or revoke the exposed credential (7.2), disable the
   affected feature or tool (Admin → Tools), or suspend the abusive account.
2. **Preserve evidence.** Copy the relevant logs, run ids and Audit rows before
   anything rotates or expires. Do not delete anything.
3. **Write the timeline** with times in UTC.
4. **Scope it.** What could the credential or flaw reach? Which customers? Which
   data classes (account details, scan results, stored third-party credentials)?
5. **Decide on notification** (7.5) with the facts you have, not after a long
   investigation.

### 7.2 Secret rotation table

Rotate **everything the exposed secret could reach**, then redeploy so the new
value is used. "GH" is a GitHub Actions repository secret; "Azure" is the Static
Web App's application settings (**owner-held**).

| Secret | Where it lives | How to rotate | Side effects |
|---|---|---|---|
| `SUPABASE_SERVICE_ROLE_KEY` | GH, Azure | Supabase → Project settings → API → roll the key | **Full database access if leaked: SEV1.** All API routes and workers fail until both copies are updated and the app redeployed |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | GH (build) | same screen | Public by design, protected by RLS; rotation signs users out |
| `DATABASE_URL` | GH (and local) | Supabase → Database → reset password | Migrations and the deploy fail until updated (OT-01) |
| `STRIPE_SECRET_KEY` | Azure | Stripe → Developers → API keys → roll | Checkout and portal fail until updated |
| `STRIPE_WEBHOOK_SECRET` | Azure | Stripe → Webhooks → roll the signing secret | Webhooks are rejected until updated; resend missed events |
| `RESEND_API_KEY` | GH, Azure | Resend → API keys | Emails stop until updated (6.10) |
| `CREDENTIALS_ENC_KEY` | GH, Azure (same value) | see 7.4 | **Rotating makes stored third-party credentials unreadable** |
| `GH_PAT` | GH | GitHub → Developer settings → tokens | On-demand scans stop dispatching until updated |
| `GH_APP_PRIVATE_KEY` / `GH_APP_ID` | GH | the GitHub App's settings → generate a new private key | Customer-repo features fail until updated |
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | GH | Azure portal → the SWA → reset deployment token | Deploys fail until updated |
| `AZURE_CREDENTIALS`, `ACR_*` | GH | Azure (service principal, registry) | Only the Container Apps path uses them |
| `AZURE_OPENAI_KEY`, `STRIX_LLM_API_KEY` | GH, Azure | the provider | AI features fail until updated |
| `SENTRY_DSN` (and public DSN) | GH, Azure | Sentry → Client keys | A DSN is write-only; low risk, rotate if spammed |
| `UPSTASH_REDIS_REST_TOKEN` | Azure | Upstash console | Rate limiting fails open until updated |
| `NVD_API_KEY`, `HIBP_API_KEY`, `WPSCAN_API_TOKEN`, `INTERACTSH_TOKEN`, `GOOGLE_SAFE_BROWSING_API_KEY` | GH | each provider | That scanner step is skipped or degraded |

After any rotation: update **every** place in the table, redeploy
(a push to `master`, or re-run Deploy), then verify `/api/health`, a sign-in, a
scan, and the specific feature the secret serves.

### 7.3 Specific incidents

**A service-role key, database URL or encryption key leaked** (pasted in chat,
committed, logged). Rotate at once (7.2). Then look for misuse: the Supabase logs
for the exposure window, unexpected rows, new admin flags. Search git history for
the value; removing it from history does not make it safe, only rotating does.

**Suspected breach of customer data.** Contain (rotate, disable), preserve
evidence, scope which customers and which fields, then 7.5. Customer-supplied
third-party credentials (ticket-tracker and on-call tokens, authenticated-scan
cookies and passwords, cloud-posture credentials) are encrypted at rest with
AES-256-GCM; their exposure risk depends on whether the key and the database
were both reached. If you cannot rule that out, tell affected customers to rotate
those third-party credentials.

**One customer sees another's data.** RLS is meant to make this impossible from
the client. Treat it as a flaw in an API route using the service role: disable
the route if you can identify it, preserve the request logs, fix with a test that
reproduces it, then 7.5.

**An admin account is compromised.** Disable it in the Supabase dashboard,
rotate the service-role key if it could read keys, review the Audit tab for
`admin.*` actions in the window.

**A vulnerability reported to us.** `SECURITY.md` is the disclosure policy.
Acknowledge, reproduce, fix, and credit only if the reporter wants it.

**A customer's scan misuse, or an unauthorised scan of a third party.** Suspend
the account, preserve the Audit and scan rows, and review how domain ownership
was (not) verified. The offensive (Tier A) profile additionally requires a
current per-target authorisation row and a verified domain; a record of that
authorisation is the evidence in any dispute. Customer contracts must authorise
attack traffic before the destructive tools are enabled (a standing owner
action).

**Malware or a malicious dependency.** Production dependency audit runs weekly
and on lockfile changes (`dependency-audit.yml`). If one lands: pin or remove it,
rotate any secret the build could read, and rebuild.

### 7.4 The credential-encryption key

`CREDENTIALS_ENC_KEY` is a 32-byte key. It must be the **same value** in GitHub
and in the Azure settings, because the scan workers decrypt stored credentials
too. **Keep a copy in a password manager**: losing it makes every stored
third-party credential unrecoverable.

- **Missing or wrong key:** a value that cannot be decrypted is skipped with a
  logged error; the key is never used as a credential. Saving a new secret
  returns 503 until the key is set.
- **There is no re-key tool in the repository.** The "Encrypt stored secrets"
  workflow only encrypts values that are still plaintext. If you must rotate the
  key (after a confirmed compromise), assume every stored credential becomes
  unreadable: tell affected customers to re-enter them. **(verify)** before
  rotating whether a re-encryption script has been added since this was written.

### 7.5 Telling people

- **UK GDPR:** a personal-data breach that risks people's rights must be reported
  to the ICO **within 72 hours of becoming aware of it**, and affected people
  told without undue delay when the risk is high. When you may have a reportable
  breach, decide and record the decision the same day. This is guidance, not
  legal advice; get advice when it is real.
- **Customers:** section 9. Be specific about what was and was not exposed.
- **Stripe, Supabase, GitHub** need no notification for your own key leak, but
  check their dashboards for abuse.

---

## 8. Disaster recovery

### 8.1 Recovery objectives (targets)

| Scenario | RPO (data we can lose) | RTO (time to recover) | Status |
|---|---|---|---|
| Bad deploy | none | minutes (revert, 6.3) | in place |
| Database row or table damaged | up to 24 h on the free plan's daily backup; seconds with point-in-time recovery (paid plan, not enabled) | hours | **never drilled** (OT-12) |
| Supabase project lost | up to 24 h (last daily backup, if it survives with the project) | hours to a day | **not drilled**; backups may die with the project |
| Azure SWA or resource group lost | none (no data lives there) | a few hours: recreate the SWA, redeploy, redo DNS | procedure below, **not drilled** |
| GitHub repository or account lost | the repository itself, unless there is another copy | days | **gap**: no off-GitHub mirror |
| Domain lost | none | days (depends on the registrar) | owner-held |
| Encryption key lost | stored third-party credentials | customers re-enter them | key backup is the only protection |
| Total loss of everything | as above | days | section 8.8 |

The free plan's daily backup and the "minutes once initiated" restore time are
what `BACKUP-RESTORE.md` states; **no restore has been proven yet**, so treat
these as hopes until the drill (8.9) is done.

### 8.2 What is, and is not, in the repository

**In the repository (rebuildable from a clone):** all application code; every
SQL migration; the workflows and their schedules; the scanner configuration;
documentation; the Dockerfile; the Azure CLI scripts (`azure/cli-scripts/`).

**Not in the repository (you must have these elsewhere):**

| Item | Where it is | Recovery source |
|---|---|---|
| All customer and application **data** | Supabase | Supabase backups (8.3) |
| **Secrets** | GitHub secrets, Azure settings | a password manager (keep a current copy of every secret in 7.2) |
| `CREDENTIALS_ENC_KEY` | GitHub, Azure | password manager; no other copy |
| Supabase **Auth settings**: Site URL, redirect URLs, providers (Google), email templates, MFA settings, SMTP | Supabase dashboard | record them (8.10); they are not restored by a data backup |
| Stripe **products, prices, webhook endpoint, signing secret** | Stripe | Stripe holds them; note the price IDs |
| Resend **sending domain and DNS records** | Resend, registrar | registrar |
| **DNS records** | GoDaddy | export or screenshot; see 8.5 |
| Azure **SWA custom-domain binding**, application settings | Azure | re-enter from the password manager |
| GitHub **branch protection, secrets, App installation** | GitHub | re-create |
| Blob Storage **report PDFs** | Azure Storage | regenerable from scan results; retention is 90 days |
| Third-party monitors (UptimeRobot, status page) | their sites | re-create |

### 8.3 Recover the database

Never restore over production first.

1. **Scratch project.** Create a new Supabase project (free tier is fine).
2. **Restore into it.** On the *source* project: Dashboard → Database → Backups →
   pick the backup. Use the option to restore, or download it if your plan offers
   that **(verify what your plan offers; the free plan may only allow restoring in
   place)**. If only an in-place restore is possible, take a manual export of the
   current state first (`pg_dump` of the production database using
   `DATABASE_URL`) so you can undo it.
3. **Compare.** Check row counts and the newest rows in `scans`, `scan_results`,
   `subscriptions`, `users`, `findings`/lifecycle tables against what you expect.
4. **Decide:** copy back the affected rows, or do a full restore (below).
5. **Full restore (in place)** : Dashboard → Database → Backups → **Restore** at
   the chosen timestamp, or **PITR** to a timestamp if enabled. This replaces the
   whole database and **the migration ledger comes back with it**, so the ledger
   and the schema stay consistent.
6. **Re-apply migrations.** After the restore:
   ```bash
   cd hebridescyber-app
   export DATABASE_URL='<direct postgres url>'
   npx tsx src/scripts/apply-migrations.ts status     # applied / pending / drift
   npx tsx src/scripts/apply-migrations.ts apply      # applies anything the backup predates
   ```
   Do **not** use `supabase db push`: it does not know the ledger. Migrations are
   forward-only and written to re-apply safely; a few documented exceptions are
   listed in `migrations.db.test.ts`.
7. **Verify** with section 8.11.

**Smoke-test** `BACKUP-RESTORE.md`'s quick check also: a subscriptions column
exists and a sign-in works.

### 8.4 Reconcile after a restore (the data gap)

A restore brings back the database as of the backup. Things that happened
**after** it are in the outside world and not in the database:

- **Stripe:** upgrades, cancellations and failed payments in the gap. Stripe
  Dashboard → Developers → Webhooks → resend events from the gap. Because the
  restore also reverts the "already processed" event ledger, the handler will
  apply them again. **(verify on the first real use.)** Then spot-check each
  customer who changed plan in the window against Stripe.
- **Sign-ups:** a user created in Supabase Auth after the backup exists in Auth
  but has no profile row if the restore predates it. The new-user trigger
  creates a profile on sign-up; for users who already exist, have them sign in
  and check the profile row, or create it.
- **Scans:** scans run in the gap are gone; scheduled scans will re-run on their
  cadence. Finding history for the gap is lost, so SLA clocks and "first seen"
  dates for findings first seen in the gap start again.
- **Emails sent in the gap** (alerts, reports) were sent and will not be
  re-sent; do not trigger duplicates.
- **Erasure requests:** a customer erased in the gap may be back. Check the
  deletion records and **re-erase** anyone who had asked to be forgotten. This
  is a legal obligation.
- **Tell customers** what was lost (section 9).

### 8.5 Rebuild the platform from nothing

For the case where Azure, Supabase or both are gone and you are starting again.
Do the steps in order; each one has a check.

**0. Gather.** A clone of the repository; the password manager with all secrets
(7.2); the Supabase backup if one survives; the DNS record list (8.10).

**1. Supabase** (if the project is gone)
1. Create a project; note the URL, anon key, service-role key and the **direct**
   Postgres connection string (Settings → Database).
2. Restore the backup into it if you have one (8.3); otherwise start empty.
3. `export DATABASE_URL=...` then:
   ```bash
   cd hebridescyber-app
   npx tsx src/scripts/apply-migrations.ts status
   ```
   - **Empty database:** `apply` runs every migration in order.
   - **Restored database with no ledger table** (rare): `status` exits 1 telling
     you to record history first; run `baseline <last-applied-number>` for the
     files already in the data, then `apply`.
4. Re-create the **Auth settings** (8.10): Site URL, redirect URLs, Google
   provider, email templates, MFA.
5. Create your admin user and set `users.is_admin = true` for it.
6. **Check:** `status` shows `0 pending`; you can sign in.

**2. Azure Static Web App** (if it is gone)
1. Do **not** `terraform apply` `azure/terraform/main.tf`. It is a never-applied
   scaffold with placeholder names and a different region; applying it would
   create a second, duplicate set of resources.
2. Use `azure/cli-scripts/provision.sh` (needs `az login`) as a **starting
   point, not a turnkey script**: it creates a resource group, a storage account
   and a Static Web App, but its variables are placeholders that do not match
   production (it names the resource group `hebridescyber-rg` in `uksouth`, and
   its GitHub repository URL and branch are placeholders that must be set to the
   real repository and `master`). The previous production resources were in
   resource group `rg-hebrides-cyber` (eastus2) with storage account
   `hebridescyberstor`, per the note in `azure/terraform/main.tf`. Edit the
   variables first, then run it, and **(verify)** each resource it creates.
3. Copy the new SWA's **deployment token** into the GitHub secret
   `AZURE_STATIC_WEB_APPS_API_TOKEN`.
4. Add the **application settings** (Settings → Environment variables) from the
   password manager: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, the
   `STRIPE_*` values, `RESEND_API_KEY`, `CREDENTIALS_ENC_KEY` (same value as in
   GitHub), `SENTRY_DSN`, `UPSTASH_REDIS_REST_URL`/`_TOKEN`, `GH_APP_*`/`GH_PAT`,
   `AZURE_STORAGE_CONNECTION_STRING`, and the optional AI and scanner keys.
5. **Check:** the SWA shows the default hostname.

**3. GitHub** (if the repository is gone, push your clone to a new repository)
1. Re-create the repository secrets (7.2, build-time ones: `NEXT_PUBLIC_*`,
   `SITE_URL`, `DATABASE_URL`, `SUPABASE_*`, `RESEND_API_KEY`, `SENTRY_DSN`,
   `CREDENTIALS_ENC_KEY`, `AZURE_STATIC_WEB_APPS_API_TOKEN`, `GH_PAT`,
   `GH_APP_*`, `AZURE_STORAGE_CONNECTION_STRING`, and the optional scanner keys).
2. Re-install the GitHub App on the repository and re-add branch protection.
3. Enable Actions.

**4. Deploy**
1. Push to `master`, or Actions → Deploy → Run workflow. It runs the gate, applies
   migrations, deploys, and health-checks.
2. For a restored database that has no ledger history, run Deploy manually with
   `baseline_up_to` set to the last applied migration number the first time (this
   input records files as applied without running them).
3. **Check:** the Deploy run is green; the default hostname serves the site.

**5. DNS and domain**
1. At GoDaddy, point `www` (CNAME) at the SWA's default hostname and restore the
   bare-domain handling so it redirects to `www`.
2. Re-add the custom domain on the SWA and wait for its certificate.
3. Restore the Resend DNS records (SPF, DKIM) and any CAA record.
4. **Check:** `https://www.hebridescyber.co.uk/api/health` is 200 and the bare
   domain 301s to `www`.

**6. Stripe**
1. Confirm products and prices exist; set the `STRIPE_PRICE_*` variables.
2. Make sure the webhook endpoint is `https://www.hebridescyber.co.uk/api/stripe/webhook`
   (the `www` host) and update `STRIPE_WEBHOOK_SECRET` from it.
3. Resend any events from the gap (8.4).

**7. Everything else**
Re-create the status page and uptime monitors (OT-09, OT-27), turn Sentry back
on (OT-08), and confirm the workflows run on schedule.

**8. Verify** with 8.11. Then write the review (section 10).

### 8.6 The alternative web host (last resort)

A Container Apps deployment path exists (`Dockerfile`,
`deploy-containerapp.yml`, manual only). It was built to get off the Free-tier
Functions ceiling and **was never put into service or proven**. If Azure Static
Web Apps is unavailable for long, it is a candidate, but expect to debug it:
it needs the registry and resource-group secrets listed at the top of that
workflow, and the Terraform for its resources sits in a scaffold that must not be
applied whole (8.5, step 2).

### 8.7 GitHub lost or locked

You still have the code in every clone. Create a new repository, push, and follow
8.5 steps 3 to 4. Scans and deploys are down until then; the site keeps serving
the last build. **Gap:** keep a recent off-GitHub mirror of the repository
(a private mirror elsewhere, refreshed weekly) so a locked account does not stop
recovery.

### 8.8 Total loss

Do 8.5 in order: Supabase (data from backup if any survives), Azure, GitHub,
deploy, DNS, Stripe. The irrecoverable items without an off-platform copy are:
customer data if no backup survived; stored third-party credentials if the
encryption key is lost; any secret not in a password manager. Everything else is
regenerated from the repository.

### 8.9 Drills (do these)

An untested recovery plan is a guess. Schedule and record each.

| Drill | How | How often | Proves |
|---|---|---|---|
| **Restore drill** (OT-12) | follow `BACKUP-RESTORE.md` "Testing the restore procedure" in a scratch project; time it; record the result in that file | once now, then every 6 months | the RPO and RTO above |
| **Rebuild drill** | stand up a throwaway Supabase project + SWA from the repository using 8.5, point a test subdomain at it | yearly | 8.5 is complete and ordered right |
| **Rollback drill** | revert a harmless commit and watch the redeploy | after any pipeline change | 6.3 |
| **Secret rotation drill** | rotate a low-risk key (the Sentry DSN) through 7.2 | yearly | that every place is listed |
| **Backup-of-secrets check** | confirm the password manager has every secret in 7.2 and the encryption key | quarterly | 8.2 |
| **Alert test** | force an error and see it in Sentry; trip the uptime monitor | quarterly | monitoring works (launch AC1) |

### 8.10 Record these now (so you can rebuild)

Keep these in the password manager, not the repository:

- The current **Supabase Auth settings**: Site URL, redirect URLs, enabled
  providers and their client ids, email templates, SMTP, MFA, password rules.
- **DNS**: a full export of the GoDaddy zone for `hebridescyber.co.uk`
  (A/CNAME for `www`, the bare-domain redirect, MX, SPF, DKIM, DMARC, CAA, the
  Resend records, any `_acme` validation records).
- **Stripe**: product and price ids, the webhook endpoint url and its events.
- **Azure**: the resource group, SWA and storage account names, region, and the
  application settings list (names; values in the password manager).
- **Accounts and who holds them**: registrar, GitHub, Azure, Supabase, Stripe,
  Resend, Sentry, Upstash, the password manager; recovery codes for each.

### 8.11 Verification checklist after any recovery

- [ ] `https://www.hebridescyber.co.uk/api/health` is 200 and `supabase` is true
- [ ] bare domain returns a 301 to `www`; certificate valid
- [ ] `apply-migrations status` reports `0 pending` and no drift
- [ ] sign-in works (magic link and, if enabled, Google); MFA step-up works
- [ ] the dashboard loads for a Pro account and a Tier A account
- [ ] an on-demand scan queues, runs, completes, and shows results
- [ ] a scheduled-scans run completes (or trigger one)
- [ ] a test email is received (alert and scan-complete)
- [ ] Stripe: a test-mode checkout updates the plan; the webhook shows 200s
- [ ] Sentry receives a forced test error (web and worker)
- [ ] the uptime monitor and status page show green
- [ ] erasure requests from the gap are re-honoured (8.4)
- [ ] customers have been told what happened (section 9)

---

## 9. Communication

### 9.1 Status update (first, even without a cause)

> **Investigating** (HH:MM UTC): We are aware that [what customers see]. We are
> investigating. Scans already completed are unaffected. Next update by HH:MM.

Then **Identified**, **Monitoring** and **Resolved** with the same shape. State
what customers can and cannot do. Update at the time you promised.

### 9.2 Customer email when they were affected

> Subject: What happened on [date] and what it means for you
>
> On [date] from [time] to [time] UTC, [plain description]. [What was and was not
> affected, in one or two sentences: for example "Scans you started during this
> period did not complete, and scheduled alerts were not sent."] [What we have done
> and what you need to do, if anything.] We are sorry. [How to reach you.]

Do not say "no data was affected" unless you checked. Say what you know.

### 9.3 Checking who is asking

Before removing an MFA factor, changing an account's email or sharing anything
about an account, confirm the person controls the account email and ask for a
detail only the owner would know (a recent scan target, the plan). Do not act on
an unverified request, however urgent.

## 10. After every incident

Within a few days, add an entry to the log below and fix what made it hard.

**Template**

```
### YYYY-MM-DD: short title (SEV n)
- Detected: how and when (UTC)
- Impact: who and what, for how long
- Cause: what actually went wrong
- Resolution: what fixed it
- Customers told: when, how
- What went well:
- What made it hard:
- Follow-ups: (each becomes an issue or an OT item)
```

### Incident log

No incidents recorded yet.

## 11. Vendors and contacts

| Vendor | For | Status page / support |
|---|---|---|
| Supabase | database, auth | https://status.supabase.com, dashboard → Support |
| Microsoft Azure | Static Web Apps, Blob Storage, OpenAI | https://azure.status.microsoft, Azure portal → Help + support |
| GitHub | repository, Actions | https://www.githubstatus.com |
| Stripe | payments | https://status.stripe.com, dashboard → Support |
| Resend | email | their dashboard / status page |
| Sentry | error tracking | https://status.sentry.io |
| Upstash | rate limiting | their console / status page |
| GoDaddy | domain, DNS | account → Support |

The owner's contact details and each account's recovery codes belong in the
password manager. If someone other than the owner is on call, give them access to
it before they need it.

## 12. Keeping this runbook true

- Re-read it after any change to hosting, the deploy pipeline, the queue, or the
  secret list. A runbook that describes a system that no longer exists is worse
  than none.
- When an incident teaches you a step, add it here in the same week.
- Run the drills in 8.9 and replace every **(verify)** with what you saw.
- Owner-only steps (accounts, secrets, dashboards) are tracked in `OWNER-TODO.md`
  as `OT-nn` items: the restore drill is OT-12, the status page OT-27, error
  tracking OT-08, and uptime verification OT-09.
