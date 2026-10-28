# Incident runbook

What to do when something is broken in production. Three situations: **scans
are stuck**, **the site is down**, **the database is unavailable**. Each says
how to confirm it, what to try in order, and when to stop and escalate.
Companion to `BACKUP-RESTORE.md` (restores) and `NEXT-STEPS.md`
(current state). Owner-only steps are in `OWNER-TODO.md`.

**First, for any incident**
1. Say what you see, with the time. Keep a running note: it becomes the post-incident write-up.
2. Check `GET /api/health` on the live site. It returns booleans and a queue count only: `supabase` (a real query), `stripe` (a real API call) and the `scan_jobs` queue depth. `stripe: false` alone is a billing problem, not an outage.
3. Check the last **Deploy** run in GitHub Actions. If an outage started right after one, suspect it first.
4. Check Sentry (when `SENTRY_DSN` is set; see OT-08). Web errors and scan-worker errors both land there. A scan's id is its correlation id, so searching the scan id finds its log lines, its `scan_jobs` row and its Sentry events together.

## 1. Scans are stuck or not running

**Signs:** scans sit in "queued" or "scanning" in the dashboard; `/api/health` shows a large and growing queue depth; customers report no results.

**How scans flow:** `run-scan` creates a `scans` row and enqueues a `scan_jobs` row. GitHub Actions workers claim jobs: `scheduled-scans.yml` (cron, full tools) and `on-demand-scan.yml` (dispatched per request, passive). Nothing runs in the web app itself.

**Try, in order**
1. **Is a worker running?** GitHub → Actions → "Scheduled Scans" / "On-demand scan". No recent run means the cron or dispatch failed: check the workflow isn't disabled and re-run it with "Run workflow".
2. **Did a worker fail?** Open the failed run. A repo secret that is missing or expired (for example `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`) fails every job the same way.
3. **Is a job orphaned?** A runner killed mid-scan (out of memory, runner restart) leaves a `scan_jobs` row in `running` forever. `reset_stale_scan_jobs()` puts such rows back to `pending` only after **390 minutes**, deliberately longer than GitHub's 360-minute job ceiling so a live scan is never run twice (`041_reset_stale_scan_jobs.sql`). It runs at the start of every worker run. To do it by hand, use Admin → Queue → **Recover stuck jobs**; it applies the same 390-minute rule, so a job stuck for less than that is not touched. Do not shorten the threshold to "fix" a stuck job: that causes duplicate results, alerts and tickets.
4. **A single job failed:** Admin → Queue → **Retry** on that job.
5. **One tool hangs or misbehaves** (every scan slow, one tool in every error): Admin → Tools switches it off globally without a deploy (`055`). Re-enable after the fix.

**Escalate / stop** when jobs fail on every worker run after the secrets are confirmed: it is a code or dependency problem; check the last merge to `master`.

## 2. The site is down

**Signs:** `GET /api/health` returns non-200 or times out; the Deploy run's health check step warns; uptime monitor alerts.

**Try, in order**
1. **Which domain?** The bare domain only redirects to `www`; always test `https://www.hebridescyber.co.uk`.
2. **Was there a deploy?** Look at the latest **Deploy** run. If it failed before the deploy step, production is still on the previous build: not a deploy outage. If the post-deploy health check warned, production is on the new build and unhealthy.
3. **Roll back a bad deploy:** revert the offending commit on `master` (`git revert <sha>`, push). The push redeploys the previous behaviour. Prefer this to a forced reset. If the commit added a migration, read step 4 before reverting: migrations already applied stay applied.
4. **A migration broke something:** migrations auto-apply on push to `master` and are not rolled back by a code revert. Write a forward migration that fixes it (next free number, idempotent). Do not edit an applied migration: the checksum drift check will fail every deploy.
5. **Azure Static Web Apps itself:** check the Azure status page and the SWA resource in the portal. Nothing in this repo can fix an Azure incident; say so on the status page and wait.
6. **Only some pages fail:** open Sentry for the route's error before touching infrastructure.

## 3. The database is unavailable

**Signs:** `/api/health` has `supabase: false`; sign-in and the dashboard fail; scans can't be claimed.

**Try, in order**
1. Check the Supabase status page and the project's dashboard (paused? out of disk? over its connection limit?). A free-tier project pauses after inactivity.
2. Check `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` in the Azure SWA settings weren't changed or the key rotated. A bad key looks identical to an outage from `/api/health`.
3. If the password in `DATABASE_URL` was rotated, update the `DATABASE_URL` GitHub secret too (OT-01), or migrations and the deploy fail.
4. **Data loss or corruption:** do not restore over production. Follow `BACKUP-RESTORE.md` to restore into a scratch project first and compare. The free plan's backups are daily (up to 24 hours of data lost); point-in-time recovery needs a paid plan (OT-12 records the restore drill).
5. While it is down, scans in flight fail and are reported as failed, not clean; jobs resume once the database is back. Don't mark anything fixed by hand.

## After the incident

- Say what happened and what customers saw, in plain words, on the status page (when one is configured: `NEXT_PUBLIC_STATUS_PAGE_URL`, OT-27) and to affected customers by email if data or alerts were affected.
- Add a dated line below. Fix what made it hard to diagnose, not only what broke.

### Incident log

No incidents recorded yet.
