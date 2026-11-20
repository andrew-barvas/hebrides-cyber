# GitHub Actions workflows

Every workflow in the repo-root `.github/workflows/` (32 files, checked against
`master` on 2026-11-20). GitHub runs workflows only from there; there is no
workflow folder inside `hebridescyber-app/`. Times are UTC. GitHub's scheduler
often starts a cron run late, sometimes by hours, so a schedule here is the
earliest a run starts, not a guarantee.

Secrets are repository secrets (Settings → Secrets and variables → Actions →
Secrets); variables are repository variables (same page, Variables tab).
GitHub rejects secret names that start with `GITHUB_`, which is why the GitHub
App and token are stored as `GH_APP_ID`, `GH_APP_PRIVATE_KEY` and `GH_PAT`.

**Runner image.** Every job runs on `ubuntu-latest` except the `work` job in
`scheduled-scans.yml` and the job in `tool-integration.yml`, which are pinned
to `ubuntu-24.04` (#277). GitHub moved `ubuntu-latest` to 26.04, which ships
Python 3.14; prowler 5.47 refuses it and `docker/scan-tools.sh` installs
prowler as a hard requirement, so scheduled scans failed at tool install until
the pin. Keep the pin until prowler supports Python 3.14.

**When a scheduled job fails**, GitHub emails the person who last edited the
workflow's cron line, and the run shows red under Actions. Some jobs also open
or comment on a GitHub issue; that is noted per row.

## Deploy and quality gates

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `deploy.yml` (Deploy) | push and PR to `master`; manual (optional `baseline_up_to` to record old migrations as applied) | Runs lint, `tsc`, unit tests with coverage and Playwright e2e; on `master` applies migrations (`apply-migrations.ts`, ledger and checksum drift check), checks the schema, deploys to Azure Static Web Apps and curls `/api/health` | `AZURE_STATIC_WEB_APPS_API_TOKEN`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`, `SITE_URL`, `NEXT_PUBLIC_SENTRY_DSN`, `NEXT_PUBLIC_GA_MEASUREMENT_ID`, `NEXT_PUBLIC_STATUS_PAGE_URL`; variable `NEXT_PUBLIC_GOOGLE_SIGNIN` (shows "Continue with Google" when `true`, #273) | On a PR: a gate failed, don't merge. On `master`: the site was not deployed, or a migration failed to apply, or the deployed site's health check failed. Check which job is red |
| `db-tests.yml` (Database tests) | PR and push to `master` touching `sql/**`, `tests/db/**`, `attackSurfaceMonitor.ts`, `findingsView.ts`; manual | Applies every migration to a throwaway Postgres and tests RLS per role, `claim_scan_job()` concurrency and migration idempotency | none | A migration doesn't apply or re-apply cleanly, or a table's RLS doesn't match `rls.db.test.ts` |
| `dependency-audit.yml` | PR and push touching `package.json`/`package-lock.json`; Mondays 06:23; manual | `npm audit` of the app's own dependencies | none | A high or critical advisory in a production dependency. Dev-only advisories are listed in the summary but don't fail it |
| `npm-audit-fix.yml` | Mondays 06:47; manual | Runs `npm audit fix` (no `--force`) and opens or refreshes one rolling PR, branch `deps/npm-audit-fix` | `GH_PAT` (optional; without it the PR's checks need a close-and-reopen) | The fix or PR step failed; advisories may still be open |
| `sast-rules.yml` | PR and push touching `sast-rules/**`; manual | Runs the annotated tests beside each in-house code-scanning rule with the pinned Opengrep, and validates the rule files | none | A rule is broken or its tests don't match; merging it would make every code scan report `error` |
| `terraform-security-scan.yml` | push and PR touching `azure/terraform/**`; manual | Checkov static analysis of the Terraform, `soft_fail: false` | none | A new, untriaged infrastructure finding: fix it or add a documented skip in `main.tf` |
| `benchmark.yml` (Scanner accuracy benchmark) | Mondays 04:17; PR and push touching `src/lib/scanners/**` or `bench/**`; manual | Scores the base checks against local fixture sites; optional network job on manual dispatch | none | Precision or recall dropped below `bench/baseline.json`, or a must-find / must-not-find expectation broke. The network job never fails the run |
| `agent.yml` (Device Agent) — **new, P1-5** | PR and push to `master` touching `agent/**`; manual | `gofmt`, `go vet` and `go test` for the Go device agent on Linux, Windows and macOS (`-race` on Linux), then cross-compiles **unsigned** binaries for six targets with `SHA256SUMS` as a 14-day artifact | none | The agent doesn't build or a collector test broke. The artifact isn't for customers until signing exists (`agent/SIGNING.md`) |
| `tool-integration.yml` | Mondays 04:17; PR touching the tool wrappers, `crawler.ts`, `cveIndex.ts`, `execTool.ts` and similar; manual | Runs the real scan tools against a deliberately vulnerable app on localhost so the parsers are checked against real output. **Pinned to `ubuntu-24.04`** | none | A tool's output or install changed and a parser or install check no longer matches. On a tool-update PR this is the gate |
| `scan-worker-image.yml` | PR and push touching `Dockerfile`, `docker/**`; manual | Builds the `scan-worker` image without pushing; every pinned tool must download, match its SHA-256 and run; then checks the entrypoint reaches the worker | none | A tool pin is wrong or a tool no longer installs. Fix it before it reaches a scheduled scan |
| `scanner-tool-updates.yml` | Tuesdays 05:41; manual (optional single tool) | Checks every pinned scan tool against upstream and opens one PR per tool with a newer stable release at least 14 days old, hash cross-checked. Since #259 a failed update job runs `report-errors`, which opens or comments on one "Scanner tool auto-update needs attention" issue | `GH_PAT` (Contents, Pull requests and Workflows write) | Usually the `GH_PAT` push failed (OT-49). An issue is opened with the run link |

## Scans

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `scheduled-scans.yml` (Scheduled Scans) | daily 03:00; manual | `enqueue` adds a `scan_jobs` row for each verified monitored target that is due (Basic weekly, Pro/Agency daily); `work` installs the scan tools and a ZAP daemon and a matrix of shards drains the queue with `executeScan`; `verify` fails the run when scans ran the extended tier but no tool completed (`scanRunVerification.ts`). **`work` is pinned to `ubuntu-24.04`** | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `CREDENTIALS_ENC_KEY`, `RESEND_API_KEY`, `SENTRY_DSN`, `GH_APP_ID`, `GH_APP_PRIVATE_KEY`, `GH_PAT`, `AZURE_STORAGE_CONNECTION_STRING`, `AZURE_OPENAI_*`, `GOOGLE_SAFE_BROWSING_API_KEY`, `HIBP_API_KEY`, `NVD_API_KEY`, `WPSCAN_API_TOKEN`, `INTERACTSH_TOKEN`, `PROWLER_AWS_ACCESS_KEY_ID`, `PROWLER_AWS_SECRET_ACCESS_KEY`, `STRIX_LLM_API_KEY`; variables `NEXT_PUBLIC_SITE_URL`, `AI_TRIAGE`, `DISABLE_OAST`, `INTERACTSH_SERVER`. Optional keys only switch features on | Scheduled scans did not run or did not finish; jobs stay queued for the next run. Failed 2026-11-17 to 19 (tool install under Python 3.14) until #277 |
| `on-demand-scan.yml` (On-Demand Scan) | dispatched by the app (`onDemandScanTrigger.ts`) after a verified "Run scan" or `POST /api/v1/scans`; manual | Claims queued on-demand jobs and runs them passive-only (no tool installs) | Same core secrets as above minus the GitHub App, Azure Blob and Prowler ones; variables `NEXT_PUBLIC_SITE_URL`, `AI_TRIAGE`, `DISABLE_OAST`, `INTERACTSH_SERVER` | That customer's scan waits for the next scheduled run. If dispatch itself fails, the app falls back to the same |
| `easm-discovery.yml` (EASM Discovery) | every 6 hours at :25; manual (`dry_run`) | Finds newly certificated subdomains of every verified target of an active subscriber via certificate logs and HEAD probes, records them and alerts the owner | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | A due alert could not be delivered (it retries next sweep), or the sweep crashed. A certificate-log outage decides nothing and does not fail it |
| `cve-index-sync.yml` (CVE Index Sync) | nightly 02:50; manual (`max_pages`, default 200) | Pages NVD's CVE feed into the local CPE → CVE index used by service CVE matching. Since #268 the index is gzipped objects in the private Supabase Storage bucket `cve-index`, or Azure Blob when `CVE_INDEX_STORE=azure`. Resumable | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `NVD_API_KEY` (optional, 10x rate limit), `AZURE_STORAGE_CONNECTION_STRING` (only for the Azure backend); variable `CVE_INDEX_STORE` | The index wasn't refreshed. After 7 days without a successful run every service CVE lookup reports `error`, never "no CVEs". The file's header comment still says "migration 069" tables; that is stale, the tables were dropped in 081 |
| `device-inventory-match.yml` (Device Inventory Match) — **new, P1-5** | hourly at :17; manual (`dry_run`) | For each active device whose latest agent report is newer than its last match: OSV.dev for Debian/Ubuntu/Alma/Rocky packages, the CPE index for a curated list of desktop programs, endoflife.date for the OS, then re-checks the Cyber Essentials 14-day rule (`src/lib/deviceAgent/matchJob.ts`). Before migration 086 it exits with nothing to do | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AZURE_STORAGE_CONNECTION_STRING` (Azure CVE index only); variable `CVE_INDEX_STORE` | At least one device couldn't be matched (each error is listed). A failed OSV, index or endoflife.date lookup isn't a run failure: that device's match is stored as `partial` and shows as "not enough evidence" |
| `cve-index-export.yml` (CVE index export) | manual only | **One-off, already run** on 2026-11-20: copied 409,088 CVEs and 2,273,094 criteria from the old Postgres tables into object storage with the sync state. The tables are gone (migration 081), so it has no source now and is kept for reference | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`, `AZURE_STORAGE_CONNECTION_STRING`; variable `CVE_INDEX_STORE` | Expected if run now: there is nothing to export. Don't re-run |

## Customer email and alerts

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `weekly-fix-email.yml` (Weekly Fix Email) — **new, #255** | Mondays 08:00; manual | Emails each active subscriber the single most urgent open finding across their sites (top of the "fix this first" rank), how to fix it and a link to check it's fixed. Skips anyone who turned it off (`subscriptions.notify_weekly_fix`), anyone with nothing worth fixing, and anyone sent one in the last 6 days, so a re-run never double-sends | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | At least one send failed. Failed sends aren't recorded, so the next run (or a manual re-run) retries them |
| `emerging-threats.yml` (Emerging Threat Alerts) | every 6 hours at :40; manual (`dry_run`) | Matches CVEs newly added to CISA KEV against each paying customer's latest scan per site and alerts by email (and Slack/Teams on Pro and up) | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`, `NVD_API_KEY` (optional); variable `NEXT_PUBLIC_SITE_URL` | A KEV, NVD or OSV lookup or a send failed. Never treated as "not affected". NVD timeouts without a key are the usual cause (OT-17) |
| `scheduled-reports.yml` (Scheduled Reports) | hourly at :15; manual | Sends due daily, weekly and monthly reports to their recipients | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | A due report wasn't sent |
| `monthly-digest.yml` (Monthly Digest) | 1st of the month 07:30; manual | Sends each active subscriber one Security Score digest covering their monitored sites | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | The digest didn't go out |
| `uptime-sync.yml` (Uptime sync) | every 15 minutes; manual | Refreshes each customer's own UptimeRobot monitors and sends one down and one recovered message per outage | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `CREDENTIALS_ENC_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | Statuses weren't refreshed this round; a failed provider call never changes a stored status |
| `repo-link-reminders.yml` (Repo Link Reminders) — **new, #267** | manual only; `dry_run` defaults to **true** | Emails owners whose connected repositories aren't linked to a site, once per connection (`repo_connections.link_reminder_sent_at`). Since #248 an unlinked repository is never scanned. Run once with dry run to see the list, then again unticked | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`; variable `NEXT_PUBLIC_SITE_URL` | A send failed; it isn't recorded, so the next run retries |

## Content

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `daily-blog.yml` (Daily Cyber Security Brief) | daily 07:00; manual | Publishes the daily post from KEV, NVD and security news; AI write-up if Azure OpenAI is set, otherwise a templated post | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AZURE_OPENAI_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` (optional) | No post today |
| `weekly-newsletter.yml` (Weekly Newsletter) | Mondays 07:00; manual | Publishes the weekly roundup post | Same as the daily blog | No newsletter this week |
| `publish-scheduled-posts.yml` | hourly at :12; manual | Flips blog posts with status `scheduled` to `published` once their date passes | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | A scheduled post is late |

## Data protection and housekeeping

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `db-size-guard.yml` (DB size guard) — **new, #268** | daily 06:15; manual | Writes the database size and largest tables to the job summary against the Supabase Free plan's 500 MB. Emails a warning from 70% (350 MB) | `DATABASE_URL`, `RESEND_API_KEY`; variable `ALERT_EMAIL` (optional, default hello@hebridescyber.co.uk) | **The database is at or above 85% (425 MB)**, or the size couldn't be read. Over 100% Supabase can make the project read-only. Look at the largest tables in the summary. Expected size after #268: about 17 MB |
| `data-retention-cleanup.yml` | daily 04:00; manual | Deletes scan results older than 12 months, report PDFs older than 90 days and contact enquiries older than 12 months, as `/privacy` promises | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `AZURE_STORAGE_CONNECTION_STRING` (PDF cleanup skipped without it, OT-29) | Retention wasn't enforced today |
| `deletion-requests.yml` (Account deletion reminders) | daily 06:47; manual | Emails the operator about erasure requests due within 7 days or overdue. Erasure itself stays a manual command | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `RESEND_API_KEY`, `CONTACT_EMAIL` (optional) | A due reminder couldn't be sent: check the erasure queue by hand |
| `uptime.yml` (Uptime) | every 10 minutes; manual | Probes the live site's `/api/health` and checks the bare domain redirects to www; opens a GitHub issue labelled `uptime` when down or degraded and closes it on recovery | `SITE_URL` | The site is down or degraded (Supabase, Stripe or the queue check failed). Treat as an incident. Actions cron can run late, so this is a backstop, not the primary pager |

## Manual operations

| Workflow | Trigger | What it does | Secrets / variables | A failure means |
|---|---|---|---|---|
| `set-plan.yml` (Set account plan) | manual: email, plan, reason, `confirm` (dry run unless ticked) | Grants a plan outside Stripe, tagged `source='admin'` and audited | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | The grant wasn't written; nothing changed |
| `encrypt-stored-secrets.yml` | manual: `confirm` (dry run unless ticked) | Rewrites any customer secrets still stored in plaintext as encrypted; skips those already encrypted | `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `CREDENTIALS_ENC_KEY` | Some rows couldn't be encrypted; the summary lists them |
| `deploy-containerapp.yml` (Deploy (Container Apps)) | manual only | Alternative deploy of the site as a container to Azure Container Apps. Not the live path | `AZURE_CREDENTIALS`, `ACR_LOGIN_SERVER`, `ACR_USERNAME`, `ACR_PASSWORD`, `AZURE_RESOURCE_GROUP`, `AZURE_CONTAINER_APP_NAME`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SITE_URL` | The alternative deploy failed; the live site is unaffected |
| `deploy-scan-worker.yml` (Deploy (scan worker)) | manual only | Builds the `scan-worker` image and points the Azure Container Apps Job at it. Needs the owner's Terraform apply first; until then scans run in GitHub Actions | `AZURE_CREDENTIALS`, `ACR_LOGIN_SERVER`, `ACR_USERNAME`, `ACR_PASSWORD`, `AZURE_RESOURCE_GROUP` | The always-on worker wasn't updated; GitHub Actions scanning is unaffected |

## Added or changed since 2026-11-18

| Change | PR |
|---|---|
| `weekly-fix-email.yml` added | #255 |
| `repo-link-reminders.yml` added | #267 |
| `db-size-guard.yml` and `cve-index-export.yml` added; `cve-index-sync.yml` gains `CVE_INDEX_STORE`, `AZURE_STORAGE_CONNECTION_STRING` and a larger Node heap for a full rebuild; `tool-integration.yml` builds the prowler environment with the system Python | #268 |
| `scanner-tool-updates.yml` opens an issue when an update push fails | #259 |
| `scheduled-scans.yml` `work` job and `tool-integration.yml` pinned to `ubuntu-24.04` | #277 |
| `deploy.yml` builds `NEXT_PUBLIC_GOOGLE_SIGNIN` into the site | #273 |
| `agent.yml` and `device-inventory-match.yml` added (device patch-audit agent) | P1-5 |
| Dependabot bumps to pinned actions (Checkov action, Docker login action) | #244, #215 |
