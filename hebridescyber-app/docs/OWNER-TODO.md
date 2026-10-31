# Owner to-do list

Manual steps only the owner can do: accounts, secrets, legal, decisions,
anything outside the code. Development work is not listed here; it goes in
`NEXT-STEPS.md` and gets done in PRs.

**How this list works**
- Each item has an ID (`OT-nn`) that never changes or gets reused. Finished
  items stay, marked Done with the date, so the history is kept.
- **Raised** is when the need was first recorded, with the source.
- **Actioned** is the date you did it. Whoever finds the item done (you, or a
  Claude session that verified it) fills it in.
- **Status** is one of:
  - **Open:** not done.
  - **Check:** a session can't see whether it's done (for example Azure app
    settings), so it needs your confirmation.
  - **Decision:** needs your call, not a task.
  - **Done**
- Claude sessions add an item whenever they find a step that needs you, and
  close one when they can prove it's done. Proof means a passing health
  check, a secret present in `gh secret list`, a run log, or similar. Your
  say-so in chat counts too; record it as "owner confirmed".
- Detailed walkthroughs already in `OWNER-SETUP.md` are linked, not copied.

Raised dates are the first commit that recorded each item. Last reviewed:
2026-10-27, with each item checked against the live site,
`gh secret list` (names only) and workflow logs.

## Summary

| ID | Item | Priority | Status | Raised | Actioned |
|---|---|---|---|---|---|
| OT-01 | Rotate the Supabase database password | 🔴 Critical | Open | 2026-10-14 | |
| OT-02 | Add `RESEND_API_KEY` (no scheduled email has been sent) | 🔴 Critical | Open | 2026-10-06 | |
| OT-03 | Review and merge #107 (cookie settings, Sentry in the privacy policy) | 🔴 High | Open | 2026-10-26 | |
| OT-04 | Decide on #110 (Tier A plan checks), closed unmerged | 🟠 High | Decision | 2026-10-27 | |
| OT-05 | Confirm `CREDENTIALS_ENC_KEY` in Azure and encrypt stored secrets | 🟠 High | Check | 2026-10-14 | |
| OT-28 | Decide whether to rotate `CREDENTIALS_ENC_KEY` (it was exposed as a plaintext variable) | 🟠 High | Decision | 2026-10-28 | |
| OT-29 | `AZURE_STORAGE_CONNECTION_STRING` (the 90-day report PDF retention job skips without it) | 🟠 High | Check | 2026-10-28 | |
| OT-06 | Upstash Redis for rate limiting (fails open without it) | 🟠 High | Check | 2026-08-17 | |
| OT-07 | Branch protection on `master` | 🟠 High | Open | 2026-08-26 | |
| OT-08 | `NEXT_PUBLIC_SENTRY_DSN`, plus `SENTRY_DSN` in Azure | 🟡 Medium | Open | 2026-09-04 | |
| OT-09 | Verify uptime monitoring with a real free UptimeRobot key | 🟡 Medium | Open | 2026-10-26 | |
| OT-10 | Decide plan gating for AI fix, API keys, share links, tickets (H5) | 🟡 Medium | Decision | 2026-10-06 | |
| OT-11 | Provision an owned, deliberately vulnerable staging target (H3) | 🟡 Medium | Open | 2026-08-26 | |
| OT-12 | Restore drill: restore a backup into a scratch project | 🟡 Medium | Open | 2026-10-06 | |
| OT-13 | Solicitor review of the ToS; PI insurance before any offensive traffic | 🟡 Medium | Open | 2026-08-26 | |
| OT-14 | Marketing and grant copy integrity pass | 🟡 Medium | Open | 2026-10-22 | |
| OT-15 | Approve pruning stale merged remote branches | 🟢 Low | Decision | 2026-10-22 | |
| OT-16 | Run the Container Apps deploy once (Dependabot action majors) | 🟢 Low | Open | 2026-10-26 | |
| OT-17 | Optional scanner secrets: `HIBP_API_KEY`, `NVD_API_KEY`, `INTERACTSH_TOKEN` | 🟢 Low | Open | 2026-10-27 | |
| OT-18 | Optional AI secrets: `AZURE_OPENAI_*` (AI triage, blog and newsletter write-ups) | 🟢 Low | Open | 2026-10-27 | |
| OT-19 | DNS: CAA record, `hebridescyber.com`, a `security@` alias | 🟢 Low | Open | 2026-10-06 | |
| OT-20 | Publish the GitHub Action from a public repository | 🟢 Low | Open | 2026-10-06 | |
| OT-21 | NCSC replacement campaign: blog post and marketing drafts | 🟢 Low | Open | 2026-10-06 | |
| OT-22 | Review the login-recording consent copy | 🟢 Low | Open | 2026-10-05 | |
| OT-30 | Delete three unused GitHub secrets | 🟢 Low | Open | 2026-10-28 | |
| OT-31 | Optional: `CONTACT_EMAIL` and a GitHub App | 🟢 Low | Open | 2026-10-28 | |
| OT-46 | Prowler IAM check: create our AWS scan identity and secrets, then verify against a real account | 🟡 Medium | Open | 2026-10-31 | |
| OT-47 | Optional: hash-pin Prowler's Python dependencies | 🟢 Low | Open | 2026-10-31 | |
| OT-23 | Decide whether to build the supplier security rating | 🟢 Strategic | Decision | 2026-10-27 | |
| OT-24 | Stripe keys and price IDs | — | Done | 2026-10-06 | by 2026-10-27 |
| OT-25 | `SITE_URL` and `DATABASE_URL` deploy secrets | — | Done | 2026-09-25 | 2026-10-14 |
| OT-26 | `SENTRY_DSN` GitHub secret (scan-worker errors) | — | Done | 2026-10-23 | 2026-10-23 |
| OT-27 | Create a public status page and set `NEXT_PUBLIC_STATUS_PAGE_URL` | 🟡 Medium | Open | 2026-10-28 | |
| OT-32 | `NEXT_PUBLIC_SITE_URL` variable pointed at the Azure hostname | — | Done | 2026-10-28 | 2026-10-26 |
| OT-33 | Lookout: check the name (UK trademark, domain) and sign off prices | 🟡 Medium | Decision | 2026-10-30 | |
| OT-34 | Lookout: create six Stripe prices and add the env vars | 🟡 Medium | Open | 2026-10-30 | |
| OT-35 | Lookout: solicitor wording for a "managed exposure review" in the ToS | 🟡 Medium | Open | 2026-10-30 | |
| OT-36 | Decide where OpenVAS runs if the Actions prototype doesn't fit | 🟢 Low | Decision | 2026-10-30 | |
| OT-37 | Decide whether the container registry stays on the Basic SKU | 🟢 Low | Decision | 2026-10-30 | |
| OT-38 | Choose an auditor and SOC 2 / ISO 27001 scope | 🟢 Strategic | Decision | 2026-10-31 | |
| OT-39 | Write the core security policies | 🟢 Strategic | Open | 2026-10-31 | |
| OT-40 | Choose a compliance automation platform | 🟢 Strategic | Decision | 2026-10-31 | |
| OT-41 | Commission an independent penetration test | 🟢 Strategic | Open | 2026-10-31 | |

## Items

### OT-01: Rotate the Supabase database password 🔴
- **What and why:** the password inside `DATABASE_URL` was pasted into a chat
  during setup on 2026-10-14, so treat it as exposed. That URL gives full
  database access.
- **How:** follow `OWNER-SETUP.md` §1. Reset the password in Supabase
  (Project settings → Database), then update the `DATABASE_URL` GitHub secret.
- **Verify:** the next push to `master` passes "Apply migrations + verify
  schema". `gh secret list` shows `DATABASE_URL` with a date after 2026-10-14
  (on 2026-10-27 it still showed 2026-10-14).
- **Raised:** 2026-10-14 (`NEXT-STEPS.md`, Owner actions 0 and 4).

### OT-02: Add `RESEND_API_KEY` 🔴
- **What and why:** every worker email goes through Resend (`src/lib/email.ts`),
  and the secret isn't set. Eight workflows use it: `scheduled-scans.yml`,
  `on-demand-scan.yml`, `scheduled-reports.yml`, `monthly-digest.yml`,
  `emerging-threats.yml`, `uptime-sync.yml`, `deletion-requests.yml` and
  `easm-discovery.yml`. Without it there are no critical-finding or scan-complete
  emails, no scheduled reports, no digest, no uptime-down emails, no new-hostname
  alerts from the 6-hourly EASM sweep, and no erasure-deadline reminders. The EASM
  sweep run fails (red in Actions) whenever a new-hostname alert is due and cannot
  be delivered, then retries on the next sweep, so it will show the problem rather
  than stay green. Owners with Slack or Teams set up are still told through those. The 2026-10-27 scheduled-reports run logged `RESEND_API_KEY:`
  empty and "sent 0".
- **How:**
  1. Create a Resend account.
  2. Add and verify the domain `hebridescyber.co.uk`. Resend gives you DKIM
     and SPF records to add at GoDaddy.
  3. Create an API key with sending access.
  4. Add it as the GitHub secret `RESEND_API_KEY`, and as an Azure Static Web
     App setting if the contact form should send too.
- **Verify:** dispatch "Scheduled Reports" in Actions. The log shows a
  non-empty key and, with a report configured, "sent 1". Our own scanner's
  DNS checks should still pass SPF and DMARC afterwards.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` plan item 7: "the scan workers never
  had `RESEND_API_KEY`"). Confirmed missing on 2026-10-27.

### OT-03: Review and merge #107 🔴
- **What and why:** `NEXT_PUBLIC_GA_MEASUREMENT_ID` was set on 2026-10-24, so
  every deploy now builds Google Analytics in (it loads only after a visitor
  accepts the banner). #107 adds the footer "Cookie settings" control the
  privacy policy promises, so visitors can withdraw consent. It also adds
  Sentry to the policy's list of processors. Its merge was held for you to
  approve the policy wording.
- **How:**
  1. Read the privacy-policy diff in
     https://github.com/andrew-barvas/hebrides-cyber/pull/107.
  2. Mark it ready.
  3. Squash-merge it, or ask a session to.
- **Verify:** the live footer shows "Cookie settings", and it reopens the
  banner.
- **Raised:** 2026-10-26 (#107 description).

### OT-04: Decide on #110 (Tier A plan checks) 🟠
- **What and why:** #110 made every dashboard and account plan check include
  Tier A. Without it, Tier A customers see paid features locked that the API
  allows, and the Tier A Overview page throws an error, which includes the
  seeded staff account. CI was green. It was closed from your GitHub account
  at 20:57 UTC on 2026-10-27 with no comment. The branch was deleted and then
  restored.
- **Your call:** reopen and merge it, or tell a session why it was dropped.
  If it's kept: the server-side jobs that also leave out Tier A are listed in
  its description (`emergingThreatAlerts.ts`, `attackSurfaceMonitor.ts`,
  `lookalikeDomainMonitor.ts`, the scan-alert check in `scanExecution.ts`, and
  `scanCadence.ts`) and would be a follow-up PR.
- **Raised:** 2026-10-27.

### OT-05: Confirm `CREDENTIALS_ENC_KEY` in Azure and encrypt stored secrets 🟠
- **What and why:** the GitHub secret exists (2026-10-15). The Azure Static
  Web App needs the **same value**, or saving any integration token returns
  503. Secrets saved before the key existed stay plaintext until the
  "Encrypt stored secrets" workflow runs.
- **How:** follow `NEXT-STEPS.md` Owner actions 0, steps 2 and 3:
  1. Set the Azure app setting.
  2. Run Actions → "Encrypt stored secrets" as a dry run.
  3. Run it again with "confirm" ticked.
- **Verify:** saving a Slack webhook on Integrations succeeds, and the
  workflow's confirm run reports 0 plaintext rows left.
- **Raised:** 2026-10-14.

### OT-06: Upstash Redis for rate limiting 🟠
- **What and why:** `src/lib/rateLimit.ts` **fails open** when
  `UPSTASH_REDIS_REST_URL`/`_TOKEN` aren't set. That leaves no limit on
  scans, logins-adjacent routes or the API. These are Azure app settings, so a
  session can't see them.
- **How:** follow `OWNER-SETUP.md` §5. Create a free Upstash Redis database
  and add both values as Azure Static Web App settings.
- **Verify:** hammering `POST /api/scan` from one IP returns 429.
- **Raised:** 2026-08-17.

### OT-07: Branch protection on `master` 🟠
- **What and why:** `master` has no protection rule (the GitHub API returned
  "Branch not protected" on 2026-10-27). A PR with failing tests can be
  merged, and every merge deploys to production.
- **How:** follow `OWNER-SETUP.md` §4b. A private repo needs GitHub Pro.
  Require a PR and the `Lint, typecheck, test` check.
- **Verify:** on a deliberately failing PR, the merge button is blocked.
- **Raised:** 2026-08-26 (BETA-5).

### OT-08: Browser and app-side Sentry 🟡
- **What and why:** `SENTRY_DSN` is a GitHub secret (scan workers, done in
  OT-26). `NEXT_PUBLIC_SENTRY_DSN`, which `deploy.yml` reads for browser
  errors, isn't set. The Azure app setting `SENTRY_DSN`, for API routes, can't
  be seen from here.
- **How:** follow `OWNER-SETUP.md` §3. Add the GitHub secret
  `NEXT_PUBLIC_SENTRY_DSN`, which can be the same DSN, and the Azure app
  setting `SENTRY_DSN`.
- **Verify:** throw a test error from the site and see it in Sentry.
- **Raised:** 2026-09-04 (E-03 / BETA-1).

### OT-09: Verify uptime monitoring with a real UptimeRobot key 🟡
- **What and why:** the UptimeRobot v3 client was built from documentation
  and recorded shapes, not a live account. That a dashboard API key works as
  the v3 bearer token, and that status strings map as expected, is
  unverified until someone tries it.
- **How:** follow `OWNER-SETUP.md`, "Verify uptime monitoring with a real
  UptimeRobot key". Enter the key only in the dashboard field, never in chat.
- **Verify:** that section's checklist passes. A paused monitor shows
  "Paused", and a down/up cycle sends one message each way (this needs OT-02
  for the email part).
- **Raised:** 2026-10-26 (#102 and #103).

### OT-10: Decide plan gating for open routes (H5) 🟡
- **What and why:** `ai-fix`, `keys` (API keys), `shares` (share links),
  `create-ticket` and `scheduled-reports` have no plan gate, so any signed-in
  account can use them. No pricing page promises them for a tier, so gating
  them would be new policy.
- **Recommendation:**
  - Gate AI fix and API keys to Pro and above: they cost money, and API keys
    are a Pro/Agency feature in the API docs.
  - Leave share links and tickets on every paid plan.
  - Leave scheduled reports as the plan page says.
  - Once you decide, a session pins it in tests (`SPRINT-PLAN.md` H5-1).
- **Raised:** 2026-10-06 (`NEXT-STEPS.md`, "Owner decisions needed").

### OT-11: Provision a deliberately vulnerable staging target (H3) 🟡
- **What and why:** proving the extended tools find real issues in
  production (H3, POC-1, POC-5) needs a target we own and are allowed to
  attack.
- **How:** deploy OWASP Juice Shop, or a similar target, on a free host under
  a subdomain such as `lab.hebridescyber.co.uk`. Verify the domain in the
  dashboard and add it as a monitored site on an internal account.
- **Verify:** a scheduled scan of it has extended tools reporting
  `completed`, with findings. The H3 `verify` job in `scheduled-scans.yml`
  checks this.
- **Raised:** 2026-08-26 (staging target); 2026-10-22 (`SPRINT-PLAN.md` H3).

### OT-12: Restore drill 🟡
- **What and why:** backups are untested until one has been restored.
- **How:** follow `BACKUP-RESTORE.md`. Restore into a scratch Supabase project
  and record the date and result there. Consider Supabase Pro for
  point-in-time recovery.
- **Raised:** 2026-10-06 (E-13 / LIVE-4).

### OT-13: ToS solicitor review; PI insurance before offensive traffic 🟡
- **What and why:** the terms (`docs/legal/terms-of-service-draft.md`) haven't
  been reviewed by a solicitor (BETA-B1). Tier A's offensive tools must not
  send real attack traffic until the customer contract authorises it and PI
  insurance covers it. Your 2026-10-23 decision stands: leave them
  `not_configured` and don't market them.
- **Raised:** 2026-08-26 (BETA-B1); 2026-10-12 (Tier A, `NEXT-STEPS.md` item
  11).

### OT-14: Marketing and grant copy integrity pass 🟡
- **What and why:** some marketing and grant copy claims things the product
  doesn't do: SSO/SAML, RBAC, SCIM, an MSP portal, "autonomous AI pen-test",
  and unsourced statistics such as the "43%" figure in
  `marketing/11-social-media-and-local-press-playbook.md`. The site's own
  Tier A pricing card is fixed in code separately.
- **How:** read `marketing/` and `marketing/12-hie-grant-application.md`
  against `docs/FUNCTIONALITY-MATRIX.md`, then remove or source each claim.
- **Raised:** 2026-10-22 (`SPRINT-PLAN.md` H5, `PRODUCT-REVIEW-2026-10.md`
  P0-2).

### OT-15: Approve pruning stale merged remote branches 🟢
- **What and why:** about 20 merged branches are still on GitHub (H5). It's
  harmless but noisy. Deleting them is reversible: each merged PR keeps a
  "Restore branch" button.
- **Your call:** say "prune merged branches" and a session will delete only
  those whose PR is merged.
- **Raised:** 2026-10-22.

### OT-16: Run the Container Apps deploy once 🟢
- **What and why:** #51, #52 and #53 moved `deploy-containerapp.yml` to the
  Node 24 majors of its actions. It's only run by hand, so they're
  unverified. This only matters if you use the Container Apps path.
- **How:** Actions → "Deploy to Azure Container Apps" → Run workflow, or use
  the `deploy-containerapp` skill.
- **Raised:** 2026-10-26.

### OT-17: Optional scanner secrets 🟢
- **What and why:**
  - `HIBP_API_KEY` enables breach checks (paid, and needs HIBP domain
    verification).
  - `NVD_API_KEY` raises NVD rate limits for CVE lookups.
  - `INTERACTSH_TOKEN` gives a private out-of-band server for nuclei's
    SSRF/OAST templates. Without it they use the public pool.
  - Each check reports `not_configured` without its key. Nothing fails.
- **How:** add each as a GitHub secret.
- **Raised:** 2026-10-27 (secrets audit).

### OT-18: Optional AI secrets 🟢
- **What and why:** `AZURE_OPENAI_ENDPOINT`, `_KEY` and `_DEPLOYMENT` enable
  AI triage (off by default; `AI_TRIAGE=1`) and the AI write-ups in
  `daily-blog.yml` and `weekly-newsletter.yml`. Without them those parts are
  skipped.
- **Raised:** 2026-10-27 (secrets audit).

### OT-19: DNS housekeeping 🟢
- **How:**
  1. Add a CAA record at GoDaddy (`0 issue "digicert.com"`, or the CA that
     Azure SWA actually uses: check the live certificate's issuer first),
     then rerun the own-site scan.
  2. Defensively register `hebridescyber.com`.
  3. Optionally add a `security@hebridescyber.co.uk` alias for
     `security.txt`.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 6 and 9).

### OT-20: Publish the GitHub Action publicly 🟢
- **What and why:** this repo is private, so customers can't `uses:` the
  action. Publish it from a small public repository.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 5).

### OT-21: NCSC replacement campaign 🟢
- **How:**
  1. Run `sql/seed/002_ncsc_web_check_retirement_post.sql` in the Supabase
     SQL editor to publish the post.
  2. Send or post the drafts in `marketing/16-ncsc-replacement-campaign.md`.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 8).

### OT-22: Review the login-recording consent copy 🟢
- **What and why:** "login recording" is the authenticated-scan feature. It
  drives a customer's own login form once to capture a session for the
  signed-in crawl. Before it's promoted beyond the dashboard form, its
  checkbox and any marketing copy need a wording review. The copy must say to
  use a dedicated test account, never a personal or admin login
  (`AUTHENTICATED-CRAWL.md`, "Still open").
- **How:** read the consent text in the authenticated-scan form under Assets,
  and any marketing mention, against that note. Approve or reword.
- **Raised:** 2026-10-05.

### OT-23: Decide whether to build the supplier security rating 🟢
- **What and why:** the 2026-10-27 competitor analysis ranked an A–F rating
  for any domain the top new product line. The comparison is UpGuard Vendor
  Risk at $1,750/month for 50 vendors. About 80% of the checks already exist.
  It needs a ToS and policy change, because results currently require domain
  verification, so it depends on OT-13.
- **Your call:** go or no-go. On go, a session writes the design.
- **Raised:** 2026-10-27.

### OT-24: Stripe ✅
Done. The live `/api/health` reported `stripe: ok` (overall `ok`) on
2026-10-27.

### OT-25: `SITE_URL` and `DATABASE_URL` deploy secrets ✅
Done 2026-10-14. Since #111, the post-deploy health check follows the
bare-domain redirect, so `SITE_URL` doesn't need changing to `www`.

### OT-27: Public status page 🟡
- **What and why:** launch priority #2 wants a status page linked from the
  footer. The footer now shows a "Status" link as soon as
  `NEXT_PUBLIC_STATUS_PAGE_URL` is set to an https URL; until then it shows
  nothing. A status page hosted on the same site would be down with it, so it
  needs to be external.
- **How:** create a free public status page (an UptimeRobot status page works,
  and OT-09's monitor can feed it). Add its URL as the GitHub secret
  `NEXT_PUBLIC_STATUS_PAGE_URL`, then push to `master` (or re-run Deploy) so it
  is built in.
- **Verify:** the live footer shows "Status" and the link opens the page.
- **Raised:** 2026-10-28 (launch priority #2, AC4).

### OT-28: Decide whether to rotate `CREDENTIALS_ENC_KEY` 🟠
- **What and why:** from 2026-10-14 to 2026-10-26 a GitHub **repository
  variable** named `CREDENTIALS_ENC_KEY` held the encryption key in plaintext.
  Variables are not hidden the way secrets are, so anyone with read access to
  the repo could see it, and it was printed into a Claude session transcript
  on 2026-10-25. Nothing read it, and it was deleted on 2026-10-26. If the
  real secret (set 2026-10-15) holds the same value, treat that key as
  exposed. The code supports exactly one key, so rotating makes anything
  already encrypted unreadable until it is entered again.
- **How:**
  1. In the Supabase table editor, count the rows in `ticket_integrations`,
     `target_auth_credentials` and `cloud_credentials`.
  2. If no customer has saved a credential, rotate. Generate a key with
     `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`,
     then set it as the GitHub secret `CREDENTIALS_ENC_KEY` and as the Azure
     app setting, with the same value. This is also OT-05 step 1.
  3. If customers have saved credentials, ask a session to build a
     previous-key fallback and a re-encrypt step first. That is not built.
- **Verify:** `gh secret list` shows `CREDENTIALS_ENC_KEY` dated after
  2026-10-26, and saving an integration on the Integrations page succeeds.
- **Raised:** 2026-10-28 (found 2026-10-25 while auditing GitHub variables).

### OT-29: `AZURE_STORAGE_CONNECTION_STRING` GitHub secret 🟠
- **What and why:** `/privacy` promises report PDFs are deleted after 90 days.
  `data-retention-cleanup.yml` does that against the "reports" Blob container,
  but only when this secret is set. Without it the job logs "skipping PDF
  report cleanup" and deletes nothing, so any PDFs stored in Blob Storage stay
  past the published window. A session can't see whether the site is storing
  PDFs there, which needs the same value as an Azure app setting.
- **How:**
  1. In the Azure portal open the storage account, then Security +
     networking → Access keys, and copy a connection string.
  2. Add it as the GitHub secret `AZURE_STORAGE_CONNECTION_STRING`.
  3. Run Actions → "Data Retention Cleanup" once.
- **Verify:** the run log no longer says "skipping PDF report cleanup" and
  reports how many blobs it deleted (0 is fine if none are over 90 days old).
- **Raised:** 2026-10-28 (secrets audit).

### OT-30: Delete three unused GitHub secrets 🟢
- **What and why:** `DIGEST_SERVICE_TOKEN`, `NEWSLETTER_SERVICE_TOKEN` and
  `NEXT_PUBLIC_AZURE_FUNCTIONS_URL` belonged to routes and a Functions app
  that no longer exist. No workflow or source file reads them; the only
  mentions of `DIGEST_SERVICE_TOKEN` are comments saying it is no longer
  needed. An unused secret is a credential nobody is watching.
- **How:** Settings → Secrets and variables → Actions → delete each one, or
  `gh secret delete <NAME> --repo andrew-barvas/hebrides-cyber`.
- **Verify:** `gh secret list` no longer shows them, and the next push to
  `master` still deploys.
- **Raised:** 2026-10-28 (secrets audit).

### OT-31: Optional: `CONTACT_EMAIL` and a GitHub App 🟢
- **What and why:** two optional settings that are blank today.
  - `CONTACT_EMAIL` is where the erasure-deadline reminder is sent. It
    defaults to `hello@hebridescyber.co.uk`, so set it only if that is not the
    mailbox you read.
  - `GH_APP_ID` and `GH_APP_PRIVATE_KEY` let fix pull requests and repo scans
    use a per-repo GitHub App token instead of the shared `GH_PAT`, which
    reaches more than it needs to. The header of `src/lib/githubApp.ts`
    explains the trade-off.
- **How:** add each as a GitHub secret. For the App, create it with contents
  and pull-request write access and install it on the repos it should reach.
- **Verify:** `gh secret list` shows the names. For the App, a fix pull request
  on an installed repo opens without using `GH_PAT`.
- **Raised:** 2026-10-28 (secrets audit).

### OT-33: Lookout name and prices 🟡
- **What and why:** the plan (`DEFENSIVE-ASSESSMENT-PLAN.md`) uses the working
  name "Lookout" and proposes Essentials £149/mo and Assured £299/mo. You chose
  these on 2026-10-30, but the name has not been checked.
- **How:** search the UK IPO trade-mark register and Companies House for
  "Lookout" in cyber security (class 42, and 9 if it becomes software); check a
  domain or subdomain is free. Confirm VAT treatment of the prices.
- **Verify:** a short written result (clear, or pick Beacon / Harbour Watch).
- **Raised:** 2026-10-30.

### OT-34: Lookout Stripe prices 🟡
- **What and why:** you chose Stripe checkout from day one. Billing is
  monthly-only today, so this needs six new prices: Essentials and Assured, each
  monthly, quarterly and annual.
- **How:** create the six recurring prices in the Stripe dashboard, then add
  their IDs as env vars once the code names them (`create-checkout-session.ts`
  `PRICE_IDS`). Do not publish checkout before the pilot criteria in the plan.
- **Verify:** a test-mode checkout completes for each price.
- **Raised:** 2026-10-30.

### OT-35: ToS wording for the managed exposure review 🟡
- **What and why:** `src/app/terms/page.tsx` §2 lists the services. Lookout is a
  recurring, analyst-written service with scan windows and fair-use hours, and
  it uses active (non-injecting) scanning on verified domains. Wording needs a
  solicitor, together with OT-13.
- **How:** send the plan's service description and the copy draft
  (`marketing/17-lookout-managed-exposure-review.md`) with the OT-13 brief.
- **Verify:** approved wording merged into the terms.
- **Raised:** 2026-10-30.

### OT-36: Where OpenVAS runs 🟢
- **What and why:** you chose to add OpenVAS and Nikto. OpenVAS needs a large
  feed sync and several services, which may not fit the ephemeral Actions
  runners. Decide after the prototype in the plan.
- **How:** once the prototype reports feed size and time-to-first-scan, choose
  Actions, a small VM, or a Container Apps job.
- **Verify:** a decision recorded here.
- **Raised:** 2026-10-30.

### OT-37: Container registry SKU 🟢
- **What and why:** the Checkov scan flags six settings on the Container Apps
  registry (`hebridescyberacr` in `azure/terraform/main.tf`) that need the
  Premium SKU: no public network access, untagged-image cleanup,
  geo-replication, image quarantine, dedicated data endpoints and signed
  images. Premium costs roughly ten times Basic each month. They're skipped
  with reasons in `main.tf` so the scan passes. Image vulnerability scanning
  (CKV_AZURE_163) is a separate paid Defender for Containers plan. None of
  this matters unless you use the Container Apps path (OT-16).
- **How:** keep Basic (no action), or move to Premium and replace the skips
  with the real settings. Turn on Defender for Containers separately if you
  want image scanning.
- **Verify:** a decision recorded here.
- **Raised:** 2026-10-30.

### OT-38: Choose an auditor and certification scope 🟢
- **What and why:** the repo-side evidence map is `CONTROLS-EVIDENCE.md` and
  the public `/trust` page says we are not certified. Getting attested needs
  an external auditor and a decision on SOC 2 Type I/II versus ISO 27001, and
  on whether it is worth the cost yet.
- **How:** get two or three quotes; share `docs/CONTROLS-EVIDENCE.md` with them.
- **Verify:** a decision recorded here. Only after an auditor's report may
  `/trust` change its certification wording.
- **Raised:** 2026-10-31.

### OT-39: Write the core security policies 🟢
- **What and why:** auditors need written policies (information security,
  access control, incident response, change management, supplier management,
  data classification and retention, ISMS scope and roles). The repo has
  engineering controls but not these documents.
- **How:** draft them yourself or via the platform chosen in OT-40, then
  record the approval date and owner for each.
- **Verify:** policies exist and are linked from the evidence map.
- **Raised:** 2026-10-31.

### OT-40: Choose a compliance automation platform 🟢
- **What and why:** tools such as Vanta, Drata or Secureframe collect
  evidence continuously and supply policy templates. Optional; an auditor can
  work without one. It costs money each year.
- **How:** decide after OT-38, since some auditors partner with a platform.
- **Verify:** a decision recorded here.
- **Raised:** 2026-10-31.

### OT-41: Commission an independent penetration test 🟢
- **What and why:** an external test of the platform itself is expected
  evidence for both standards. Needs a budget and a written scope and
  agreement with the tester.
- **How:** pick a CREST-accredited provider, agree scope, and run it against a
  staging copy where possible. Keep the report private.
- **Verify:** a report received and findings triaged.

### OT-46: Prowler IAM check: AWS scan identity, secrets, first real run 🟡
- **What and why:** the Prowler IAM / privilege-escalation check
  (`src/worker/tools/prowlerIam.ts`) assumes each customer's read-only role
  from an AWS identity of ours. That identity doesn't exist yet, so for any
  owner who connects a role the check reports an error (never a clean result).
  It was also never run against a real AWS account: its tests use a
  hand-built report in Prowler's documented format.
- **How:**
  1. In an AWS account you control, create an IAM user (or role) allowed only
     `sts:AssumeRole` on `*`. Note its account id.
  2. Add GitHub secrets `PROWLER_AWS_ACCESS_KEY_ID` and
     `PROWLER_AWS_SECRET_ACCESS_KEY` for it, and set `PROWLER_PLATFORM_AWS_ACCOUNT_ID`
     (the account id, not secret) as an app setting in Azure; the dashboard
     shows it to customers for their trust policy.
  3. In a test AWS account, create role `HebridesCyberAudit` with managed
     policies `SecurityAudit` and `ViewOnlyAccess`, trusting that identity
     with condition `sts:ExternalId` = the id the dashboard shows after
     "Generate external ID" (Account, Cloud Posture Scanning).
  4. Save the role ARN, run a scheduled scan, check the scan's `prowler`
     result is `completed` with the account listed.
  5. Run `prowler aws --role <arn> --external-id <id> -s iam -M json-ocsf
     --ignore-exit-code-3`, redact account ids, and replace
     `src/worker/tools/fixtures/prowler/iam-ocsf-5.47.0.json` with the real
     capture (tests will show any shape difference).
- **Walkthrough for customers and for step 3:** `docs/AWS-IAM-POSTURE.md`.
- **Verify:** `completed` result with the account listed; real fixture merged.
- **Raised:** 2026-10-31.

### OT-47: Optional: hash-pin Prowler's Python dependencies 🟢
- **What and why:** the workflow verifies Prowler's own wheel by SHA-256, but
  pip resolves its dependencies at install time without hashes.
- **How:** generate a hashed lockfile (`pip-compile --generate-hashes`) in a
  clean Python 3.12 venv and install with `--require-hashes`.
- **Verify:** the install step uses the lockfile.
- **Raised:** 2026-10-31.

### OT-26: `SENTRY_DSN` GitHub secret ✅
Done 2026-10-23 (`gh secret list`). It covers scan-worker errors; see OT-08
for the browser and API side.

### OT-32: `NEXT_PUBLIC_SITE_URL` variable ✅
Done 2026-10-26 (recorded 2026-10-28). The repository variable pointed at the
raw `proud-stone-04a76350f.7.azurestaticapps.net` hostname, so links in emails
sent by the workers (scheduled reports, digests, emerging-threat alerts) used
it instead of the canonical `https://www.hebridescyber.co.uk`. It now holds the
`www` address (`gh variable list`, updated 2026-10-26T08:18Z).
