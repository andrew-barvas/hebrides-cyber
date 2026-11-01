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
| OT-42 | Lookout: approve tier limits (analyst hours, assets, onboarding cap, dashboard access) | 🟡 Medium | Decision | 2026-10-31 | |
| OT-43 | Lookout: approve the traffic disclosure; keep or drop the login rate-limit check; PI cover | 🟡 Medium | Decision | 2026-10-31 | |
| OT-44 | Lookout: review the restricted nuclei tag lists in PR #144 | 🟡 Medium | Open | 2026-10-31 | |
| OT-45 | Lookout: decide pilot-first launch (Q5) and line up five pilot prospects | 🟢 Strategic | Decision | 2026-10-31 | |

## Common steps

Several items below refer to these two procedures.

**GitHub secret.** From `hebridescyber-app/`, run `gh auth login` once, then
`gh secret set NAME`. It prompts for the value, so the secret stays out of
shell history. Or use GitHub → repo → Settings → Secrets and variables →
Actions → New repository secret. `gh secret list` shows names and dates only,
which is how a session can confirm a secret exists without seeing it. A change
to a secret that is baked into the site (names starting `NEXT_PUBLIC_`) needs
a push to `master` or Actions → Deploy → Run workflow before it shows.

**Azure app setting.** Azure portal → your Static Web App → Settings →
Environment variables (older portals call it Configuration) → Add → name and
value → Save. From the CLI: `az staticwebapp list -o table` finds the app
name, then `az staticwebapp appsettings set --name <app> --setting-names NAME=value`.
Sessions can't read these, so an item that depends on one stays "Check" until
you confirm.

## Items

### OT-01: Rotate the Supabase database password 🔴
- **What and why:** the password inside `DATABASE_URL` was pasted into a chat
  during setup on 2026-10-14, so treat it as exposed. That URL gives full
  database access.
- **How:** work through `OWNER-SETUP.md` §1 in this order:
  1. Supabase dashboard → your project → Settings → Database → Database
     password → Reset database password. Copy the new password straight away.
  2. Same page → Connection string → URI. Replace `[YOUR-PASSWORD]` with the new
     password (URL-encode any `@`, `:` or `/` in it).
  3. Update the `DATABASE_URL` GitHub secret: `gh secret set DATABASE_URL` and
     paste the whole string.
  4. Update `DATABASE_URL` anywhere else it lives: your local `.env.local`, and
     any Azure setting that holds it (see "Common steps").
  5. While you're there, rotate anything else ever pasted into a chat: the
     Supabase service-role key (Settings → API → regenerate, then update
     `SUPABASE_SERVICE_ROLE_KEY` in GitHub and Azure) and any Stripe keys.
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
- **How:** decide, then act:
  1. Open https://github.com/andrew-barvas/hebrides-cyber/pull/110 and read the
     description and the file list.
  2. If you want it: click Reopen pull request, check CI is green, then Squash
     and merge. Then ask a session for the follow-up PR covering the server-side
     jobs listed above.
  3. If you don't: write one line on the PR (or here) saying why, so the next
     session doesn't redo it. Tier A users then keep seeing the locked features
     and the Overview error until another fix lands.
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
- **How:**
  1. Sign up at https://console.upstash.com (free tier).
  2. Create database → Redis, pick the region closest to your Azure Static Web
     App, leave TLS on, create.
  3. On the database page open the REST API section and copy
     `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
  4. Add both as Azure Static Web App settings (see "Common steps", Azure app setting).
  5. Redeploy or restart is not needed for API routes, but a push to `master`
     (or Actions → Deploy → Run workflow) makes sure the new settings are live.
- **Verify:** repeated `POST` requests to `/api/run-scan` from one machine eventually return 429 (the limit is in `src/pages/api/run-scan.ts`).
- **Raised:** 2026-08-17.

### OT-07: Branch protection on `master` 🟠
- **What and why:** `master` has no protection rule (the GitHub API returned
  "Branch not protected" on 2026-10-27). A PR with failing tests can be
  merged, and every merge deploys to production.
- **How:**
  1. GitHub → repo → Settings → Branches (or Rules → Rulesets) → Add rule /
     New branch ruleset for `master`. A private repo needs GitHub Pro or Team
     for this.
  2. Tick Require a pull request before merging.
  3. Tick Require status checks to pass, search for and add
     `Lint, typecheck, test`.
  4. Optional: Require branches to be up to date, Require linear history.
  5. Decide whether admins are exempt. If they are, you can still merge past a
     red check, so leave "Do not allow bypassing" ticked if you want it strict.
  6. Save. Note that sessions that squash-merge will now be blocked until CI is
     green, which is the point.
- **Verify:** on a deliberately failing PR, the merge button is blocked.
- **Raised:** 2026-08-26 (BETA-5).

### OT-08: Browser and app-side Sentry 🟡
- **What and why:** `SENTRY_DSN` is a GitHub secret (scan workers, done in
  OT-26). `NEXT_PUBLIC_SENTRY_DSN`, which `deploy.yml` reads for browser
  errors, isn't set. The Azure app setting `SENTRY_DSN`, for API routes, can't
  be seen from here.
- **How:**
  1. Sentry → create a project, platform Next.js (or reuse the one from
     OT-26) → copy its DSN.
  2. Add the GitHub secret `NEXT_PUBLIC_SENTRY_DSN` (see "Common steps", GitHub secret). This
     must be a GitHub secret, not only an Azure setting: `deploy.yml` bakes it
     into the browser bundle at build time.
  3. Add the Azure setting `SENTRY_DSN` with the same DSN for API routes
     (see "Common steps", Azure app setting).
  4. Push to `master` or re-run Deploy so the browser bundle is rebuilt.
- **Verify:** throw a test error from the site and see it in Sentry.
- **Raised:** 2026-09-04 (E-03 / BETA-1).

### OT-09: Verify uptime monitoring with a real UptimeRobot key 🟡
- **What and why:** the UptimeRobot v3 client was built from documentation
  and recorded shapes, not a live account. That a dashboard API key works as
  the v3 bearer token, and that status strings map as expected, is
  unverified until someone tries it.
- **How:**
  1. Sign up at uptimerobot.com (free). In it open Integrations → API and
     create an API key.
  2. Sign in to the dashboard as a Pro or Agency user → Integrations → Uptime
     monitoring → paste the key → Connect. If it says the key was rejected,
     copy the exact message and give it to a session (the v3 token type may
     differ; the fix is in `uptimeRobot.ts`).
  3. Click Create monitors for a verified site; confirm a monitor appears in
     UptimeRobot.
  4. In UptimeRobot pause that monitor. Wait for the next sync (up to 15
     minutes) or reload the card after 5, and confirm the dashboard shows
     Paused.
  5. Resume it, then (needs OT-02 for email) take a test target down briefly
     and confirm one down message and one up message arrive.
  6. Never paste the key anywhere except the dashboard field.
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
- **How:**
  1. Read the recommendation above and the five routes named.
  2. Reply with one line per route: gate to Pro, gate to Agency, or leave open.
  3. A session then adds `planGate` to the chosen routes
     (`src/lib/planAccess.ts`) and pins the decision in tests (`SPRINT-PLAN.md`
     H5-1). Update the pricing page copy if a route newly requires a plan.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md`, "Owner decisions needed").

### OT-11: Provision a deliberately vulnerable staging target (H3) 🟡
- **What and why:** proving the extended tools find real issues in
  production (H3, POC-1, POC-5) needs a target we own and are allowed to
  attack.
- **How:**
  1. Pick a free host (Azure Container Apps free grant, Fly.io, or a small VM)
     and run OWASP Juice Shop: `docker run -d -p 3000:3000 bkimminich/juice-shop`
     behind HTTPS.
  2. Add a DNS record at GoDaddy for `lab.hebridescyber.co.uk` pointing at it.
  3. In the dashboard sign in as an internal account, Assets → add the domain
     and complete ownership verification (the TXT record or file it shows).
  4. Add it as a monitored site and set its scan profile to `full`.
  5. Run the scheduled-scan workflow (or wait for the cron), then open the
     scan and check extended tools show `completed`.
  6. Make sure it is never linked from public pages and that nothing sensitive
     is hosted on it: it is deliberately vulnerable.
- **Verify:** a scheduled scan of it has extended tools reporting
  `completed`, with findings. The H3 `verify` job in `scheduled-scans.yml`
  checks this.
- **Raised:** 2026-08-26 (staging target); 2026-10-22 (`SPRINT-PLAN.md` H3).

### OT-12: Restore drill 🟡
- **What and why:** backups are untested until one has been restored.
- **How:** follow `BACKUP-RESTORE.md`:
  1. Supabase → create a new scratch project (free tier is fine).
  2. Follow the "Restore from a daily backup" section of that guide to restore
     the latest backup into it.
  3. Check row counts of `profiles`, `scans` and `subscriptions` against
     production, and that a sample row reads correctly.
  4. Record the date, how long it took and any problems in `BACKUP-RESTORE.md`.
  5. Delete the scratch project. Consider Supabase Pro for point-in-time
     recovery.
- **Raised:** 2026-10-06 (E-13 / LIVE-4).

### OT-13: ToS solicitor review; PI insurance before offensive traffic 🟡
- **What and why:** the terms (`docs/legal/terms-of-service-draft.md`) haven't
  been reviewed by a solicitor (BETA-B1). Tier A's offensive tools must not
  send real attack traffic until the customer contract authorises it and PI
  insurance covers it. Your 2026-10-23 decision stands: leave them
  `not_configured` and don't market them.
- **How:**
  1. Choose a UK solicitor who handles SaaS or technology terms; ask for a fixed
     quote.
  2. Send them `docs/legal/terms-of-service-draft.md`, the privacy policy page,
     and (for OT-35 and OT-43) the Lookout copy
     `marketing/17-lookout-managed-exposure-review.md`.
  3. Ask specifically about: authorisation to scan third-party-owned
     assets, limitation of liability, the offensive-scan authorisation wording
     for Tier A, and the Lookout service description.
  4. Ask your insurer for professional indemnity cover that names security
     testing, and get it in writing before any offensive traffic is sent.
  5. Merge the approved wording into `src/app/terms/page.tsx`.
- **Raised:** 2026-08-26 (BETA-B1); 2026-10-12 (Tier A, `NEXT-STEPS.md` item
  11).

### OT-14: Marketing and grant copy integrity pass 🟡
- **What and why:** some marketing and grant copy claims things the product
  doesn't do: SSO/SAML, RBAC, SCIM, an MSP portal, "autonomous AI pen-test",
  and unsourced statistics such as the "43%" figure in
  `marketing/11-social-media-and-local-press-playbook.md`. The site's own
  Tier A pricing card is fixed in code separately.
- **How:**
  1. Open `docs/FUNCTIONALITY-MATRIX.md` (what the product really does) beside
     each file in `marketing/` and `marketing/12-hie-grant-application.md`.
  2. For each claim you can't match to a row there (SSO/SAML, RBAC, SCIM, MSP
     portal, "autonomous AI pen-test", the "43%" statistic), either delete it,
     reword it to what exists, or add a named source.
  3. Tell a session which files you approved, or ask it to make the edits.
- **Raised:** 2026-10-22 (`SPRINT-PLAN.md` H5, `PRODUCT-REVIEW-2026-10.md`
  P0-2).

### OT-15: Approve pruning stale merged remote branches 🟢
- **What and why:** about 20 merged branches are still on GitHub (H5). It's
  harmless but noisy. Deleting them is reversible: each merged PR keeps a
  "Restore branch" button.
- **Your call:** say "prune merged branches" and a session will delete only
  those whose PR is merged.
- **How:**
  1. Reply "prune merged branches". A session lists branches whose PR is merged
     (`gh pr list --state merged`) and shows you the list.
  2. After you approve the list it deletes only those with
     `git push origin --delete <branch>`. Each merged PR keeps a Restore branch
     button if you need one back.
- **Raised:** 2026-10-22.

### OT-16: Run the Container Apps deploy once 🟢
- **What and why:** #51, #52 and #53 moved `deploy-containerapp.yml` to the
  Node 24 majors of its actions. It's only run by hand, so they're
  unverified. This only matters if you use the Container Apps path.
- **How:**
  1. Actions → Deploy to Azure Container Apps → Run workflow (or use the
     `deploy-containerapp` skill). This needs the Azure credentials it
     documents.
  2. Watch the run; each action's Node 24 major should load without warnings.
  3. If it fails, copy the failing step's log into a session.
- **Raised:** 2026-10-26.

### OT-17: Optional scanner secrets 🟢
- **What and why:**
  - `HIBP_API_KEY` enables breach checks (paid, and needs HIBP domain
    verification).
  - `NVD_API_KEY` raises NVD rate limits for CVE lookups.
  - `INTERACTSH_TOKEN` gives a private out-of-band server for nuclei's
    SSRF/OAST templates. Without it they use the public pool.
  - Each check reports `not_configured` without its key. Nothing fails.
- **How:**
  1. `HIBP_API_KEY`: buy a key at haveibeenpwned.com/API/Key and verify the
     domain(s) you'll search; then add it as a GitHub secret (see "Common steps").
  2. `NVD_API_KEY`: request one at nvd.nist.gov/developers/request-an-api-key
     (free, arrives by email); add it as a GitHub secret.
  3. `INTERACTSH_TOKEN`: only if you run your own interactsh server; also set
     the `INTERACTSH_SERVER` repository variable (Settings → Secrets and
     variables → Actions → Variables).
  4. Each is picked up at the next scheduled scan run.
- **Raised:** 2026-10-27 (secrets audit).

### OT-18: Optional AI secrets 🟢
- **What and why:** `AZURE_OPENAI_ENDPOINT`, `_KEY` and `_DEPLOYMENT` enable
  AI triage (off by default; `AI_TRIAGE=1`) and the AI write-ups in
  `daily-blog.yml` and `weekly-newsletter.yml`. Without them those parts are
  skipped.
- **How:**
  1. Azure portal → create an Azure OpenAI resource and a model deployment.
  2. Copy the endpoint, a key, and the deployment name.
  3. Add GitHub secrets `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_KEY`,
     `AZURE_OPENAI_DEPLOYMENT` (see "Common steps", GitHub secret).
  4. To enable AI triage also set the repository variable `AI_TRIAGE` = `1`
     (Settings → Secrets and variables → Actions → Variables). Read
     `AI-TRIAGE-DESIGN.md` first and check the output by hand on a few of your
     own sites.
- **Raised:** 2026-10-27 (secrets audit).

### OT-19: DNS housekeeping 🟢
- **How:**
  1. **CAA record.** Open the live certificate in a browser (padlock →
     Certificate) and note the issuer. At GoDaddy → DNS → Add record → type
     CAA, name `@`, flags 0, tag `issue`, value the issuer's CAA domain (for
     DigiCert `digicert.com`). Re-run the own-site scan afterwards.
  2. **`hebridescyber.com`.** Register it at GoDaddy and point it to redirect
     to `https://www.hebridescyber.co.uk`.
  3. **security@ alias.** In your email host create `security@hebridescyber.co.uk`
     forwarding to you, then confirm `public/.well-known/security.txt` lists it.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 6 and 9).

### OT-20: Publish the GitHub Action publicly 🟢
- **What and why:** this repo is private, so customers can't `uses:` the
  action. Publish it from a small public repository.
- **How:**
  1. Create a new public GitHub repository (for example `hebrides-cyber-action`).
  2. Copy the contents of the repo-root `action/` folder (its `action.yml` and
     README) into it, and add a README `uses:` example.
  3. Tag a release (`v1`) so customers can pin it.
  4. Update the `/docs/ci` templates to reference the new repo.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 5).

### OT-21: NCSC replacement campaign 🟢
- **How:**
  1. Supabase dashboard → SQL editor → paste and run
     `sql/seed/002_ncsc_web_check_retirement_post.sql`.
  2. Open the blog on the live site to confirm the post is published.
  3. Send or post the drafts in `marketing/16-ncsc-replacement-campaign.md`.
- **Raised:** 2026-10-06 (`NEXT-STEPS.md` Owner actions 8).

### OT-22: Review the login-recording consent copy 🟢
- **What and why:** "login recording" is the authenticated-scan feature. It
  drives a customer's own login form once to capture a session for the
  signed-in crawl. Before it's promoted beyond the dashboard form, its
  checkbox and any marketing copy need a wording review. The copy must say to
  use a dedicated test account, never a personal or admin login
  (`AUTHENTICATED-CRAWL.md`, "Still open").
- **How:**
  1. Dashboard → Assets → the authenticated-scan form: read the consent
     checkbox text.
  2. Read the "Still open" section of `AUTHENTICATED-CRAWL.md`.
  3. Check the text tells users to use a dedicated test account, never a
     personal or admin login, and that it says what is recorded.
  4. Approve it or send the rewording to a session.
- **Raised:** 2026-10-05.

### OT-23: Decide whether to build the supplier security rating 🟢
- **What and why:** the 2026-10-27 competitor analysis ranked an A–F rating
  for any domain the top new product line. The comparison is UpGuard Vendor
  Risk at $1,750/month for 50 vendors. About 80% of the checks already exist.
  It needs a ToS and policy change, because results currently require domain
  verification, so it depends on OT-13.
- **Your call:** go or no-go. On go, a session writes the design.
- **How:**
  1. Read the competitor analysis (2026-10-27) and `PRODUCT-IDEAS.md`.
  2. Decide go or no-go. It depends on OT-13: the terms currently require
     domain verification before results are shown.
  3. On go, ask a session to write the design.
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
- **How:**
  1. Create a free public status page. UptimeRobot: Status pages → Create
     status page, add the monitors from OT-09, publish, note the https URL.
  2. Add the GitHub secret `NEXT_PUBLIC_STATUS_PAGE_URL` (see "Common steps", GitHub secret).
  3. Push to `master` or re-run Deploy, because it is inlined at build time.
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
- **How:**
  1. `gh secret list` and confirm `DIGEST_SERVICE_TOKEN`,
     `NEWSLETTER_SERVICE_TOKEN` and `NEXT_PUBLIC_AZURE_FUNCTIONS_URL` appear.
  2. `gh secret delete DIGEST_SERVICE_TOKEN`, then the other two (add
     `--repo andrew-barvas/hebrides-cyber` if you're outside the checkout).
  3. Remove the same names from Azure settings if present.
  4. Push or re-run Deploy to confirm nothing depended on them.
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
- **How:**
  1. `CONTACT_EMAIL`: only if `hello@hebridescyber.co.uk` isn't the mailbox you
     read; add as a GitHub secret.
  2. GitHub App: Settings → Developer settings → GitHub Apps → New. Give it
     Repository permissions Contents: read and Pull requests: write, no
     webhook needed. Create it and note the App ID.
  3. Generate a private key (downloads a `.pem`). Add GitHub secrets
     `GH_APP_ID` and `GH_APP_PRIVATE_KEY` (the whole PEM including the BEGIN
     and END lines).
  4. Install the App (Install App tab) on only the repos it should reach.
  5. Delete the downloaded `.pem` from your machine.
- **Verify:** `gh secret list` shows the names. For the App, a fix pull request
  on an installed repo opens without using `GH_PAT`.
- **Raised:** 2026-10-28 (secrets audit).

### OT-33: Lookout name and prices 🟡
- **What and why:** the plan (`DEFENSIVE-ASSESSMENT-PLAN.md`) uses the working
  name "Lookout" and proposes Essentials £149/mo and Assured £299/mo. You chose
  these on 2026-10-30, but the name has not been checked.
- **How:**
  1. Search the UK IPO trade-mark register (search-trademark.service.gov.uk)
     for "Lookout" in classes 42 and 9; note any live marks.
  2. Search Companies House for company names containing "Lookout" in
     software or security.
  3. Check a domain or subdomain you'd use is free.
  4. Confirm with your accountant whether £149 and £299 are the VAT-inclusive
     or exclusive prices.
  5. Record the result here, or pick Beacon / Harbour Watch and repeat.
- **Verify:** a short written result (clear, or pick Beacon / Harbour Watch).
- **Raised:** 2026-10-30.

### OT-34: Lookout Stripe prices 🟡
- **What and why:** you chose Stripe checkout from day one. Billing is
  monthly-only today, so this needs six new prices: Essentials and Assured, each
  monthly, quarterly and annual.
- **How:**
  1. Stripe dashboard → Product catalogue → add the Lookout Essentials and
     Assured products if not yet present.
  2. For each, create three recurring prices (monthly, every 3 months, yearly)
     in GBP. Do this in test mode first, then live.
  3. Copy the six price IDs (`price_…`).
  4. Give them to a session to add as env vars and to `PRICE_IDS` in
     `create-checkout-session.ts`; then set each in the place the session names (GitHub secret or Azure app setting; see "Common steps").
  5. Don't publish checkout before the plan's pilot criteria are met.
- **Verify:** a test-mode checkout completes for each price.
- **Raised:** 2026-10-30.

### OT-35: ToS wording for the managed exposure review 🟡
- **What and why:** `src/app/terms/page.tsx` §2 lists the services. Lookout is a
  recurring, analyst-written service with scan windows and fair-use hours, and
  it uses active (non-injecting) scanning on verified domains. Wording needs a
  solicitor, together with OT-13.
- **How:**
  1. Send your solicitor `marketing/17-lookout-managed-exposure-review.md`, the
     plan's service description and `src/app/terms/page.tsx` §2 (same brief as
     OT-13).
  2. Ask them to review the recurring-service, fair-use-hours and
     active-scanning wording.
  3. Give the approved text to a session to merge into the terms.
- **Verify:** approved wording merged into the terms.
- **Raised:** 2026-10-30.

### OT-36: Where OpenVAS runs 🟢
- **What and why:** you chose to add OpenVAS and Nikto. OpenVAS needs a large
  feed sync and several services, which may not fit the ephemeral Actions
  runners. Decide after the prototype in the plan.
- **How:**
  1. Wait for the OpenVAS prototype result (feed size, time to first scan).
  2. If the feed sync plus scan fits well inside a GitHub Actions job limit,
     choose Actions. If not, choose a small VM (cheapest to keep the feed
     warm) or an Azure Container Apps job.
  3. Record the choice here.
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
- **How:**
  1. Decide whether you use the Container Apps path (OT-16). If not, do nothing.
  2. If you do and want the six hardening settings, change the registry SKU to
     Premium in the Azure portal (or `azure/terraform/main.tf`) and ask a
     session to replace the Checkov skips with the real settings.
  3. Image scanning is a separate Defender for Containers plan; enable it under
     Microsoft Defender for Cloud if wanted.
  4. Record the decision here.
- **Verify:** a decision recorded here.
- **Raised:** 2026-10-30.

### OT-38: Choose an auditor and certification scope 🟢
- **What and why:** the repo-side evidence map is `CONTROLS-EVIDENCE.md` and
  the public `/trust` page says we are not certified. Getting attested needs
  an external auditor and a decision on SOC 2 Type I/II versus ISO 27001, and
  on whether it is worth the cost yet.
- **How:**
  1. List 2 or 3 auditors (SOC 2: a CPA firm; ISO 27001: a UKAS-accredited
     certification body).
  2. Send each `docs/CONTROLS-EVIDENCE.md` and ask for a fixed quote and the
     elapsed time for Type I (point in time) and Type II (observation window).
  3. Decide SOC 2 versus ISO 27001, or neither yet, based on what your
     customers ask for.
  4. Record the decision here. `/trust` may not claim certification until a
     report exists.
- **Verify:** a decision recorded here. Only after an auditor's report may
  `/trust` change its certification wording.
- **Raised:** 2026-10-31.

### OT-39: Write the core security policies 🟢
- **What and why:** auditors need written policies (information security,
  access control, incident response, change management, supplier management,
  data classification and retention, ISMS scope and roles). The repo has
  engineering controls but not these documents.
- **How:**
  1. Write one policy per topic: information security, access control, incident
     response, change management, supplier management, data classification and
     retention, ISMS scope and roles. Use your platform's templates (OT-40) or
     a standard template pack.
  2. Give each an owner, a version and an approval date.
  3. Link each from `docs/CONTROLS-EVIDENCE.md` next to the control it
     supports.
- **Verify:** policies exist and are linked from the evidence map.
- **Raised:** 2026-10-31.

### OT-40: Choose a compliance automation platform 🟢
- **What and why:** tools such as Vanta, Drata or Secureframe collect
  evidence continuously and supply policy templates. Optional; an auditor can
  work without one. It costs money each year.
- **How:**
  1. Take demos from two vendors (for example Vanta, Drata, Secureframe) after
     OT-38, and ask whether your chosen auditor works with them.
  2. Compare annual cost against doing evidence collection by hand.
  3. Record the choice, including "none", here.
- **Verify:** a decision recorded here.
- **Raised:** 2026-10-31.

### OT-41: Commission an independent penetration test 🟢
- **What and why:** an external test of the platform itself is expected
  evidence for both standards. Needs a budget and a written scope and
  agreement with the tester.
- **How:**
  1. Pick a CREST-accredited provider; ask for quotes against a written scope
     (the app, API, the scan workers, and Supabase configuration).
  2. Provide a staging copy and test accounts; agree test windows and a
     contact for emergencies.
  3. Sign the rules of engagement, run the test, and keep the report private.
  4. Triage each finding into issues and record the report date here.
- **Verify:** a report received and findings triaged.
- **Raised:** 2026-10-31.

### OT-42: Lookout tier limits 🟡
- **What and why:** checkout makes it easy to sell more analyst time than one
  person has. The plan (`DEFENSIVE-ASSESSMENT-PLAN.md`, "Pricing & Tiers")
  proposes caps that need your sign-off before they go into the copy and terms:
  Essentials 4 analyst hours per quarter, up to 3 domains and 5 IP addresses;
  Assured 9 hours per quarter, up to 10 domains and 16 IP addresses; two new
  Lookout customers a month during the pilot; Essentials gets Pro dashboard
  features and Assured gets Agency ones.
- **How:**
  1. Open `DEFENSIVE-ASSESSMENT-PLAN.md`, "Pricing & Tiers".
  2. For each proposed number (hours, domains, IPs, pilot sign-ups, dashboard
     feature level) write approve or a new value.
  3. Update the table and `marketing/17-lookout-managed-exposure-review.md`,
     removing the [VERIFY] marks (or ask a session to).
- **Verify:** the agreed numbers recorded in the plan and in
  `marketing/17-lookout-managed-exposure-review.md`, with the [VERIFY] marks
  removed.
- **Raised:** 2026-10-31.

### OT-43: Lookout traffic disclosure 🟡
- **What and why:** the copy says Lookout never exploits anything, and it also
  says plainly what the checks send: page and file requests, connections to
  common ports, and five login submissions with made-up details (the base
  suite's rate-limit check). That last check can trip a customer's lockout
  alerts. The disclosure is what keeps "never exploitative" accurate.
- **How:**
  1. Read "What Lookout sends to your systems" in
     `marketing/17-lookout-managed-exposure-review.md`.
  2. Decide whether the five-login-submission rate-limit check stays on for
     Lookout customers (turning it off is a code change a session can make).
  3. Send the section to the solicitor with OT-35.
  4. Ask your insurer for written confirmation that professional indemnity
     covers an advisory review service.
  5. Record the decision and keep the insurer's reply on file.
- **Verify:** approved wording and the login-check decision recorded in the
  plan; insurer's confirmation on file.
- **Raised:** 2026-10-31.

### OT-44: Review the `exposure` profile's nuclei tags 🟡
- **What and why:** draft PR #144 restricts nuclei for Lookout: a smaller
  baseline tag list, every input-injecting category excluded and out-of-band
  interaction off. The PR asks for your check of the tag lists before launch,
  because they decide what traffic Lookout sends.
- **How:**
  1. Open draft PR #144 and find the nuclei section of its description.
  2. Read the baseline tag list and the excluded categories; flag any tag
     that sends input to a target or that you wouldn't want run against a
     customer.
  3. Comment on the PR with approved or the changes you want.
- **Verify:** your approval on PR #144.
- **Raised:** 2026-10-31.

### OT-45: Lookout pilot 🟢
- **What and why:** plan question Q5. Checkout from day one (Q3) removes the
  cheap demand test, so the plan proposes a pilot: three to five customers,
  reports written by hand, analyst hours logged. Stop if fewer than 2 of 5
  prospects would pay £149 a month, or if a quarterly report takes more than
  4 analyst hours.
- **How:**
  1. Decide: pilot first, or open checkout straight away.
  2. If pilot: list five prospects (names, why they fit) and approach them with
     the copy draft.
  3. Track analyst hours per report. Stop if fewer than 2 of 5 would pay £149 a
     month or a quarterly report takes more than 4 hours.
  4. Record the decision and the results in the plan and `PRODUCT-IDEAS.md`
     P-06.
- **Verify:** the decision and the pilot result recorded in the plan and in
  `PRODUCT-IDEAS.md` P-06.
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
