# Hebrides Cyber — Product Guide

What this product does, who it's for, how the pieces fit together end to
end, and the workflows and user stories that drove each feature. Written
for anyone who needs the product picture without reading source code —
teammates, stakeholders, or a new contributor before they dive into
`CLAUDE.md`'s technical reference.

For "how do I run this locally / deploy it," see this same folder's
`README.md` (not the git root — see `docs/README.md` for the full doc map
and why this repo has two roots). For API details, see `docs/API.md`. For
the technical architecture and security model, see `docs/architecture.md`
and `docs/security.md`. For exactly what's gated by plan and how, see
`docs/FUNCTIONALITY-MATRIX.md` — this guide describes intended behaviour;
that file describes what the code actually enforces, and the two don't
always agree yet (flagged inline below where they don't).

---

## 1. What it is

Hebrides Cyber is an automated website security scanning platform: point it
at a domain you own, and it runs dozens of real, evidence-based checks —
TLS configuration, security headers, DNS email authentication, exposed
files, cloud storage misconfiguration, outdated software, CMS-specific
vulnerabilities, and more — then turns the results into a scored report
with specific, copy-pasteable fixes for each issue. Scans repeat on a
schedule so a customer sees their security posture trend over time, not
just a one-off snapshot.

It is built for the gap between "too small to afford a real penetration
test" and "too exposed to ignore security entirely" — small businesses,
SaaS teams, and agencies managing multiple client sites.

## 2. Who it's for (personas)

- **The free evaluator** — a small business owner who found the site via
  search or referral, wants to know "is my website actually secure"
  without committing to anything, and gets one free scan to find out.
- **The paying SMB customer** — runs a small SaaS or business site,
  subscribes to Basic or Pro for recurring scans and alerting, doesn't
  have (and doesn't want) an in-house security person.
- **The agency** — manages security posture across several client sites,
  needs white-labelled reports to hand to clients, and wants alerts routed
  into whatever tool their team already lives in (Slack, Teams, Jira,
  Linear).
- **The developer** — wants security checks wired into CI so a pull
  request fails on a newly introduced high-severity issue, not a manual
  dashboard visit.
- **The admin/operator** — runs the platform itself, not a scan target.
  Needs cross-customer visibility (who's on what plan, which scans are
  stuck, what's in the queue), the ability to intervene on a specific
  customer's behalf (retry/cancel a scan), and an audit trail of every
  privileged action taken, their own or another admin's.

## 3. Feature overview

### 3.1 Scanning

**Base passive suite** — runs on every scan, regardless of plan: TLS/
certificate grading, OWASP security headers + CSP grading, DNS email
authentication (SPF/DKIM/DMARC/MTA-STS/TLS-RPT) + CAA + DNSSEC, sensitive
file exposure (`.env`, `.git`, config backups, debug endpoints), directory
listing detection, cloud storage misconfiguration (S3/Azure Blob/GCS),
technology fingerprinting, open port exposure (via Shodan InternetDB),
headless-browser page health (mixed content, console errors), Certificate
Transparency subdomain discovery, WordPress/Joomla/Drupal deep scans once
that CMS is fingerprinted, vulnerable JS library detection (live CVE
lookup), Subresource Integrity checks, Google Safe Browsing malware/
phishing flags, Wayback Machine historical-URL discovery, and HaveIBeenPwned
domain breach exposure.

**WordPress plugin CVE matching** — plugin versions detected on the target
are checked against the real WPScan Vulnerability Database, not just
reported as "detected" with no risk signal.

**Extended active-tool suite** — runs only on the scheduled monitoring path
(nightly, via GitHub Actions, where real binaries can run): nmap, nuclei
(template set scoped to the target's actual detected technologies, not the
entire default template library), sqlmap, XSSer (dedicated cross-site
scripting confirmation), commix (dedicated OS command injection
confirmation), Subfinder subdomain takeover detection, testssl.sh deep TLS
analysis. A connected GitHub repository
additionally unlocks Gitleaks secret scanning, real dependency-manifest
vulnerability scanning (npm/pip/Composer, checked against OSV.dev), and
Dockerfile base-image freshness checks.

**Authenticated scanning** (Agency plan) — connect a session cookie or
Basic Auth credential for a monitored site, and the header/cookie/CSP/CORS
checks re-run against the logged-in page. The one thing this catches that
nothing else can: a real session cookie with insecure flags, invisible
until you're actually authenticated. Not a full crawl behind login, not
access-control (IDOR) testing.

### 3.2 Compliance mapping

Every finding that genuinely maps to one is tagged against Cyber Essentials
(the UK NCSC scheme), OWASP Top 10:2021, and/or CIS Controls v8 — plus a
Cyber Essentials-specific 5-control breakdown on the scan report,
explicitly labelled an automated indicator, never a certification claim. A
finding with no framework tag means "doesn't genuinely apply to any of the
three," never a forced mapping.

### 3.3 Reporting and output

- **Scored report** (0–100, weighted by finding severity) with a plain-
  English executive summary (AI-generated if Azure OpenAI is configured,
  otherwise a solid deterministic summary).
- **New/Fixed/Unchanged** — every finding carries a stable identity, so a
  re-scan shows exactly what changed since last time.
- **Score trend chart** across every past scan of the same target.
- **PDF export** and **CSV/JSON export** (the latter for spreadsheets or
  a customer's own reporting pipeline).
- **Shareable, read-only report links** and a **score badge** for embedding.
- **White-label branding** (Agency) — a customer's own logo/name on PDF
  reports.

### 3.4 Remediation — four distinct, complementary paths

1. **Static remediation text** on every finding — specific, copy-pasteable
   fix instructions (config snippets for nginx/Apache/Next.js/Azure, not
   generic advice).
2. **AI-tailored fix** (on demand, per finding) — sends the finding plus
   the target's detected tech stack to Azure OpenAI for a stack-specific
   version of the fix.
3. **Automated remediation pull request** — opens a real GitHub PR with a
   `SECURITY-FIXES.md` summary; for dependency findings, it bumps the
   actual `package.json` version when OSV.dev names a safe, same-major-
   version fix.
4. **Ticket creation** — turns a finding into a real Jira issue or Linear
   issue, reusing the same remediation text rather than writing new prose.
   Ticketing the same finding twice adds a "re-detected" comment to the
   existing issue instead of opening a duplicate, and if that issue was
   deleted in your tracker a fresh one is opened rather than silently
   nothing. Optionally (off by default, per integration), a later scan that
   no longer finds the issue moves its ticket to your workflow's done status
   and comments when it was verified — nothing in your tracker moves unless
   you turn that on.

### 3.5 Notifications

Slack and Microsoft Teams webhooks (independent — set either, both, or
neither), critical-finding email alerts (every active plan, including
Basic), outbound webhooks on scan completion (HMAC-signed, for anyone
building their own integration), and the monthly digest email.

### 3.6 Scheduling and the public API

Scans run on-demand (dashboard button or `POST /api/v1/scans`, queued and
usually complete within about a minute) or on a nightly schedule for
monitored targets, cadence tiered by plan (Basic weekly, Pro/Agency daily —
the cadence logic itself has no Agency-only restriction). **Fixed as of
2026-08-28** (`docs/ENHANCEMENTS.md` E-01): the dashboard's "add a target"
UI now renders for any active plan, with server-enforced per-plan caps
(Basic 1 / Pro 3 / Agency 15). `docs/ROADMAP.md` POC-1's own verify step
(a real scheduled-scan run against a staging account) hasn't been re-run
since the fix landed — don't treat this as fully proven until that's done.
The public REST
API (`docs/API.md`) supports listing scans, fetching a full report with
New/Fixed diffing, exporting findings, and reading score trends —
authenticated by session or API key. A packaged GitHub Action wraps the API
for CI, gating a build on newly introduced findings above a configurable
severity.

### 3.7 Billing and plans

Free (one scan, ever), Basic (weekly automated scans), Pro (daily scans,
dependency monitoring, Slack/Teams alerts), Agency (multi-site monitoring,
white-label reports, authenticated scanning, team collaboration). Stripe
Checkout + webhooks keep subscription state in sync.

**What's actually enforced vs. advertised**: server-side plan gating today
covers the free-tier scan cap, scan cadence, Slack/Teams alerts, and
white-label branding — see the previous section's gap on scheduled-scan
access, and `docs/FUNCTIONALITY-MATRIX.md` §5/§6 for the complete picture
of which other tier differences (dependency monitoring, multi-site
monitoring, authenticated scanning, team collaboration) are not currently
server-enforced. This section describes what the product is *designed* and
*sold* to do; the matrix describes what the code actually checks.

### 3.8 Content

An auto-generated daily security blog and a separate weekly newsletter,
both grounded in real, current events (CISA's KEV catalog, recent
high-severity CVEs from NVD, established security-news RSS feeds) — never
fabricated content, and never one replacing the other.

### 3.9 Admin panel

Cross-customer overview, scan/customer management, audit log, blog post
management — gated behind `is_admin`, server-side.

---

## 4. Key workflows

### 4.1 New customer, free scan

1. Visit the homepage, enter a domain, sign up (magic link or Google).
2. Submit a scan → prove domain ownership (DNS TXT record or a file
   upload) — this is required before any scan actually runs, so the
   platform never scans a domain the caller doesn't control.
3. Scan queues, completes in roughly a minute, dashboard shows the scored
   report with every finding's detail + remediation.
4. Free tier is exhausted after that one scan — the dashboard's upsell
   prompts a plan upgrade for recurring scanning.

### 4.2 Paying customer, ongoing monitoring

1. Subscribe (Basic/Pro/Agency) via Stripe Checkout.
2. Add the site under monitored targets. **As currently shipped, this step
   is Agency-only** — see §3.6/§3.7's gap note. A Basic or Pro subscriber
   has no equivalent today; running scans by clicking "Run scan" on-demand
   is the only option, which is manual, not on the plan's advertised
   cadence.
3. For an Agency-monitored target: scheduled scans run automatically; a change since the last scan
   triggers a critical-alert email and, if configured, a Slack/Teams post.
4. Re-scan after fixing something → the report shows it under "Fixed,"
   not just a fresh, unrelated finding list.

### 4.3 Developer, connect a repo for dependency scanning

1. Install the Hebrides Cyber GitHub App on the repo (or add the bot as a
   collaborator, on deployments still using the PAT fallback).
2. Connect the repo in Account settings — access is verified against the
   real GitHub API before the connection is saved.
3. Scheduled scans now also run Gitleaks, dependency-manifest scanning
   (npm, pip, Composer, Go, Maven), and Dockerfile base-image checks against
   that repo.
4. From a finding, request an automated remediation PR — for a safe
   dependency bump, it lands as a real PR with the version already changed.

### 4.4 Agency, managing multiple clients

1. Add each client site as a monitored target.
2. Optionally connect an authenticated-scan credential per site for the
   deeper header/cookie recheck.
3. Configure Slack and/or Teams webhooks so the team sees alerts where
   they already work; connect Jira or Linear so a finding becomes a
   trackable ticket with one click.
4. Generate a white-labelled PDF report to hand to the client, with the
   agency's own logo instead of Hebrides Cyber's.

### 4.5 Developer, CI integration

1. Create an API key in Account settings.
2. Add the packaged GitHub Action to a workflow, pointing at a staging or
   production URL, with a `fail-on` severity threshold.
3. Every PR runs a scan; the Action fails the build only on **newly
   introduced** findings at or above that threshold — not the whole
   existing backlog, which would red-line the first run and get the check
   disabled the same day.

### 4.6 Finding → fix, one specific issue

1. Open a scan report, find an issue (say, a missing CSP header).
2. Read the static remediation — concrete nginx/Next.js/Azure snippets.
3. Optionally: click "Get an AI-tailored fix" for stack-specific guidance,
   "Create ticket" to open a Jira/Linear issue, or request a remediation
   PR if it's dependency-related.
4. Re-scan to confirm the finding clears.

### 4.7 Unhappy paths

What actually happens when something doesn't go to plan — per the
docs-describe-reality rule this guide follows throughout, including where
"nothing happens yet" is the honest answer.

- **A scan fails.** `scans.status` moves to `'failed'`; the dashboard shows
  it as a failed row with no further detail — there's no error-message
  column on the scan itself, and (per `docs/architecture.md`'s
  Observability section) no error tracking exists yet to look one up after
  the fact. The customer's only recourse today is deleting the failed scan
  (`ScanList`'s delete button — fixed this session, see migration `015`;
  previously the delete button silently did nothing due to a missing RLS
  policy) and trying again.
- **Domain verification never completes.** No timeout, no reminder email,
  no expiry — the `verifications` row just sits with `verified_at` null
  indefinitely. DNS propagation can genuinely take minutes to hours;
  `src/lib/ownership.ts`'s own comment already flags that the dashboard
  should say so explicitly and let the customer retry, which it doesn't
  clearly do today.
- **A subscription lapses or is cancelled.** Stripe's
  `customer.subscription.deleted` webhook flips `subscriptions.status` to
  `'cancelled'`. From that point, `enqueue-scheduled-scans.ts` simply stops
  including that account's targets in future scheduled runs — no explicit
  notification, no grace-period messaging, and any Agency-only monitored
  targets stay in the database (just never scanned again) rather than
  being archived or flagged.
- **A customer asks to delete their data.** `/privacy` §7 commits to
  responding within 30 days, which is a real, legally sufficient process
  today — email the address in `/privacy`. There is **no self-service or
  automated path**: no dashboard "delete my account" action, no admin
  one-click deletion, no scheduled retention cleanup at all. See
  `docs/security.md`'s Data Retention section and `docs/ENHANCEMENTS.md`
  E-10 for the full gap.

---

## 5. User stories

Grouped by persona, in "as a ... I want ... so that ..." form — these are
the concrete needs each feature area above exists to satisfy.

**Free evaluator**
- As a small business owner, I want a free security scan of my website so
  that I can find out if I'm exposed before paying for anything.
- As a first-time visitor, I want the report to explain findings in plain
  English so that I don't need a security background to understand my
  own risk.

**Paying SMB customer**
- As a subscriber, I want scans to repeat automatically so that I find out
  about a new issue without remembering to check manually.
- As a non-technical site owner, I want specific fix instructions, not
  just "you have a problem," so that I (or my developer) can actually
  close the gap.
- As a customer who just fixed something, I want the next scan to
  confirm it's resolved, not just show a fresh list, so that I can trust
  the tool's signal.
- As a Basic-tier customer, I want critical-finding email alerts even
  without Slack configured, so that I hear about serious issues
  regardless of what tools I use.

**Agency**
- As an agency, I want to monitor several client sites from one account
  so that I don't need a separate login per client.
- As an agency, I want white-labelled reports so that I can hand a
  polished document to a client without my own tooling showing through.
- As an agency, I want alerts in Slack or Teams — whichever my team
  actually uses — so that a new finding doesn't get missed in an inbox.
- As an agency managing a client's logged-in admin area, I want an
  authenticated recheck of session-cookie security so that I'm not blind
  to the one thing that matters most once someone's actually signed in.
- As an agency team, I want findings to become real Jira/Linear tickets
  so that remediation work fits into how we already track work, instead
  of living only in a scan report no one revisits.

**Developer**
- As a developer, I want dependency vulnerabilities checked against the
  real manifest, not just detected client-side libraries, so that I catch
  issues in packages that never render to a browser.
- As a developer, I want a safe dependency fix to arrive as an actual pull
  request, not just a recommendation, so that fixing it is a review-and-
  merge instead of a manual chase.
- As a developer, I want CI to fail only on genuinely new issues, so that
  the check stays meaningful instead of getting disabled on day one.
- As a developer integrating via API, I want to export findings as CSV/
  JSON so that I can pipe results into my own reporting or ticketing
  system without scraping a UI.

**Admin/operator**
- As an operator, I want a cross-customer overview (plan mix, scan volume,
  MRR) so that I can see the business's health without querying the
  database directly.
- As an operator, I want to retry or cancel a specific customer's stuck
  scan so that I can resolve a support request without a database console.
- As an operator, I want every privileged action — mine or another admin's —
  recorded in an audit log so that "who changed this and when" is always
  answerable.
- As an operator, I want the admin check itself to be a single, consistently
  used piece of code rather than reimplemented per route, so that a future
  security fix to it can't silently miss a route that rolled its own check
  (see `docs/ENHANCEMENTS.md` E-08 — this was a real gap, not hypothetical).

**Everyone**
- As any customer, I want to know which of my findings actually matter
  for a real compliance framework (Cyber Essentials, OWASP, CIS), so that
  I can prioritise beyond "the tool said high severity."
- As any customer, I want a clear, honest answer about what this scanner
  *can't* detect (business logic flaws, full auth-flow testing, zero-days)
  so that I don't mistake a clean scan for a clean bill of health — see
  `/what-we-check` for the specific list.

---

## 6. What this product deliberately does not do

Worth stating plainly, since it shapes several design decisions above:

- **No brute-forcing, no destructive payloads.** Every passive check is
  read-only; the active-tool suite (nuclei/sqlmap/xsser/commix/nmap/ZAP)
  only runs against domains that have already passed real ownership
  verification.
- **No fabricated findings.** A check that can't evidence something
  reports nothing, rather than guessing — see `/what-we-check`'s
  "How we avoid false positives" section for the concrete mechanisms
  behind that rule.
- **No full crawl-behind-login, no IDOR testing, no multi-step auth
  (OAuth/MFA) handling** — authenticated scanning is a narrow header/
  cookie recheck, not a penetration test.
- **No cloud account-level IAM auditing yet** (ScoutSuite/Prowler-style) —
  a real, acknowledged gap, out of scope until a credential-onboarding
  flow with real customer consent is built for it specifically.
