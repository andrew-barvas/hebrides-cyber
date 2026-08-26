# Enhancements backlog

Stable-ID (`E-nn`) list of what could be built and why — **no commitment, no
dates**. `docs/ROADMAP.md` decides what's actually sequenced and when,
referencing these IDs; this file never restates roadmap sequencing. Once an
ID is assigned here it's referenced from other docs by that ID — **never
renumber an existing item**; if one is dropped, mark it `WITHDRAWN` and
leave the number retired rather than reusing it.

**Category** (from `docs/COMPETITIVE-ANALYSIS.md` §6's framing, applied
product-wide, not just to competitive gaps):
- **code** — fixable by a contained code change
- **money/time** — fixable, but needs budget, a third-party service, or
  calendar time (legal review, cert acquisition) rather than just code
- **solo-blocked** — structurally hard for a one-person team; needs
  headcount or a partner, not a sprint

**Source**: `audit` (production-readiness gaps audit), `competitive`
(`docs/COMPETITIVE-ANALYSIS.md` §7), `roadmap` (harvested from
`docs/decisions/ENGINEERING-LOG-2026-08.md`, formerly `PLATFORM-ROADMAP.md`
§1/§10, before that file was archived).

---

## E-01 — Give Basic/Pro subscribers a way to receive the scheduled scans they pay for

**What**: `MonitoredTargets.tsx`, the only UI that lets an account register
a target for scheduled scanning, renders only `{plan === "agency" && ...}`
(`src/app/dashboard/page.tsx:474`). Scan cadence itself
(`scanCadence.ts`/`enqueue-scheduled-scans.ts`) is already plan-aware
(Basic weekly, Pro/Agency daily) and has no Agency-only restriction — the
gap is purely that Basic/Pro accounts have no path to add a target at all.
**Why**: Basic and Pro are sold "weekly/daily automated scans"
(`marketing/03-pricing-page.md`); today, a paying Basic/Pro customer with no
Agency-tier UI access cannot receive a single scheduled scan. This is the
single largest gap between advertised and actual capability in the whole
product — see `docs/FUNCTIONALITY-MATRIX.md` §5.
**Impact/effort**: high impact, low effort — the backend already supports
it; this is a UI-gating change (show the component for any active
subscription, not just Agency) plus deciding the target-count cap per tier.
**Depends on**: a decision on per-tier target-count limits (Agency's
differentiator becomes count/multi-site scale, not raw access).
**Category**: code. **Source**: audit.

## E-02 — Server-side plan enforcement audit (teams, webhooks, keys, shares, AI fix, target-auth)

**What**: per `docs/FUNCTIONALITY-MATRIX.md` §5, 14 dashboard/API
capabilities have **no plan gate at all** — including AI-tailored fix
(pays Azure OpenAI per click, any tier, uncapped), remediation PRs, ticket
integrations, team collaboration, API keys/webhooks/share links, connected-repo
scanning, and authenticated scanning (labelled "Optional (Agency)" on
`/what-we-check` but enforced nowhere).
**Why**: the Basic/Pro/Agency ladder exists in Stripe billing and in
marketing copy; in the product it mostly doesn't exist. Every advertised
tier differentiator beyond white-label branding is currently honour-system.
**Impact/effort**: high impact, medium effort — mechanical per-route
(`branding-logo.ts` is the existing correct pattern to copy), but ~14 routes
plus their RLS policies (`monitored_targets` INSERT has no plan check
either).
**Depends on**: a decision on exactly which capabilities are tier-exclusive
vs. universal (e.g. AI fix could reasonably become Pro+, or stay free with a
per-account cap instead — a product decision, not just an enforcement one).
**Category**: code. **Source**: audit.

## E-03 — Observability: error tracking

**What**: wire Sentry or Application Insights. Today: 80 `console.*` calls
across 26 files is the entire logging strategy; `src/app/error.tsx:14`'s own
comment says "wire to Application Insights / Sentry here later."
**Why**: if a customer's scan fails in production today, there is no way to
find out why after the fact. This is the single biggest operational gap for
Beta-readiness.
**Impact/effort**: high impact, medium effort (SDK integration + deciding
what to redact from a security-scanner's own error payloads, since findings
data can be sensitive).
**Depends on**: none — can start immediately.
**Category**: code (setup) + money/time (paid tier at scale).
**Source**: audit.

## E-04 — Health check endpoint

**What**: `GET /api/health` — Supabase/Stripe/queue-depth sub-checks, 200
when healthy, 503 when degraded. Doesn't exist today.
**Why**: nothing external can currently determine whether the app is up
short of loading a page; blocks any real uptime monitoring.
**Impact/effort**: low effort, unlocks E-03's value (an alert needs
something to alert *from*).
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-05 — Rate limit / abuse-protect the public contact form

**What**: `POST /api/contact` is public, unauthenticated, and has zero rate
limiting, CAPTCHA, or honeypot — the only fully open write path in the app
with no abuse protection.
**Why**: trivially spammable; would burn the Resend free tier (100/day) and
pollute `contact_enquiries` with junk. `checkRateLimit()`
(`src/lib/rateLimit.ts`) already exists and is proven on `run-scan.ts` —
this is applying an existing pattern, not building a new one.
**Impact/effort**: low effort, meaningful risk reduction. A good first
contributor task — see `docs/ONBOARDING.md` §7.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-06 — Runtime schema validation at API boundaries

**What**: adopt a schema library (zod is the natural fit for a TS codebase)
for `req.body`/`req.query` parsing. Today: no zod/yup/joi/ajv anywhere;
validation is 28 instances of `req.body as {...}` (a compile-time cast, not
a runtime check) followed by ad-hoc `if` checks of wildly varying rigour —
`contact.ts` validates well, `admin/contacts.ts`'s `read: boolean` and
`team/members.ts`'s `role?: string` are written straight through with
almost no check.
**Why**: for a security product specifically, shipping without a runtime
validator at the API boundary is a credibility risk as much as a technical
one.
**Impact/effort**: medium effort, ideally incremental (new routes first,
backfill existing ones opportunistically) rather than a big-bang rewrite.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-07 — Configure live Stripe Price IDs

**What**: `STRIPE_PRICE_BASIC`/`PRO`/`AGENCY` are unset in the deployed
environment; `create-checkout-session.ts` 400s/500s until they're real
Stripe Dashboard Price IDs.
**Why**: the entire paid-signup funnel is currently broken end to end.
**Impact/effort**: low effort (a Stripe Dashboard + Azure app-settings
task), highest-priority blocker on the list — nothing else in this backlog
matters commercially while this is unset.
**Depends on**: a completed Stripe product/price setup (may already exist
partially — verify before treating as a from-scratch task).
**Category**: money/time (Stripe account config, not code).
**Source**: audit.

## E-08 — Consolidate admin auth checks onto `requireAdmin()`

**What**: `admin/overview.ts` and `admin/contacts.ts` each hand-roll their
own inline admin check instead of calling the shared
`src/lib/adminAuth.ts`'s `requireAdmin()` — and do it *differently* from
each other (one constructs a fresh anon `createClient`, the other calls
`supabaseAdmin.auth.getUser` directly).
**Why**: two-plus implementations of the same security control is exactly
how one of them drifts out of sync with a future fix to the shared one (as
nearly happened with the `is_admin` RLS gap this session already fixed
separately — see migration `017`).
**Impact/effort**: low effort, mechanical. A good first contributor task —
see `docs/ONBOARDING.md` §7.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-09 — Publish Terms of Service

**What**: no `/terms` route exists anywhere in `src/app/`. The app takes
card payments via Stripe Checkout with no contract, no liability cap, no
acceptable-use policy, on a product that fires real attack payloads
(sqlmap, commix, XSSer, nuclei) at third-party infrastructure.
**Why**: highest-priority *legal* gap identified in the audit — arguably
outranks several code items above in urgency.
**Impact/effort**: needs a solicitor-reviewed draft, not just a page
template — this is why it's money/time, not a code task.
**Depends on**: legal review.
**Category**: money/time. **Source**: audit.

## E-10 — Data retention: implement the cleanup job, and reconcile the two conflicting promises

**What**: `docs/security.md` states 90-day retention; `src/app/privacy/page.tsx`
tells customers 12 months for scan results and 90 days for PDFs
specifically — the two documents currently contradict each other, and
**neither figure is implemented in code** (no cleanup job, no lifecycle
rule on the storage account). There is also no customer-facing
data-deletion path — grep for "delete account"/"erasure" across `src/`
returns zero hits, despite the privacy policy promising a 30-day response.
**Why**: a published retention/deletion promise you don't keep is a worse
legal position than making no promise at all, on a live site already
publishing one.
**Impact/effort**: medium — first a product decision (pick one retention
figure, fix both docs to agree — see `docs/ROADMAP.md` BETA-3's dependency
on this), then a scheduled cleanup job (matching the existing
`daily-blog.yml`/`weekly-newsletter.yml` direct-script pattern rather than
an HTTP route), then a minimal deletion API/admin action.
**Depends on**: the retention-figure decision must happen first.
**Category**: code (job) + money/time (the decision itself may want legal
input given E-09). **Source**: audit.

## E-11 — Fix `send-monthly-digest.ts`'s N+1 query pattern before it times out

**What**: a serial `for` loop over every active subscriber, each iteration
issuing 3+ Supabase queries plus an outbound email, all inside a single
HTTP request on Azure SWA's Free-tier managed Functions.
**Why**: this is the exact execution-ceiling failure mode ("Backend call
failure") already hit and fixed once for `daily-blog.yml` and
`weekly-newsletter.yml`, both resolved by converting to a directly-run
script with no HTTP hop. `send-monthly-digest.ts` still goes through the
API route and will time out once subscriber count grows past a few dozen.
**Impact/effort**: low-medium effort — the fix pattern is proven and
already used twice elsewhere in this codebase; this is applying it a third
time.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-12 — Rate-limit the expensive per-click routes

**What**: `checkRateLimit()` is called from exactly 2 of ~30 routes
(`run-scan.ts`, `v1/scans.ts`). Not covered, and each expensive per-call:
`scans/[id]/ai-fix.ts` (Azure OpenAI tokens, uncapped), `generate-report.ts`
(launches headless Chromium per call), `generate-fix-pr.ts`/
`scans/[id]/create-ticket.ts` (real GitHub/Jira/Linear API calls),
`verify-ownership.ts` (outbound DNS+HTTP per call).
**Why**: an authenticated owner can currently loop any of these and run up
a real cost (OpenAI tokens, compute) with no cap — cost control exists only
for scan creation itself.
**Impact/effort**: low-medium, same `checkRateLimit()` pattern reused per
route.
**Depends on**: none — complements E-02 (plan gating) but is a distinct,
narrower fix (a cap, not a tier restriction).
**Category**: code. **Source**: audit.

## E-13 — Document Supabase backup/restore procedure

**What**: no documented RPO/RTO, no PITR configuration note, no restore
runbook exists anywhere in the repo. Migrations are forward-only with no
`down` scripts.
**Why**: "a backup you've never restored from isn't a backup, it's a hope"
(the codebase's own blog seed content, somewhat ironically the only place
this idea appears).
**Impact/effort**: low effort if Supabase PITR is already enabled on the
project (verify + document); higher if it needs enabling and testing a real
restore first.
**Depends on**: access to the Supabase project's plan/settings to confirm
current PITR status.
**Category**: money/time (verifying + possibly upgrading the Supabase plan)
+ code (the runbook itself is just a doc). **Source**: audit.

## E-14 — Remove the `"changeme"` default for `ZAP_API_KEY`

**What**: `src/worker/tools/zap.ts:97` —
`process.env.ZAP_API_KEY ?? "changeme"`. A literal, trivially-guessable
fallback credential for a security tool's own API key.
**Why**: if a ZAP daemon is ever reachable and its API key isn't
explicitly set, this is a real weak-default finding — the kind of thing
this product's own scanner would flag on someone else's site.
**Impact/effort**: trivial — fail loudly (throw / `not_configured`) instead
of defaulting, matching every other optional-credential module's pattern in
this codebase.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-15 — Add a UI entry point for remediation-PR generation

**What**: `POST /api/generate-fix-pr` — opens a real GitHub PR fixing
headers/deps — has **no caller in the UI at all**. Reachable only by
hand-crafting a session-authenticated POST request. It's advertised on
`/services` as "Remediation Pull Requests."
**Why**: a real, working, differentiated feature (see
`docs/COMPETITIVE-ANALYSIS.md` §5's remediation ladder) that customers
currently cannot discover or use.
**Impact/effort**: low-medium — the backend works; this is adding a button
to `ScanReportView.tsx`'s `FindingCard`, matching the existing pattern for
"Get AI-tailored fix"/"Create ticket."
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-16 — In-app first-run onboarding checklist

**What**: a dashboard checklist for a new signup — verify domain → run
first scan → read the report → set an alert channel — rather than relying
on documentation nobody reads post-signup.
**Why**: onboarding friction / time-to-first-value is itself a competitive
dimension (`docs/COMPETITIVE-ANALYSIS.md` D10); this is a product feature,
not something a markdown file can fix (see `docs/ONBOARDING.md` §0's
reasoning for why no customer-facing onboarding doc was written).
**Impact/effort**: medium — new dashboard component + state tracking
per-account.
**Depends on**: none, but naturally follows E-01 (no point checklisting
"add a target" for a Basic/Pro account that currently can't).
**Category**: code. **Source**: audit.

## E-17 — Paginate/cap the remaining unbounded admin queries

**What**: `admin/overview.ts` fetches all rows of `users`/`subscriptions`/`scans`
with no `.range()`/`.limit()` (unlike `admin/audit.ts`/`blog.ts`/`customers.ts`/`scans.ts`,
which all paginate correctly) and counts scans in JS — will silently return
wrong totals once past PostgREST's default 1000-row ceiling.
`admin/contacts.ts` has a `.limit(100)` with no pagination UI beyond it.
`admin/metrics.ts` samples only the 500 most recent scans for its
status/MRR breakdown.
**Why**: correctness bug at scale, not just a performance one — the admin
panel would report confidently wrong numbers rather than erroring.
**Impact/effort**: low-medium, same `.range()` pattern already used
correctly elsewhere in the same directory.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-18 — Verify `xsser.ts` and `commix.ts` against a real binary

**What**: both tool wrappers carry an explicit `CONFIDENCE NOTE` in their
own header comments — written without a verified reference run against the
real `xsser`/`commix` binaries, unlike every other tool wrapper in
`src/worker/tools/` (which were copied from already-verified integrations).
**Why**: these are the least-trustworthy code in the extended scanner
suite. Blast radius is contained (scheduled-job-only, `not_configured` on
any parsing failure), but a wrong flag or output-format assumption
currently degrades silently to "found nothing" rather than being caught.
**Impact/effort**: low effort once a test environment with both binaries
installed exists (matching `scheduled-scans.yml`'s own install step) —
mostly about *having* that environment, not writing new code.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-19 — Delete the stale duplicate `on-demand-scan.yml`

**What**: `hebridescyber-app/.github/workflows/on-demand-scan.yml` is a
different, older copy of the real workflow at the git root
(`.github/workflows/on-demand-scan.yml`). GitHub only executes root-level
workflows, so the nested copy is dead — but it's a live trap for a future
edit made to the wrong file.
**Why**: pure cleanup, but the risk (someone "fixing" the dead copy and
wondering why nothing changed) is real and has already caused confusion
once in this project's history (see the two-root layout note in
`docs/ONBOARDING.md` §0).
**Impact/effort**: trivial. A good first contributor task — see
`docs/ONBOARDING.md` §7.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-20 — Add a `pull_request` trigger to `deploy.yml`

**What**: `deploy.yml` triggers only on `push: branches: [master]` — every
quality gate (lint, typecheck, unit tests, coverage floor, e2e) currently
runs *after* merge, in the same job that deploys. A failing check doesn't
block a merge; it blocks the deploy, leaving `master` broken until fixed.
**Why**: survivable solo; becomes a real problem with a second contributor,
and this whole project just onboarded its first `docs/ONBOARDING.md` for
exactly that eventuality.
**Impact/effort**: low effort (split the existing checks into a
`pull_request`-triggered job, keep `push`-triggered deploy as a separate
job that depends on it) — but needs branch-protection rules configured
too, which is a GitHub settings change, not just a workflow-file edit.
**Depends on**: none.
**Category**: code + a GitHub repo-settings change. **Source**: audit.

## E-21 — Migrate auth off localStorage to httpOnly cookies

**What**: `src/lib/auth.ts`'s own TODO — sessions live in
supabase-js's default localStorage-backed browser storage (XSS-readable,
not sent server-side automatically), and `src/proxy.ts` is a deliberate
no-op — there is **no server-side route protection at all**; every
protected page gates itself client-side after rendering. The stronger
pattern (`@supabase/ssr` + httpOnly cookies + a real `proxy.ts` that
redirects unauthenticated requests before a protected page renders) is
already identified in the existing TODO.
**Why**: the author's own assessment — "worth doing before this handles
real customer accounts at scale" — still holds, and arguably held before
today given the app already takes real payments.
**Impact/effort**: high effort — touches every authenticated page and the
whole session-handling model; not a small refactor.
**Depends on**: none technically, but best scheduled deliberately rather
than opportunistically given the blast radius.
**Category**: code (large). **Source**: audit.

## E-22 — Add the RFC-9116-mandatory `Expires` field to `security.txt`

**What**: `public/.well-known/security.txt` is missing `Expires`, which
RFC 9116 §2.5 makes mandatory (has `Contact`, `Preferred-Languages`,
`Canonical` only).
**Why**: for a security vendor specifically, a non-conformant
`security.txt` is a small but real own-goal — this product's own scanner
suite is the kind of thing that would flag a finding like this on someone
else's site.
**Impact/effort**: trivial, one-line fix.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-23 — Link the privacy policy from the public footer

**What**: `src/components/Footer.tsx` links only to the vertical landing
pages (`/tourism`, `/churches`, `/local-trades`); `/privacy` is reachable
only from the dashboard (behind login) and the cookie-consent banner. The
old `PLATFORM-ROADMAP.md` even asserted it should be linked "from the scan
form, not just the footer" — implying the author believed it already was
in the footer. It isn't.
**Why**: a public privacy policy unreachable from the public site is a
straightforward compliance defect and the cheapest fix in this entire
backlog.
**Impact/effort**: trivial.
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-24 — CVE references beyond JS libraries

**What**: `fingerprint.ts`'s broader `riskySoftware` detection (WordPress
core, PHP, Apache version flags) is still prose-only — no live CVE lookup
the way `osv.ts` does for npm-ecosystem JS libraries.
**Why**: these don't map cleanly onto a single OSV ecosystem the way npm
packages do, so this needs a different data source per software type
(e.g. the WordPress core advisory database, a PHP/Apache CVE feed), not
just widening the existing OSV.dev call.
**Impact/effort**: medium-high — genuinely needs new data-source
integrations per software family, not a generalisation of existing code.
**Depends on**: none.
**Category**: code. **Source**: roadmap (harvested from the frozen
engineering log's §0 "genuinely missing" list — this was the one item
there that's still actually true; its sibling item, malware/dark-web
checks, has since shipped as Safe Browsing + HaveIBeenPwned integration,
exactly as that log's §7 "buy, don't build" note proposed).

## E-25 — Per-check isolation in `runAllChecks()`

**What**: `runAllChecks()` (`src/lib/scanners/index.ts`) still uses
`Promise.all()` for its main batch of checks — one throwing check voids the
*entire* scan rather than just that check's findings. Moving to
`Promise.allSettled()` with per-check status recorded was identified as
still worth doing and has not been done.
**Why**: today, one dead third-party dependency (Shodan InternetDB down,
crt.sh unreachable) can silently kill an entire scan's worth of otherwise-
working checks, rather than just reporting that one check as unavailable.
**Impact/effort**: medium — mechanical at the call-site level
(`Promise.all` → `Promise.allSettled` + per-result status handling), but
needs care to make sure every consumer of `ScanResults` correctly handles a
partially-failed batch rather than assuming every field is always present.
**Depends on**: none.
**Category**: code. **Source**: roadmap (harvested from the frozen
engineering log — flagged there as "still worth doing separately," never
completed).

## E-26 — Terraform base scaffold doesn't match real infrastructure

**What**: `azure/terraform/main.tf`'s `azurerm_resource_group.main`,
`azurerm_storage_account.main`, and `azurerm_static_site.main` blocks (and
`azure/cli-scripts/provision.sh`'s equivalent variables) describe resources
that were never actually applied through Terraform — the real production
resource group is `rg-hebrides-cyber` in `eastus2`, not `hebridescyber-rg`
in `uksouth`; the real storage account is `hebridescyberstor`, not
`hebridescyberstorage`; the real Static Web App is named `hebrides-cyber`,
not `hebridescyber-app`. Confirmed via `az group list`/`az resource list`
on 2026-08-27, and via a real `terraform plan` (with no prior state) that
showed it would create all 3 as brand-new resources — right alongside the
real ones — rather than recognizing them as already existing. The Container
Apps resources added alongside this item route around the problem via a
`data "azurerm_resource_group" "existing"` block pointing at the real
group, specifically so a plan/apply of the container path doesn't also
create the phantom duplicates.
**Why**: as written, a plain `terraform apply` against this file (no
`-target`) creates a second, parallel resource group + storage account +
Static Web App next to the real, currently-serving ones — real cost, and a
serious risk of confusion about which resources are actually live if anyone
(including a future Claude Code session) ever runs it without reading this
item first.
**Impact/effort**: medium — either `terraform import` the 3 real resources
into state under their real names (making the file describe reality, so
`plan` shows 0 changes), or delete the 3 blocks entirely and note that the
SWA path is CLI-managed only, not Terraform-managed. Both are safe,
non-destructive changes to the `.tf` file; neither touches real Azure
resources by itself.
**Depends on**: none.
**Category**: code. **Source**: production-readiness audit (found while
scoping the Container Apps deploy path's Terraform additions).
