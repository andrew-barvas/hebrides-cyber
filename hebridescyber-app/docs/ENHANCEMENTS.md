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

**Status: partially fixed (2026-08-28).** Closed the 3 gaps that were
already advertised on a real page but enforced nowhere, following the
`branding-logo.ts` pattern (session-only, re-checks the caller's — or for
team invites, the team *owner's* — current `subscriptions.plan` server-side,
never trusts a client claim):
- `account/target-auth.ts` — POST now requires `plan === "agency"`
  (matches "Optional (Agency)" on `/what-we-check`). DELETE stays ungated
  so a downgraded account can still remove a credential it can no longer add.
- `team.ts` (`createTeam`) and `team/members.ts` (`invite`) — both now
  require `plan === "agency"` (matches `docs/USER-GUIDE.md` §3.7's "Agency
  ... team collaboration"). `invite` checks the **team owner's** plan, not
  the caller's, since an admin-role member could be inviting on the owner's
  behalf. Role changes, removal, and viewing the team stay ungated.
- `account/connect-repo.ts` — POST now requires `plan` to be `"pro"` or
  `"agency"` (matches "Pro ... dependency monitoring" in the same
  USER-GUIDE section; the connection gates Gitleaks/dockerBaseImage.ts too,
  not just dependency-manifest scanning, since all three currently share one
  connection). DELETE stays ungated.

Also reclassified `webhooks.ts` from "gap" to **intentional, not a gap** —
`docs/USER-GUIDE.md` §3.5 already documents outbound webhooks as "for
anyone building their own integration," unlike Slack/Teams alerts which the
same paragraph does gate to Pro/Agency. The matrix previously listed it
alongside the real gaps without noting this; fixed there too.

**What's still open, deliberately not touched**: `keys.ts`, `webhooks.ts`'s
own key/count limits, `account/ticket-integration.ts`, AI-tailored fix
(`scans/[id]/ai-fix.ts`), remediation PRs (`generate-fix-pr.ts`), ticket
ceation (`scans/[id]/create-ticket.ts`), share-link tier differentiation
(`scans/[id]/shares.ts`), and `generate-report.ts`'s base PDF-generation
cost. None of these are advertised as tier-specific anywhere in current
copy — gating them would mean inventing new product policy, not fixing a
documented mismatch, which is exactly the distinction this item's own
"Depends on" line below was already flagging. Left open pending the
account owner's decision on which (if any) should become tier-exclusive.

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

**Status: fixed (2026-09-04), needs your own Sentry account to actually
activate.** Wired `@sentry/nextjs` — `src/instrumentation.ts` (server/edge
registration + `onRequestError` for API-route/server-component errors),
`src/instrumentation-client.ts` (browser), `src/sentry.server.config.ts`/
`sentry.edge.config.ts`, and `src/app/error.tsx`/`global-error.tsx` (route
errors and root-layout errors respectively — the two were previously
console.error-only, `error.tsx`'s comment literally said "wire to Sentry
here later"). `next.config.mjs` wrapped with `withSentryConfig` for
optional source-map upload.

**Genuinely optional, not fake-optional**: `Sentry.init({ dsn: undefined
})` is a real no-op (captures nothing, throws nothing) when
`SENTRY_DSN`/`NEXT_PUBLIC_SENTRY_DSN` aren't set — matches every other
optional external service in this codebase (Upstash, Resend/SendGrid,
HIBP/Safe Browsing). Ships safely with zero required action; starts
working the moment a DSN is set. **You'll need to create a Sentry account
yourself** (free Developer plan, 5k errors/month) — account creation on a
third-party service isn't something this session does regardless of
context, same as the earlier Stripe/domain-registration boundaries.

Redaction: new `src/lib/sentryScrub.ts`, shared across all three runtime
entry points (one implementation, not three copies that could drift) —
scrubs target-auth credentials and anything key-name-matching
password/token/secret/api_key/service_role/authorization from
request/extra/contexts recursively. Scan **findings themselves are
deliberately not scrubbed** — they're the customer's own security data
about their own site, not a credential, and stripping them would defeat
the point of capturing a scan-processing error in the first place.

CSP fix found along the way: `connect-src` didn't allowlist Sentry's
ingest domain — without this, the browser SDK's error reports would have
been silently blocked by this app's own strict CSP with no visible error
beyond a console warning. Fixed in the same change.

Tests: `sentryScrub.test.ts` — first-ever coverage for that file. Full
suite (419 tests), `tsc`, lint (`npm run build` surfaced two Sentry SDK
deprecation warnings — `withSentryConfig` import path and two Turbopack-
inapplicable webpack-only options — fixed rather than shipped stale), and
build all verified clean. `npm audit` picked up one new moderate
transitive vulnerability from the Sentry install (`qs`, via an unrelated
`stripe` dependency actually) — fixed via a `package.json` `overrides`
entry per this project's own stated convention, not `audit fix --force`.

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

**Status: fixed (2026-09-04).** New `GET /api/health`, public and
unauthenticated (a standard uptime-monitor convention — an external
monitor has no credential to send). Returns only booleans/counts, never a
raw error message or stack trace, since the response is public by
design — verified with a test asserting a deliberately-injected secret-
looking error message never appears in the response body.

Three sub-checks, run in parallel: a real Supabase query (not just "is the
client constructed"), a real Stripe API call (`balance.retrieve()` — same
lesson as E-07: an unset/invalid key should be visibly broken, not
silently trusted), and `scan_jobs` queue depth. Queue depth is
**informational only** — a large backlog isn't the same failure class as
"can't reach Supabase," so it never flips overall health on its own, only
if the count query itself fails to run (tested as two distinct cases).
200 when every check passes, 503 otherwise.

Tests: `health.test.ts` — first-ever coverage for this route. Verified
alongside E-03's changes (same commit) — full suite, `tsc`, lint, build
all clean.

**What**: `GET /api/health` — Supabase/Stripe/queue-depth sub-checks, 200
when healthy, 503 when degraded. Doesn't exist today.
**Why**: nothing external can currently determine whether the app is up
short of loading a page; blocks any real uptime monitoring.
**Impact/effort**: low effort, unlocks E-03's value (an alert needs
something to alert *from*).
**Depends on**: none.
**Category**: code. **Source**: audit.

## E-05 — Rate limit / abuse-protect the public contact form

**Status: fixed (2026-08-28).** `POST /api/contact` now calls
`checkRateLimit(getClientIp(req), "contact")` before touching the database —
10 requests/hour per IP, 429 + `Retry-After` on rejection.
`checkRateLimit()` previously hardcoded its Redis key to a `run-scan:`
prefix regardless of caller; reusing it for a second, unrelated purpose
surfaced that, so it now takes an explicit `namespace` parameter
(`run-scan.ts`/`v1/scans.ts` keep sharing `"run-scan"`, their existing
combined-quota behaviour is unchanged). A new `getClientIp()` helper reads
`x-forwarded-for` (Azure's CDN sets this ahead of Oryx's managed Functions),
falling back to the socket address for local dev. No CAPTCHA/honeypot added
— judged sufficient for current volume; revisit if the IP-based limit proves
insufficient in practice. Tests: `src/__tests__/api/contact.test.ts`,
`src/__tests__/rateLimit.test.ts` (the latter is rateLimit.ts's first-ever
test coverage).

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

**Status: started (2026-09-05).** Adopted incrementally, per this item's
own recommendation, rather than a big-bang rewrite. Shipped: `zod` added as
a dependency; `src/lib/validate.ts`'s `parseBody(schema, body, res)` is the
shared helper (writes a 400 with a field-scoped message and returns null on
a validation failure, matching the early-return convention used everywhere
else in this codebase); applied to the two worst offenders named below —
`admin/contacts.ts`'s PATCH and all three `team/members.ts` handlers
(`invite`/`setRole`/`remove`). One real behaviour fix alongside the
type-safety win: `invite`'s `role` field used to silently coerce anything
that wasn't exactly `"admin"` to `"member"` (a typo like `"administrator"`
would have silently succeeded with the wrong role); it's now a proper
`z.enum(["admin","member"]).optional()` that rejects an invalid value with
400 instead. ID fields use `z.string().min(1)`, not `z.string().uuid()` —
zod v4 enforces strict RFC 4122 variant bits, which would reject the
repeating-digit placeholder IDs (`"33333333-..."` etc.) used as test
fixtures throughout this codebase's existing test suites, for no real
security benefit (Postgres already rejects a malformed UUID against a
`uuid` column at the DB layer). `npx tsc --noEmit`, lint, full `vitest run`,
and `next build` all verified clean. **Still open**: the other ~26
`req.body as {...}` instances — backfill opportunistically as those routes
are touched, per this item's own guidance, rather than in one pass.

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

**Status: fixed (2026-08-28).** Both routes now call the shared
`requireAdmin()`. `admin/contacts.ts` lost its own anon-`createClient` JWT
verification entirely (no behaviour change — every failure mode already
returned 403). `admin/overview.ts`'s failure responses changed from
one-off 401s to 403, matching `requireAdmin()`'s actual contract and every
other correctly-implemented admin route (`admin/customers.ts` etc.) —
tests updated to match. Full suite (375 tests), `tsc`, lint, and build all
verified clean.

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

**Status: fixed (2026-09-05).** Docs were already reconciled (`security.md`
defers to `/privacy`'s figures, see `docs/decisions/ENGINEERING-LOG-2026-08.md`)
before this pass — what remained was the missing implementation. Confirmed
with the account owner: automate against the already-published figures
rather than changing policy first. Shipped:
- `src/scripts/cleanup-retention.ts`, run nightly by
  `.github/workflows/data-retention-cleanup.yml` (git root) — deletes
  `scan_results` rows and `contact_enquiries` rows older than 12 months, and
  report PDFs in Blob Storage older than 90 days. Matches the
  `daily-blog.yml`/`weekly-newsletter.yml` direct-script pattern.
- `src/pages/api/account/request-deletion.ts` +
  `src/components/AccountDeletion.tsx` (wired into `/account`'s new "danger
  zone" section) — customer-facing GDPR erasure request. Only logs to
  `audit_logs` and emails the account owner; deletes nothing itself.
- `src/scripts/erase-user-data.ts` — the actual erasure, run manually by a
  human. Dry-run by default (`--confirm` to execute); deletes that user's
  report PDFs then their `auth.users` row, letting the existing `on delete
  cascade` FKs remove everything else. Does not touch Stripe — an active
  subscription is flagged as a warning, not cancelled automatically.
- Deliberately NOT automated: account/subscription deletion (no reliable
  "account closure" event exists in the schema to anchor a timer to — an
  automatic full-account delete on subscription cancellation risks erasing
  a customer who's just pausing between plans) and server-log retention
  (an Azure infra setting, not application data — configure separately in
  Azure Log Analytics if not already set).
- `npx tsc --noEmit`, lint, full `vitest run`, and `next build` all
  verified clean.

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

**Status: fixed (2026-09-05).** Applied the same fix a third time: moved the
logic into `src/lib/monthlyDigest.ts` (`sendMonthlyDigest()`, now unit
tested — 7 cases covering skip conditions, the score-delta/new-fixed
calculation, and per-owner error isolation), running via
`src/scripts/send-monthly-digest.ts` directly against Supabase, no HTTP
hop. `src/pages/api/send-monthly-digest.ts` and `DIGEST_SERVICE_TOKEN` are
deleted, not kept as a fallback — same precedent as the daily blog/weekly
newsletter conversion. `.github/workflows/monthly-digest.yml` updated to
run the script with `SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY` instead of
curling the old route. `npx tsc --noEmit`, lint, full `vitest run`, and
`next build` all verified clean.

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

**Status: fixed (2026-09-05).** All 5 named routes now call `checkRateLimit()`
with their own namespace (`ai-fix`, `generate-report`, `generate-fix-pr`,
`create-ticket`, `verify-ownership`), same shared 10-requests/hour-per-caller
limiter `run-scan.ts` already used — matches the "cap, not a tier
restriction" framing exactly. `ai-fix.ts`/`generate-report.ts`/
`generate-fix-pr.ts` had no test file at all before this; added focused
coverage of the auth/rate-limit gates for each (not full happy-path
coverage of Azure OpenAI/Playwright/GitHub API logic, which is out of this
fix's scope). `create-ticket.test.ts`/`verify-ownership.test.ts` already
existed with many test cases sharing one caller id — mocked
`checkRateLimit` in both so the real in-memory limiter's shared,
module-level bucket doesn't accumulate across a whole test file's cases and
start failing unrelated tests with 429s. `npx tsc --noEmit`, lint, full
`vitest run`, and `next build` all verified clean.

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

**Status: fixed (2026-08-28).** New `OnboardingChecklist.tsx`, rendered on
the dashboard for any authenticated account (not gated to an active plan —
useful pre-subscription too) right after `PlanUpsell`. All four steps are
derived from data already on the page or a cheap existence-only query, not
a new "has the user seen this" tracking table:
- Verify a domain → `verifications` table, any row with `verified_at`
  not null.
- Run your first scan → `scans.length > 0` (already fetched for
  `ScanList`).
- Read your first report → `overviewScan !== null` (already computed for
  the dashboard's own Security Overview) — a deliberate proxy for "a
  report now exists and is visible," not real view tracking.
- Set an alert channel → Slack/Teams webhook set (`loadPlan`'s existing
  state) **or** an outbound webhook row exists. Wording adapts per plan:
  Pro/Agency see "Connect Slack or Teams" (the actually-available option
  for them); every other plan sees "Set up a webhook," since outbound
  webhooks are deliberately ungated (`docs/USER-GUIDE.md` §3.5) while
  Slack/Teams are Pro/Agency-only.

Auto-hides once every step is complete, and is manually dismissible via a
`localStorage` flag (per-viewer convenience, same precedent as the
leaderboard rank-change baseline elsewhere in this app). Each incomplete
step links to the relevant section via a new anchor id
(`#domain-verification`/`#run-a-scan`/`#scan-history`) or `/account`.
Tests: `src/components/OnboardingChecklist.test.tsx` (the component's
first-ever coverage — `dashboard/page.tsx` itself still has none, a
pre-existing gap not backfilled here). Full suite (382 tests), `tsc`,
lint, and build all verified clean. **Not yet manually verified in a
browser against a real staging account** — the dashboard is auth-gated,
and this session relied on unit tests + build rather than an interactive
session; worth a real click-through before calling this fully proven.

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

**Status: fixed (2026-09-05).** `admin/overview.ts` now paginates the
customer list (page/pageSize query params, `{count:"exact"}`) the same way
`admin/customers.ts` already did — the two are near-duplicates and
`admin/overview.ts` turns out to have **no frontend caller at all**
(`OverviewTab` in `src/app/admin/page.tsx` calls `/api/admin/metrics`, not
`/api/admin/overview`); flagging that rather than deleting it, since
removing a route is a bigger call than this item asked for. `totalScans`/
`activeSubscriptions` totals now come from exact-count head queries instead
of `.length` on a truncated array. `admin/contacts.ts` is now properly
paginated (page/pageSize, `{count:"exact"}`) with real Prev/Next controls
added to the Contacts tab, matching the Audit tab's existing pattern.
`admin/metrics.ts`'s `totalScans`/`scansByStatus`/`scansLast30d` no longer
sample the 500 most recent scans — each is now an exact-count head query
(one per `scans.status` enum value for the breakdown), run sequentially
rather than in parallel since they all hit the same table and parallel
same-table thenables resolve in a non-deterministic relative order (found
while writing the regression test — see the sequential-vs-Promise.all
comment in the file). `npx tsc --noEmit`, lint, full `vitest run`, and
`next build` all verified clean; not yet manually verified in a browser
against a real staging admin account (no Supabase credentials in this
environment) — the API-level test coverage is real, this is only "haven't
clicked through it."

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

## E-27 — Multi-target "fleet" rollup on the dashboard

**Status: fixed (2026-09-04).** New `FleetOverview.tsx`, rendered on the
dashboard just above the existing single-scan Security Overview — one row
per monitored target (site, score, open-findings count, last-scanned,
linking through to that target's latest report), sorted worst-score-first
so the sites needing attention surface at the top rather than insertion
order. Matched to each target's latest scan by hostname, reusing the exact
convention `clientScanHistory.ts` already established (`target_url` isn't
byte-identical across scans of "the same" site). One batch fetch of the
200 most recent completed scans across all targets, matched client-side —
same shape as the existing single-target history fetch, just scoped to
every target in one pass instead of one target at a time.

Deliberately renders nothing for 0-1 targets: a single-target account
already gets an equivalent (arguably richer, since it includes trend/diff
data) view from the existing Security Overview immediately below it, and a
one-row fleet table would just duplicate it, not add anything.

Open-findings count excludes `info`-severity findings, matching the same
"actionable findings" filter `remediation.ts`'s PR-body builder already
uses, not a new counting convention.

Tests: `src/components/FleetOverview.test.tsx` — the component's
first-ever coverage. Full suite (387 tests), `tsc`, lint, and build all
verified clean. **Not yet manually verified in a browser against a real
staging Agency account with multiple targets** — same caveat as E-16.

**What**: the dashboard's "Security Overview" (`dashboard/page.tsx`) shows
only the most-recently-completed scan across every monitored target — its
own comment says so explicitly ("not an aggregate across every monitored
target... a multi-target selector is a bigger, separate design question").
An Agency account with up to 15 targets (post-E-01's caps) has no way to see
all of them at a glance — worst score, most recent New/Fixed diff per
target, which ones haven't scanned recently — only whichever one happened to
finish last.
**Why**: this is the single biggest gap between "Agency = multi-site
monitoring" (the pricing-page differentiator) and what the dashboard
actually shows. A customer paying for fleet monitoring currently manages
that fleet by mentally tracking which target's data they're looking at.
**Impact/effort**: medium-high — a genuinely new view (per-target score/
status cards or a table, sortable by score/last-scanned/open-findings), not
a small tweak to the existing single-scan overview. Reuses existing data
(`scan_results`, `monitored_targets`) — no new scanning or backend logic
needed, this is a dashboard/query-shape problem.
**Depends on**: E-01 (done) — this is the natural next step now that
multi-target access itself exists.
**Category**: code. **Source**: product/dashboard review.

## E-28 — Findings-by-category and compliance-coverage trend reporting

**Status: fixed (2026-09-04).** New `ComplianceTrend.tsx`, rendered on the
dashboard right after `ScoreTrend`, with two views sharing one data source:
- **Open findings by category** — current scan's non-info findings grouped
  by their checkId's module prefix (`tls`, `headers`, `dns`, etc. — already
  a stable taxonomy per `compliance.ts`'s own header comment, reused rather
  than inventing a second scheme), rendered as a simple bar list.
- **Compliance coverage trend** — % of each framework's controls (Cyber
  Essentials/OWASP/CIS) with zero open findings, across the same scan
  history window `ScoreTrend` uses. New `ALL_CONTROLS_BY_FRAMEWORK` export
  on `compliance.ts` gives a *fixed* denominator derived from
  `COMPLIANCE_MAP` itself (never a hand-maintained second list), so 100%
  genuinely means "every control this app checks for is clean," not "no
  findings happened to map to anything."

New `findComplianceHistoryClient()` in `clientScanHistory.ts`, matching
`findScoreHistoryClient`'s existing hostname-matching convention exactly —
one more data point derived from the same per-scan fetch pattern, not a
second copy of the matching logic. Capped at 10 points (vs. score's 20) —
coverage moves slower scan-to-scan than a single score number, so a
shorter window reads more clearly.

Tests: `clientScanHistory.test.ts` and `ComplianceTrend.test.tsx` (both
first-ever coverage for their files), plus 3 new tests on `compliance.ts`'s
new export. Full suite (405 tests), `tsc`, lint, and build all verified
clean. Same not-yet-browser-verified caveat as E-16/E-27.

**What**: `ScoreTrend.tsx` charts one number (score) over time per target.
There's no view of *what kind* of findings are trending up/down (TLS vs.
headers vs. dependency CVEs vs. exposure, etc.) or how Cyber Essentials/
OWASP/CIS coverage (`src/lib/scanners/compliance.ts` already computes this
per scan) changes scan-over-scan — that mapping is computed and stored but
never visualised as a trend, only as a per-scan snapshot in the report.
**Why**: "is our security posture actually improving, and in which areas"
is a more useful question for a repeat customer than a single score number,
and the compliance-trend view specifically reinforces the Cyber Essentials
positioning (`docs/COMPETITIVE-ANALYSIS.md` §9) with real data rather than a
one-off report page.
**Impact/effort**: medium — the compliance-mapping data already exists per
scan; this is aggregation + a new chart, not new scanning logic. Category
breakdown needs grouping `scan_results` findings by check category, which
doesn't currently have a stable taxonomy — worth deciding that grouping
once, not per-chart.
**Depends on**: none technically, but sequenced after E-27 since both touch
the same dashboard area and a shared "which target(s) am I looking at"
selector should probably be built once for both.
**Category**: code. **Source**: product/dashboard review.

## E-29 — Dependency-manifest scanning: Go and Maven ecosystem coverage

**Status: fixed (2026-08-28).** `dependencyManifest.ts` now also scans
`go.mod` and `pom.xml`, on the same OSV.dev-backed foundation as npm/pip/
Composer — OSV.dev's `Go` and `Maven` ecosystem strings work identically to
the existing three. Go modules pin exact versions (no range reduction
needed, unlike npm/Composer's carets); Maven's `pom.xml` gets a
regex-only extraction (no XML parser dependency, matching every other
manifest here) that resolves `${property}` version references against a
sibling `<properties>` block and deliberately ignores
`<dependencyManagement>`'s own `<dependency>` entries (its own nested
`<dependencies>` block has the exact same shape as the real one, and a
first version of this fix wrongly matched it — caught while writing this
item's own tests, fixed via a shared `extractMavenDependenciesBlock()` used
by both the parser and the entry point's declared-count, rather than two
copies that could drift). `remediationText.ts`'s
`dependencyVulnerableRemediation()` gained `go`/`maven` command sets
(`go get`/`go mod tidy`, `mvn versions:display-dependency-updates`).
Tests: `src/__tests__/scanners/dependencyManifest.test.ts` — the parsers'
first-ever test coverage (none existed for npm/pip/Composer either; not
backfilled here, out of scope for this change).

**What**: `dependencyManifest.ts` covered only npm/pip/Composer via OSV.dev
— no Go or Java/Maven support, both common ecosystems OSV.dev already
indexes.
**Why**: raised while comparing against Snyk's ecosystem breadth
(`docs/COMPETITIVE-ANALYSIS.md` §2 lists Snyk as a substitute that wins
deals on the dependency side specifically) — this was flagged as the
single lowest-effort, highest-value gap to close, since it extends an
existing pattern rather than requiring new architecture.
**Impact/effort**: was low-medium — reused the existing OSV.dev query path
and `buildFindingsForDeps` entirely; only new manifest parsing was needed.
**Depends on**: none.
**Category**: code. **Source**: competitive gap (Snyk comparison).

## E-30 — Per-finding "retest" button

**What**: Closed Door Security's PTaaS platform (`cdsec.co.uk/ptaas`) has a
live retest loop — flag a fix, click retest, get an immediate re-verify
against that one finding, rather than waiting for the next full scheduled
scan. Hebrides Cyber has the underlying capability (any scan recomputes
New/Fixed status via `findingsDiff.ts`) but no UI to trigger a single,
immediate re-check of one specific finding.
**Why**: genuinely good competitive UX to harvest — closes the loop for a
customer who's just pushed a fix and wants confirmation now, not on the
next cadence-scheduled scan.
**Impact/effort**: medium — needs a scoped "recheck this one finding"
scan mode (or a fast full re-scan triggered from a finding row), plus UI.
Not just a copy of `run-scan.ts`'s existing flow, which re-runs the whole
suite.
**Depends on**: none.
**Category**: code. **Source**: competitive UX harvest (Closed Door
Security PTaaS, 2026-09-04).

## E-31 — Stored XSS: the public blog rendered unsanitized markdown from external sources

**Status: fixed (2026-09-05).** Found and fixed in response to a direct ask
to self-audit for the same vulnerability classes this product flags in
customers — the irony of a security company shipping this on its own site
made it worth checking immediately rather than filing as a backlog item.

**What**: `src/app/blog/[slug]/page.tsx` rendered `marked.parse(post.body)`
via `dangerouslySetInnerHTML` on a fully public, unauthenticated page, with
no sanitization at all. `marked` does not sanitize its output. `post.body`
is markdown built by `src/lib/newsletter.ts` from **real external text**
Hebrides Cyber doesn't control: NVD CVE descriptions, CISA KEV entries, and
RSS feed titles/summaries — none of it HTML-escaped before being
interpolated into the markdown. A CVE description routinely contains a
literal `<script>`/`onerror` snippet as part of *describing* the
vulnerability it's about (e.g. "XSS via `<script>...</script>` in the
search field") — that snippet would have survived verbatim into the
rendered page.
**Why**: stored XSS on a public page, sourced from content Hebrides Cyber
doesn't author or control — about as bad as a finding gets, and precisely
the class of bug this product exists to catch for customers.
**Fix** (defense in depth, two independent layers):
- Generation time: `buildKevSection`/`buildNvdSection`/`buildNewsSection`
  (`src/lib/newsletter.ts`) now HTML-escape every externally-sourced field
  before interpolating it into markdown, reusing the existing `escapeHtml`
  from `src/lib/email.ts`.
- Render time: `src/app/blog/[slug]/page.tsx` now runs `marked.parse()`'s
  output through `isomorphic-dompurify` before `dangerouslySetInnerHTML` —
  this also covers admin-authored posts and the AI-narrative generation
  path, neither of which the render step should have to trust just because
  the generation-time fix above covers the deterministic path.
- 6 new regression tests (`src/lib/newsletter.xss.test.ts`) assert a
  `<script>`/`<img onerror>` payload embedded in each of the three
  external-text fields is neutralised. `npx tsc --noEmit`, lint, full
  `vitest run`, `npm audit --audit-level=moderate` (0 vulnerabilities for
  the two new dependencies), and `next build` all verified clean. The
  sanitizer itself was also verified directly against a raw `<script>`
  payload run through the exact `marked` → `DOMPurify` pipeline.
**Depends on**: none.
**Category**: code (security fix, already shipped). **Source**: direct
request to audit for SQL injection/XSS/command-injection-class issues
given this is a security company's own product, 2026-09-05.
