# Enhancements backlog

Stable-ID (`E-nn`) list of what could be built and why — **no commitment, no
dates**. `docs/ROADMAP.md` decides what's actually sequenced and when,
referencing these IDs; this file never restates roadmap sequencing. Once an
ID is assigned here it's referenced from other docs by that ID — **never
renumber an existing item**; if one is dropped, mark it `WITHDRAWN` and
leave the number retired rather than reusing it.

> **Status is not tracked in this file — don't read a listed `E-nn` as
> "unbuilt."** This is the idea backlog; whether an item has shipped lives in
> [`FUNCTIONALITY-MATRIX.md`](FUNCTIONALITY-MATRIX.md) (the arbiter of what
> exists and how it's gated) and the "Shipped" table in
> [`NEXT-STEPS.md`](NEXT-STEPS.md). Several items here (e.g. **E-70–E-74**:
> crawler, PR dependency checks, sqlmap fix, benchmark, cross-site findings) are
> **already shipped** per those files. When in doubt, FUNCTIONALITY-MATRIX wins.
> *(This note added by the 2026-10 documentation pass to stop the "backlog =
> not done" misread that propagated stale capability claims into external copy —
> see `PRODUCT-REVIEW-2026-10.md` Phase 2.)*

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

**Status: fixed (2026-09-13).** All 21 write routes now use
`parseBody(schema, body, res)` with proper zod schemas. Adopted
incrementally, per this item's own recommendation. Shipped: `zod` added as
a dependency; `src/lib/validate.ts`'s `parseBody(schema, body, res)` is the
shared helper (writes a 400 with a field-scoped message and returns null on
a validation failure, matching the early-return convention used everywhere
else in this codebase); applied to the two worst offenders first —
`admin/contacts.ts`'s PATCH and all three `team/members.ts` handlers
(`invite`/`setRole`/`remove`), then backfilled to the remaining 19 routes
including `contact.ts` (previously had zero shape-checking),
`target-auth.ts` (`z.discriminatedUnion("authType", [...])`), and
`ticket-integration.ts` (`z.discriminatedUnion("provider", [...])`).
One real behaviour fix alongside the type-safety win: `invite`'s `role`
field used to silently coerce anything that wasn't exactly `"admin"` to
`"member"` (a typo like `"administrator"` would have silently succeeded
with the wrong role); it's now a proper
`z.enum(["admin","member"]).optional()` that rejects an invalid value with
400 instead. ID fields use `z.string().min(1)`, not `z.string().uuid()` —
zod v4 enforces strict RFC 4122 variant bits, which would reject the
repeating-digit placeholder IDs (`"33333333-..."` etc.) used as test
fixtures throughout this codebase's existing test suites, for no real
security benefit (Postgres already rejects a malformed UUID against a
`uuid` column at the DB layer). Read-only routes using unvalidated
`req.query` (14 files) left for a future pass — noted here rather than
done now, to keep the scope to the write-route half flagged as
higher-risk. `npx tsc --noEmit`, lint, full `vitest run`,
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

**Status: fixed (2026-09-13).** `src/worker/tools/zap.ts` now returns
`{ status: "not_configured", note: "ZAP_API_KEY is not set — skipping ZAP
scan" }` when `ZAP_API_URL` is set but `ZAP_API_KEY` is not, matching
`hibp.ts`/`safeBrowsing.ts`'s established convention exactly. The
`"changeme"` literal is removed entirely.

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

**Status: fixed (2026-09-13).** "Generate fix PR" button added to the scan
detail page header (`src/app/dashboard/scans/[id]/page.tsx`), visible when
the user has a connected GitHub repo (`repo_connections`). Clicking it calls
`POST /api/generate-fix-pr` and shows a link to the created PR on success.

**What**: `POST /api/generate-fix-pr` — opens a real GitHub PR fixing
headers/deps — previously had **no caller in the UI at all**. It's
advertised on `/services` as "Remediation Pull Requests."
**Why**: a real, working, differentiated feature (see
`docs/COMPETITIVE-ANALYSIS.md` §5's remediation ladder) that customers
previously could not discover or use.
**Impact/effort**: low-medium — the backend works; this was adding a button
to the scan detail page header.
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

**Status: partially done (2026-09-05).** commix verified for real — its own
GitHub source cloned and run locally against a deliberately vulnerable
local test target (a throwaway Node HTTP server with a genuine OS
command-injection endpoint, never any third-party or production system).
Confirmed: `--url`/`--batch` are correct; the real detection pipeline
(heuristic → classic results-based → time-based blind → file-based
semi-blind) correctly progressed end-to-end against a real injection point.
**Found and fixed a real bug**: the `--crawl=1` flag caused commix to
report "No usable links found" and stop without ever testing the target
URL's own query parameter when its page-crawler found nothing to follow —
confirmed by running with and without the flag against the same target.
Removed. **Still not confirmed**: the exact wording of the
vulnerability-found marker `commix.ts`'s regex parses — both verification
runs were stopped before reaching a natural "confirmed" line (time/file-based
blind techniques require many slow, timed requests), and source-tracing
commix's own message-building code suggests the real format may differ by
injection type. Flagged explicitly in `commix.ts`'s own header comment
rather than claiming false confidence.

xsser was **not verified** — installing its mandatory `pycurl` dependency
was refused by this environment's own permission classifier (a sandboxing
control, not a tool failure). Did not attempt to route around it. xsser's
`CONFIDENCE NOTE` is unchanged and this item stays open for it.
**Depends on**: an environment where `pip install pycurl` is permitted, or
xsser installed a different way (its own repo shows it packaged as a
Debian apt package too — `scheduled-scans.yml`'s existing install step
already uses that path in real CI, which is a different, unblocked
environment from this one).

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

**Status: fixed (2026-09-13).** `deploy.yml` now has three jobs: `check`
(lint/tsc/unit tests/e2e — runs on both `push` and `pull_request`),
`migration-check` (E-49 schema verification — runs on push/dispatch only),
and `deploy` (runs only on push to master, depends on both check jobs).
PRs now get quality-gate feedback before merge. **Still needs**: GitHub
branch-protection rules configured to require the `check` job to pass
before merging — that's a repo-settings change, not a workflow-file edit.

**What**: `deploy.yml` previously triggered only on `push: branches:
[master]` — every quality gate ran *after* merge, in the same job that
deployed.
**Why**: survivable solo; becomes a real problem with a second contributor.
**Impact/effort**: low effort — split the existing checks into a
`pull_request`-triggered job, kept `push`-triggered deploy as a separate
job that depends on it.
**Depends on**: none (the workflow change is done; branch-protection is a
GitHub repo-settings change only the owner can configure).
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

**Status: fixed (2026-09-13).** Added `Expires: 2027-09-13T00:00:00.000Z`
(one year out), per RFC 9116 §2.5.

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

**Status: fixed (2026-09-25).** Shipped as `src/lib/scanners/softwareCveDb.ts`,
a new enrichment module following `wpvdb.ts`'s exact pattern — it takes
`fingerprint.ts`'s already-detected `riskySoftware` and adds real CVE data
from two data sources per the plan this section originally called for:
WordPress core via WPScan's `/wordpresses/{version}` endpoint (the same
`WPSCAN_API_TOKEN`-gated API `wpvdb.ts` already uses for plugins, keyed by
version instead of slug — reuses its exported `vulnerabilityAppliesToVersion`
and `wpVulnSeverity` rather than duplicating them), and PHP/Apache via NVD's
CVE API 2.0 queried by CPE name (`cpeName=cpe:2.3:a:<vendor>:<product>:...`),
the same endpoint `newsletter.ts`'s `fetchRecentHighSeverityCves` already
calls successfully, just with a version-scoped query instead of a date range.
PHP/Apache CVEs are bundled into one `Finding` per software item (capped at
30 `cveIds`) rather than one finding per CVE, to avoid flooding a report for
an old install with dozens of individual findings — severity is derived from
the highest matched CVSS score (critical ≥ 9, high ≥ 7, else medium). Wired
into `runAllChecks()`/`summariseResults()` in `src/lib/scanners/index.ts` as
a post-batch enrichment step after `fingerprint` resolves, exactly like
`wpVulnDb`. New `COMPLIANCE_MAP`/`FIX_DIFFICULTY_MAP` entries and three new
`remediationText.ts` constants (`SOFTWARE_CVE_WORDPRESS_CORE`,
`SOFTWARE_CVE_PHP`, `SOFTWARE_CVE_APACHE`) round it out.

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

**Status: fixed (2026-09-13).** Both `Promise.all()` batches in
`runAllChecks()` (`src/lib/scanners/index.ts`) converted to
`Promise.allSettled()`. Each rejected result falls back to an
`{ status: "error" }` shape matching the check's own error type, so
`summariseResults()` and every other consumer already handles it correctly
(they all guard on `status === "checked"` before accessing check-specific
fields). Mirrors the exact pattern `scanExecution.ts`'s `runExtendedTools()`
already used.

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

**Status: fixed (2026-09-05).** Investigation surfaced a real architectural
constraint that shaped the final scope: there is no way to run just one
check in isolation — `runAllChecks()` (base suite) and the 12-tool extended
batch (`scanExecution.ts`) both always run as one atomic unit, and building
true single-check scoping would be a much larger scanner-suite refactor.
Shipped instead: `src/pages/api/scans/[id]/retest-finding.ts` triggers a
real on-demand rescan (the same fast, base-suite-only path any "Scan now"
click already uses — mirrors `run-scan.ts`'s `scans`/`scan_jobs` insert +
`triggerOnDemandWorkflow()` sequence, minus the domain-reverification dance
since the target's already verified) and reports whether that one finding
came back fixed, without the customer navigating away to compare two full
reports. `src/lib/extendedToolCheckIds.ts` is the single source of truth for
which checkIds this can't safely cover — **findings from the 12 extended
tools (nuclei/zap/sqlmap/xsser/commix/nmap/subdomains/deep-tls/secretScan/
dependency-manifest/docker-base-image/auth-check) are rejected outright
(400) and the "Recheck now" button doesn't even render for them**, both
server-side and client-side, since the on-demand path never runs those
tools — retesting one of their findings this way would silently report
"fixed" without the tool that found it ever running again. Deliberately does
not call `isFreeTierExhausted()` (would double-count a free-tier user's one
allowed scan just for re-verifying a finding they already know about) or add
a new audit-log event (`executeScan()` already logs `scan.started`/
`completed`/`failed` for every job, retests included). UI copy says "Recheck
now," not anything implying the check was individually isolated — the whole
base suite genuinely reruns, so a Pro/Agency customer with Slack/Teams
alerts will also get a "score changed" notification if anything else
changed too, which is correct, not a bug. `npx tsc --noEmit`, lint, full
`vitest run` (47 new tests across the helper, the API route, and the
frontend component), and `next build` all verified clean. Not yet manually
verified in a browser (no Supabase credentials in this environment).

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

## E-32 — Cloud posture scanning (AWS/Azure/GCP configuration review)

## E-35 — CMS scanning tools (WPScan, CMSmap)

**Status: fixed (2026-09-11).** New extended tools `src/worker/tools/wpscan.ts`
and `src/worker/tools/cmsmap.ts`, wired into `runExtendedTools()`. WPScan
runs a targeted `--enumerate` sweep when WordPress is detected; CMSmap runs
a general CMS fingerprint scan. Both follow the established
`not_configured`-on-missing-binary pattern. CI install steps added to
`scheduled-scans.yml`.
**Category**: code. **Source**: roadmap.

## E-36 — OSINT tools (Gospider, Photon, metadata leak, AJAX spider)

**Status: fixed (2026-09-11).** Four new extended tools in `src/worker/tools/`:
`gospider.ts` (web spidering/link extraction), `photon.ts` (data extraction),
`metadataLeak.ts` (document metadata OSINT), and `ajaxSpider.ts` (ZAP AJAX
spider for JS-heavy SPAs). All wired into `runExtendedTools()` and follow
existing conventions.
**Category**: code. **Source**: roadmap.

## E-37 — WAF detection (WhatWaf)

**Status: fixed (2026-09-11).** New `src/worker/tools/whatwaf.ts`, detects
WAF/IDS presence before active scanning. Runs early in the extended tool
pipeline to inform other tools' expectations.
**Category**: code. **Source**: roadmap.

## E-38 — API security testing tools (Kiterunner, Arjun, session check)

**Status: fixed (2026-09-11).** New `src/worker/tools/kiterunner.ts`
(API endpoint brute-force discovery), `arjun.ts` (hidden parameter
discovery), and `sessionCheck.ts` (session management analysis). All
wired into `runExtendedTools()`.
**Category**: code. **Source**: roadmap.

## E-39 — Partner Portal panel (Agency-tier fleet management)

**Status: fixed (2026-09-11).** New `PartnerPortalPanel.tsx`, rendered on
the dashboard for Agency-plan accounts only. Shows a fleet-level rollup with
per-client scan status, score trends, and white-label report generation
links. **Client-only gate** (`{plan === "agency" && <PartnerPortalPanel />}`
in `dashboard/page.tsx`) — no server enforcement, but the component only
ever shows the caller's own RLS-scoped data, so the exposure is
informational not exploitable. Noted as ⚠️ in `FUNCTIONALITY-MATRIX.md`.
**Category**: code. **Source**: roadmap.

## E-40 — Asset inventory (subdomain/hostname tracking)

**Status: fixed (2026-09-11).** New `src/lib/assetInventory.ts` with
`syncAssetInventory()` called as a best-effort post-scan step in
`scanExecution.ts`. Populates the `asset_inventory` table (migration 022)
with every hostname seen across an owner's scans. New
`src/components/AssetInventory.tsx` and `/dashboard/assets` page for
viewing. RLS-scoped, team-visible.
**Category**: code. **Source**: roadmap.

## E-41 — Critical path analysis + multi-framework compliance tabs

**Status: fixed (2026-09-11).** New `src/lib/attackPathAnalysis.ts`
(`computeCriticalPaths()`) identifies attack chains across findings.
`ScanReportView.tsx`'s `ComplianceSummary` replaced with a framework-tabbed
version using `ALL_CONTROLS_BY_FRAMEWORK` (Cyber Essentials, OWASP Top 10,
CIS Controls v8, ISO 27001, PCI DSS, NIS2, DORA). `CriticalPaths` component
renders identified attack chains on the scan detail page.
**Category**: code. **Source**: roadmap.

## E-42 — Fix Wizard (guided remediation)

**Status: fixed (2026-09-11).** New `src/components/FixWizard.tsx`, activated
via `?wizard=1` URL param on the scan detail page. Provides step-by-step
guided remediation for each finding, grouped by fix difficulty, with inline
code snippets and verification steps.
**Category**: code. **Source**: roadmap.

## E-43 — Scan diff view + score/category history

**Status: fixed (2026-09-11).** New `src/components/DiffView.tsx` and
`/dashboard/scans/[id]/diff` page for side-by-side comparison of two scans.
New `/dashboard/scans/history` page with `CategorySparklines.tsx` showing
per-category trends. New `src/lib/clientScanHistory.ts` functions for
scan listing, finding lookup, and category history queries.
**Category**: code. **Source**: roadmap.

## E-44 — Scan replay

**Status: fixed (2026-09-11).** New `POST /api/scans/[id]/replay` — re-runs
a scan against the same target with the same (or updated) scan profile.
Resolves the profile from `monitored_targets.scan_profile`, defaults to
`safe` if no monitored-targets row exists. Only dispatches the on-demand
workflow for `safe`-profile replays; non-safe profiles are left for the
scheduled cron (which has the necessary tool binaries). `ReplayButton`
component added to the scan detail page.
**Category**: code. **Source**: roadmap.

## E-45 — Extended team roles + delegated actions

**Status: fixed (2026-09-11).** Migration 025 widens `team_members.role` to
include `developer` and `auditor` roles. `src/lib/teamAccess.ts`'s
`callerCanActFor()` enables team-delegated actions: developers can replay
scans, retest findings, and create tickets on the team owner's behalf.
`TeamSection.tsx` updated with role management UI. `team/members.ts` updated
to validate the widened role set.
**Category**: code. **Source**: roadmap.

## E-46 — Scan profile selector UI

**Status: fixed (2026-09-11).** New `ScanProfileConfig` component in
`MonitoredTargets.tsx` — per-target scan profile selector (safe/full/api/
cms/osint) with tool descriptions and estimated scan times. Writes to
`monitored_targets.scan_profile` via the browser client. **Requires
migration 026** for the UPDATE RLS policy — without it, the write silently
no-ops. Migration 026 added in this session.
**Category**: code. **Source**: roadmap.

## E-47 — Subscriptions RLS security fix

**Status: fixed (2026-09-11).** Migration 024 drops the client-writable
UPDATE policy on `subscriptions` — a real, exploitable revenue-bypass
vulnerability where any signed-in customer could set their own plan to
`agency` via the browser console. Writes to `subscriptions` now go through
`POST /api/account/notification-webhooks` (service-role only).
**Category**: code (security fix). **Source**: audit.

## E-48 — COEP header

**Status: fixed (2026-09-11).** Added `Cross-Origin-Embedder-Policy:
require-corp` to both `next.config.mjs` security headers and
`staticwebapp.config.json` global headers.
**Category**: code. **Source**: audit.

## E-49 — Missing migration-application step in deploy pipeline

**Status: fixed (2026-09-13).** A `migration-check` job added to
`deploy.yml` queries production Supabase via PostgREST to verify that
every column/table the code depends on (from migrations 019–026) actually
exists. Fails the pipeline if a migration hasn't been applied, blocking
deploy of code that would crash. Uses `SUPABASE_URL` +
`SUPABASE_SERVICE_ROLE_KEY` (already in GitHub secrets). This is a
*detection* step, not an *application* step — migrations still need to be
applied manually via the Supabase SQL editor; the CI job catches the gap
before broken code reaches production.

**What**: `deploy.yml` previously built, tested, and deployed the Next.js
app but **never touched the Supabase schema**. No automated step, no CI
check that migrations were applied, no warning when code shipped that
depended on a schema change that hadn't been applied.
**Why**: this caused a live production incident (2026-09-13) — migrations
019-026 had never been applied, causing `column contact_enquiries.company
does not exist` errors, silent RLS failures, and general "backend call
failure" symptoms across the admin panel and dashboard.
**Impact/effort**: medium — the detection step is done; full `supabase db
push` automation would be the next level (needs Supabase CLI auth in CI).
**Depends on**: `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` in GitHub
secrets (already present).
**Category**: code + process. **Source**: production incident, 2026-09-13.

**What**: nothing today checks a customer's *cloud account* configuration —
IAM policies, S3/Blob storage bucket permissions, security group/firewall
rules, public-facing resource exposure. This product is a website/app DAST
scanner (`runAllChecks()` + the extended tool suite in `scanExecution.ts`,
all black-box HTTP-based); a CSPM (Cloud Security Posture Management)
capability is a structurally different thing — it needs the customer to
grant read access to their actual cloud account (a cross-account IAM role
for AWS, a service principal for Azure, a service account for GCP), not
just a URL to scan.
**Why**: a real, common gap flagged against competitor DAST-plus-cloud
offerings — customers increasingly expect "is our app secure" and "is our
cloud account secure" to be one relationship, not two vendors. Genuinely
new revenue surface, not a check added to an existing scan.
**Impact/effort**: large — this is closer to a new product line than a
scanner addition. Needs, before any scanning code: (1) a decision on which
provider(s) to support first, (2) a secure credential-onboarding flow per
provider (cross-account role ARNs, not raw access keys — the trust/blast-
radius design here is the hard part, not the API calls), (3) a new finding
taxonomy and `checkId` namespace, (4) pricing/plan-gating decisions (this is
plausibly an Agency-tier-only or add-on capability, not something to fold
into existing prices unchanged). Don't scope this as "a few days" — it
needs real design time before code, the same way E-09's Terms of Service
needed legal review before a page could ship.
**Depends on**: a product decision on provider priority and credential
model; likely wants its own follow-up design pass rather than being
estimated further here.
**Category**: money/time (the credential-onboarding trust model and
plan/pricing decisions need real design work before "just write code"
applies) + code (the scanning logic itself, once that's settled).
**Source**: harvested from a competitive "future roadmap" comparison,
2026-09-05 — flagged as genuinely new rather than already-covered, unlike
most of that same document's other claims.

## E-33 — API-spec-aware security testing (OpenAPI/Swagger-driven)

**Status: fixed (2026-09-25).** Shipped as `src/lib/scanners/apiSpec.ts`,
split across the two-tier pipeline exactly as the original spec proposed:
`checkApiSpecPassive()` (base suite, `index.ts`) parses a stored or
auto-discovered OpenAPI 2.x/3.x spec and tests every declared endpoint for
auth bypass, undocumented-method confusion, missing-field schema
validation, and excess data exposure against the documented response
schema; `checkApiSpecInjection()` (extended suite,
`scanExecution.ts`'s `runExtendedTools()`) runs SQLi/XSS probes against
declared parameters, gated the same way the rest of the extended tool
suite is. Customers supply a spec via `POST /api/account/api-spec`
(URL fetch or raw JSON paste, same "customer points us at a resource"
shape as `connect-repo.ts`) and manage it from `ApiSpecConfig.tsx` on the
account page. `checkId` namespace is `api-spec.<check-name>:<method>:<path>`.
Auto-discovery at well-known paths (`/openapi.json`, `/swagger.json`, etc.)
covers targets with no stored spec. Remediation text, compliance mapping,
and fix-difficulty entries added alongside.

**What**: today's API coverage is incidental — ZAP's active scan exercises
whatever endpoints it discovers by crawling, and `sqlmap.ts`/`xsser.ts`/
`commix.ts` test whatever forms/parameters they find the same way. Nothing
reads a customer-supplied OpenAPI/Swagger spec to systematically test every
declared endpoint, parameter, and schema (wrong types, missing auth,
excessive data exposure per response schema, BOLA/IDOR patterns across
declared resource IDs).
**Why**: crawling finds what's linked; a spec-driven approach finds what's
*declared*, including endpoints with no UI path to reach them (the common
case for an API-first or headend-separated product) — a real gap for any
customer whose product is mostly an API.
**Impact/effort**: medium-large — bounded and code-shaped (unlike E-32),
but a genuinely new module: an OpenAPI/Swagger parser, a request-generation
layer per declared parameter/schema (type-appropriate fuzz values, not
generic payloads), and a new `checkId` namespace
(`openapi.<check-name>:<operationId>` or similar) integrated into
`runExtendedTools()`'s existing pattern. Needs a customer-supplied spec URL
or upload — a new account-settings field, similar in shape to
`account/connect-repo.ts`'s existing "customer points us at a resource"
pattern.
**Depends on**: none technically, but worth sequencing after any of the
already-open Sprint 3 items (`docs/SPRINT-PLAN.md`) — this is new scope, not
a fix to something already sold.
**Category**: code. **Source**: harvested from the same competitive
"future roadmap" comparison as E-32, 2026-09-05.

## E-34 — Trivy: base-image CVE scanning + IaC misconfiguration scanning

**Status: fixed (2026-09-05).** The one genuinely new, valuable idea out of
a "tools worth revisiting" list — six of its other seven "must revisit"
tools (ZAP, testssl.sh, Subfinder, and functional equivalents of
SecurityHeaders.io/Retire.js/Waybackurls) were already shipped under
different names; this was the real gap. Specifically fills the exact
installed-package-CVE gap `dockerBaseImage.ts`'s own header comment
declines to fill ("pulling the actual image and inspecting its package
database... what grype/trivy/syft do... out of scope for this module").

Shipped as `src/lib/scanners/trivyScan.ts`, two modes, both gated on a
connected GitHub repo (`repo_connections`) like `secretScan.ts`/
`dependencyManifest.ts`/`dockerBaseImage.ts`:
- **Image mode** (`scanTrivyImage`) — resolves the Dockerfile's
  final-stage base image (reusing `dockerBaseImage.ts`'s own
  `parseDockerfileStages`/`resolveBaseImages` rather than reimplementing
  multi-stage/ARG resolution) and runs a real `trivy image` scan against
  it. Never builds or scans the customer's own application image — only
  the named public base image, which is materially lower-risk than running
  an arbitrary customer's build steps in CI.
- **Config mode** (`scanTrivyConfig`) — a shallow git clone
  (`secretScan.ts`'s clone pattern, minus full history since misconfig
  checks only need the current tree) + a real `trivy config` scan for
  Terraform/Kubernetes/Dockerfile misconfigurations. No existing scanner
  covered IaC at all before this.

New checkId prefixes `trivy-image`/`trivy-config` added to
`src/lib/extendedToolCheckIds.ts` so E-30's retest button correctly refuses
to "retest" a Trivy finding via the on-demand path (which never runs these
tools — retesting one anyway would silently report "fixed" without the
tool that found it ever running again). Compliance mapping
(`compliance.ts`) and dedicated remediation text (`remediationText.ts`,
following the "function not constant, when the fix names something
specific" convention) added. CI install step added to
`.github/workflows/scheduled-scans.yml` (versioned install script, DB
pre-warmed once per job matching nuclei's own template-priming step).

**Deliberately out of scope**: real cloud-account posture scanning (AWS/
Azure/GCP IAM, security groups) — no credential-onboarding flow exists for
that at all, tracked separately as **E-32**; don't conflate the two.
`npx tsc --noEmit`, lint, full `vitest run` (9 new tests on the pure
JSON-parsing functions), and `next build` all verified clean. Not
verified against a real trivy binary in this environment (no Docker/trivy
available in this sandbox) — the JSON schema assumptions should be
re-checked against the pinned version's actual output the first time this
runs for real in `scheduled-scans.yml`, same CONFIDENCE-NOTE caveat as
`xsser.ts`/`commix.ts` carried before their own real-binary verification.
**Depends on**: none. **Category**: code. **Source**: harvested from a
"tools worth revisiting" list, refined into an architecture-respecting
integration after an initial version of the same request proposed a
parallel Azure Functions/Redis pipeline that was declined, 2026-09-05.

## E-50 — Email notifications on scan completion

**What**: when a scheduled or on-demand scan finishes, send the owner an
email summary: overall score, score delta vs previous scan, count of new
critical/high findings, link to the full report. Currently only Slack and
MS Teams webhooks exist (`subscriptions.slack_webhook_url` /
`ms_teams_webhook_url`); email is lower-friction for customers who haven't
set up a webhook.
**Why**: a paying customer who doesn't have Slack/Teams integrated gets zero
proactive notification when their scan finds something — they must remember to
log in and check. Email covers the baseline case. Resend (already a dep for
monthly digest) means no new infra; `executeScan()`'s Phase 2 already has
the right hook point (`sendSlackAlert` pattern, same never-throw contract).
**Impact/effort**: medium impact, low effort — follows `sendSlackAlert`'s
pattern exactly; the only new piece is an email template and a
`sendgrid_from_email` / `notification_email` preference (either the account
email from `auth.users` or a user-settable override in `subscriptions`).
**Depends on**: Resend/SendGrid already wired for monthly digest — same creds.
**Category**: code. **Source**: roadmap 2026-09-14.

## E-51 — Custom notification rules (score threshold + severity filter)

**What**: let owners set a rule so alerts only fire when the security score
drops below a threshold (e.g. "only notify me if score < 80") or when a
new finding of severity Critical/High appears. Applies to Slack, Teams, and
E-50's email channel equally.
**Why**: noisy "score went from 91 to 90" notifications on a healthy site
train owners to ignore alerts — defeating the purpose. A threshold rule
separates signal from noise. `subscriptions` already has a row per owner;
two new columns (`notify_score_threshold INT`, `notify_severity_min TEXT`)
are enough to gate both channels at the call site in `executeScan()`.
**Impact/effort**: low effort (two migration columns + a conditional around
existing `sendSlackAlert` call), meaningful UX uplift.
**Depends on**: E-50 (email channel). **Category**: code.
**Source**: roadmap 2026-09-14.

## E-52 — Score-trend sparklines on the fleet / monitored-targets view

**What**: the E-27 fleet dashboard shows each target's *current* score but
not whether it's improving or degrading. Add a small 7-point sparkline (last
7 completed scans) next to each target's score badge so an Agency customer
can see at a glance which sites are trending in the wrong direction without
opening individual scan reports.
**Why**: the data already exists in `scans` (status = 'completed', ordered
by created_at per monitored_target) — this is a query + rendering change, no
new schema. An Agency account paying for multi-site monitoring specifically
wants "which of my 15 sites needs attention today?" and a flat score is a
worse answer than a score with a direction.
**Impact/effort**: low effort — `ScoreTrend.tsx` already renders a trend line
per-target on the individual scan report; fleet view needs the same logic
with a smaller viewport footprint.
**Depends on**: E-27 (fleet dashboard, already done). **Category**: code.
**Source**: roadmap 2026-09-14.

## E-53 — CSV / JSON export of findings

**What**: a "Download findings" button on the scan report page that exports
the current scan's findings array as CSV (one row per finding: checkId,
severity, title, detail, remediation, compliance refs) or JSON (full
`ScanReport.findings`). For Agency accounts with many targets, also expose
a bulk-export from the fleet view (all targets, most recent scan each).
**Why**: security teams often need to feed findings into a spreadsheet, a
GRC tool, or an existing ticketing-import workflow — the ticket integration
covers Jira/Linear, but most real security processes involve some manual
triage first. A CSV export is the zero-friction bridge for that, and costs
almost nothing to build (the data is already serialized in `scan_results`).
**Impact/effort**: low effort — a client-side `JSON → CSV` transform
on an existing `GET /api/scans/[id]/report` payload; no new API route
needed. Add a `GET /api/v1/scans/{id}/export?format=csv|json` for API
consumers (public-API surface, follows existing v1 conventions).
**Depends on**: none. **Category**: code. **Source**: roadmap 2026-09-14.

## E-54 — PagerDuty / Opsgenie alert integration

**Status: fixed (2026-09-25).** Shipped as `src/lib/oncallAlerts.ts`, wired
into `executeScan()`'s Phase 2 notification block alongside the other
never-throwing post-completion hooks. Reuses `ticket_integrations`
(provider `'pagerduty'`/`'opsgenie'`, extended by migration 028 plus the
dedicated `pagerduty_routing_key`/`opsgenie_api_key` columns added by
`sql/migrations/039_oncall_credential_columns.sql`) — an owner can have both
providers connected at once, and both get paged. Unlike the Jira/Linear
auto-close feature, there is no separate opt-in flag: for these two
providers a row existing in `ticket_integrations` **is** the "active" signal
(same precedent as `slack_webhook_url`), so `auto_close_enabled` stays
irrelevant to this path. `triggerOncallAlerts()` fires
`createPagerDutyIncident()`/`createOpsgenieAlert()` (from
`src/lib/oncallIntegrations.ts`) for every *new* Critical-severity finding
only — narrower than the critical+high email alert, matching this feature's
literal "new Critical severity finding" spec. `resolveOncallAlerts()` closes
the incident/alert for every *fixed* finding regardless of severity, since
resolving a dedup_key/alias that was never triggered is a harmless no-op in
both APIs. Neither function uses a ledger table: both PagerDuty's
`dedup_key` and Opsgenie's `alias` are caller-supplied idempotent
identifiers, so `computeOncallDedupKey(ownerId, targetHost, checkId)`
(a truncated SHA-256, prefixed `hc-`) is simply recomputed at resolve time
rather than stored. Credentials are saved via
`POST /api/account/oncall-integration` (validated against the real
PagerDuty/Opsgenie API before being written, same "verify before saving"
precedent as `ticket-integration.ts`) and managed from the account page's
`OncallIntegrationConfig` panel.

**What**: when a scan finds a new Critical severity finding, open a
PagerDuty incident or Opsgenie alert (owner's choice), using the same
credential-save pattern as `ticket_integrations` (validate key before
saving, one row per owner+provider). Resolves the incident automatically
when the finding is marked fixed on the next scan (follows `ticketAutoClose`'s
opt-in model, `auto_close_enabled` default false).
**Why**: security teams in companies with on-call rotations already route
critical infrastructure alerts through PagerDuty/Opsgenie — this makes
Hebrides Cyber a first-class citizen in that workflow rather than something
that emails a report that sits unread until the weekly review. The
`ticket_links` ledger and `decideTicketAction()` machinery are already
designed for exactly this extension pattern.
**Impact/effort**: medium — PagerDuty Events API v2 and Opsgenie Alert API
are well-documented REST APIs; the `ticketIntegrations.ts` abstraction
already decouples the ledger from the provider. Add provider keys
`"pagerduty"` and `"opsgenie"`, implement `createPagerDutyIncident()` /
`createOpsgenieAlert()` (parallel to `createJiraIssue()`), wire into
`ticketAutoClose.ts`'s existing resolution path.
**Depends on**: `ticket_integrations`/`ticket_links` tables (already shipped).
**Category**: code. **Source**: roadmap 2026-09-14.

## E-55 — CVSS-scored findings

**What**: attach a CVSS v3.1 base score and vector string to findings where
the check is specific enough to support one (TLS grade F, exposed .env,
open critical port, known CVE). Display as a coloured badge alongside the
existing severity label on `FindingCard`; include in CSV export (E-53) and
ticket body (E-54/ticket integrations).
**Why**: security teams doing risk prioritisation work in CVSS. The existing
severity labels (critical/high/medium/low/info) are broad buckets — a CVSS
score with an attack vector component lets a team say "this Critical is
network-exploitable without auth, that Critical requires local access" and
triage accordingly. For CVE-backed findings (`recon.ts`'s Shodan CVEs,
`webapp.ts`'s JS library CVEs) the CVSS score already exists on the CVE
record — it's not being surfaced to the user today.
**Impact/effort**: medium — the CVE-backed findings just need the existing
CVSS field forwarded from the OSV/NVD response into `Finding`. For
first-party findings (TLS/headers/exposure) a manual mapping table in
`remediationText.ts` or a new `cvss.ts` module is needed; only a subset of
checks have specific enough findings to warrant one.
**Depends on**: none. **Category**: code. **Source**: roadmap 2026-09-14.

## E-56 — Full migration automation (supabase db push in CI)

**Status: fixed (2026-09-25).** `.github/workflows/deploy.yml`'s
`migration-check` job now runs `supabase db push --db-url "$DATABASE_URL"`
before the schema-verification step, gated on the `DATABASE_URL` secret
being set (`if: ${{ env.DATABASE_URL != '' }}`) — falls back to
verify-only mode (E-49's original behaviour) when that secret isn't
present yet, so adoption is incremental rather than a hard cutover. A
failed `db push` degrades to a `::warning::` annotation plus the
verify-only fallback rather than hard-failing the job, since a partial
apply is recoverable but a silent skip of the verification step is not.
Requires the `DATABASE_URL` GitHub secret (the direct Postgres connection
string from Supabase's Connect page) — owner action, see the workflow
file's header comment for the full secrets list.

**What**: upgrade `deploy.yml`'s E-49 migration-check job from "detect
missing columns and fail the build" to "apply pending migrations
automatically before deploy using `supabase db push`." This turns the
current manual Supabase SQL-editor step into a zero-touch CI step.
**Why**: the 2026-09-13 incident (migrations 019-026 never applied to
production) happened because the apply step didn't exist anywhere in the
pipeline. E-49 prevents the next deploy from crashing on missing columns,
but still requires a human to apply the fix. E-56 removes that human step
entirely.
**How**: `supabase` CLI (`npx supabase db push --db-url $DATABASE_URL`)
applies `sql/migrations/` in filename order, idempotently (Supabase tracks
applied migrations in a `supabase_migrations` schema table). Needs a
`DATABASE_URL` secret in GitHub (the direct Postgres connection string from
Supabase's "Connect" page, not the PostgREST URL). The migration-check step
then becomes a post-apply verification rather than a pre-deploy gate.
**Depends on**: DATABASE_URL secret added to GitHub repo settings (manual).
**Category**: code + money/time (one manual secret to add).
**Source**: roadmap / incident post-mortem 2026-09-14.

## E-57 — Health check curl in post-deploy step (completes BETA-2)

**Status: fixed (2026-09-25).** `.github/workflows/deploy.yml`'s `deploy`
job now has a "Post-deploy health check (E-57)" step that waits 45s for
Azure Functions warm-up then curls `${SITE_URL}/api/health`, gated on the
`SITE_URL` secret being set. A non-200 response emits a `::warning::`
annotation rather than failing the workflow outright (the deploy already
succeeded at that point — a degraded health check is worth surfacing, not
worth reverting a deploy over automatically). Requires the `SITE_URL`
GitHub secret (the live `hebridescyber.co.uk` URL) — owner action.

**What**: `docs/ROADMAP.md` BETA-2 says "`GET /api/health` returns 200 with
Supabase/Stripe/queue-depth sub-checks" and lists "curl in CI immediately
post-deploy" as the verify method — that curl has never been added. Add a
post-deploy step to `deploy.yml`'s `deploy` job that waits ~30s for the new
Functions to warm up, then curls `$SITE_URL/api/health` and fails the
workflow if the response isn't 200. Needs `SITE_URL` (the live
`hebridescyber.co.uk` URL) added as a GitHub secret.
**Why**: without this, a deploy that breaks the health endpoint goes
unnoticed until a customer reports it. The endpoint was built for exactly
this purpose (E-04, 2026-09-04) but is never actually exercised in CI.
**Impact/effort**: trivial code change (3 lines in deploy.yml) plus one
GitHub secret.
**Depends on**: E-04 (already done). **Category**: code. **Source**: audit /
BETA-2 verify-method gap, 2026-09-14.

## E-58 — CISA KEV + FIRST EPSS threat intel on CVE findings

**Status: done (2026-09-27).** `src/lib/scanners/threatIntel.ts`, a final
pass after CVSS enrichment in `executeScan()`. It adds "Actively exploited"
and ransomware badges plus EPSS likelihood, and orders exploited findings
first within a severity. The same data appears as `threat_intel` in
`GET /api/v1/scans/{id}` and the webhook, and as `known_exploited`/`epss`
CSV columns. Severity is never changed.
**Why**: NCSC's EASM buyer's guide asks how findings are ranked by
likelihood. CVSS alone ranks by potential impact.
**Category**: code. **Source**: competitive refresh 2026-09-27
(`docs/COMPETITIVE-ANALYSIS.md` §12).

## E-59 — Dangling DNS / subdomain takeover detection

**Status: done (2026-09-27).** `src/lib/scanners/takeover.ts`, base suite.
It checks up to 60 hosts (the site plus CT-log subdomains) against 15
provider patterns, and reports only with NXDOMAIN or the provider's own
unclaimed-resource page as evidence.
**Why**: listed under "DNS security" in NCSC's EASM guide. Previously it
only ran inside nuclei's `takeover` tag on scheduled full scans.
**Category**: code. **Source**: competitive refresh 2026-09-27.

## E-60 — Domain registration expiry + transfer lock (RDAP)

**Status: done (2026-09-27).** `src/lib/scanners/domainRegistration.ts`.
Findings: `domain.expiring` (medium at ≤30 days, high at ≤14),
`domain.expired`, and `domain.transfer-lock-missing` (gTLDs only).
**Why**: an expired domain takes down the website and email together.
Beagle offers this on its free tier.
**Category**: code. **Source**: competitive refresh 2026-09-27.

## E-61 — NCSC Web Check / Mail Check replacement landing page

**Status: done (2026-10-01).** `src/app/web-check-alternative/page.tsx`, in the sitemap.
**What**: a landing page for UK organisations that used NCSC Web Check or
Mail Check (retired 31 March 2026). It maps what those services and NCSC's
EASM buyer's guide cover to what we check, including the "Partial" rows
in `docs/COMPETITIVE-ANALYSIS.md` §12 stated honestly.
**Why**: a whole segment lost a free service, and NCSC now tells them to
buy commercial EASM. It's time-sensitive.
**Impact/effort**: high / low. **Category**: marketing.
**Source**: competitive refresh 2026-09-27.

## E-62 — Third-party script inventory and change alerts

**Status: done (2026-10-01).** `src/lib/scanners/scriptInventory.ts`, base
suite, with runtime capture in `playwright.ts`. The open question below was
settled as an inventory with acknowledgement inside the finding model: one
persistent `script-inventory.unreviewed:<origin>` finding per origin, open
while the page loads from it, closed by accepting it with a justification
(E-64's triage) or by removing the script. New/Fixed diffing is the change
signal; it sees origins appear or disappear, not changes inside a script.
**What**: record every external script source per scanned page, and flag
new ones since the previous scan.
**Why**: PCI DSS v4.0.1 6.4.3 (payment-page script inventory) and 11.6.1
(change and tamper detection), plus NCSC's "external dependencies"
category. It's also a common Magecart-style card-skimming vector for
online shops.
**Open question**: a "new script since last scan" finding disappears on
the next scan. Decide whether that should count as "fixed" (it would
auto-close tickets and SLA clocks) or live outside the finding model, for
example as an inventory with acknowledgement.
**Impact/effort**: high / medium. **Category**: code.
**Source**: competitive refresh 2026-09-27.

## E-63 — Continuous EASM discovery (wire `easmDiscovery.ts`)

**Status: done, 2026-10-12.** `runEasmDiscovery` now runs in `executeScan`
right after `syncAssetInventory` — crt.sh + HTTP probing on every scan, DNS
brute-force only once the scan has cleared the Tier A offensive profile's
gate. New hosts land in `asset_inventory` and are picked up for free by
`attackSurfaceMonitor.ts`'s existing "new hostname" alert. See CLAUDE.md
"EASM discovery".
**Still open**: it runs per scan, not from an independent schedule, so a
monitored domain between scans gets no EASM-only discovery pass; feeding
newly discovered hosts into `takeover.ts` specifically (beyond the generic
asset inventory) was not done.
**Source**: importer audit 2026-09-27.

## E-64 — Finding workflow state (accept risk / false positive / snooze)

**Status: done (2026-10-01).** `finding_triage` (migration 046), one row per
(owner, host, checkId); `src/lib/findingTriage.ts` decides what each state
does; `GET/PUT/DELETE /api/findings/triage` (session or API key, bulk up to
200, audited); "Mark as…" and a collapsed "Triaged" group with Undo on the
scan report. Triaged findings leave the open counts, SLA tracking and alerts,
new-finding alerts and the GitHub Action's gate. One deliberate change from
the description below: only false positives leave the score — an accepted or
snoozed risk still exists, so it still counts. Triage doesn't extend an SLA
deadline: a finding comes back from an expired snooze against its original
first-seen date.
**What**: per-finding state with a reason and optional expiry, keyed like
`finding_lifecycle` (owner, host, checkId). Accepted or false-positive
findings drop out of the score, alerts and SLA clocks, and come back when
the acceptance expires.
**Why**: expected by NCSC's checklist ("workflow features") and offered by
Intruder and HostedScan. It's also the missing half of SLA reporting.
**Impact/effort**: high / medium. **Category**: code.
**Source**: competitive refresh 2026-09-27.

## E-65 — Lookalike-domain monitoring

**Status: open.**
**What**: generate typo, omission, transposition, homoglyph and TLD-swap
permutations of the customer's domain, and report registered ones,
highlighting those with MX records. Passive DNS only, capped at a few
hundred lookups.
**Why**: phishing that impersonates the business is the most common attack
UK SMEs report.
**Impact/effort**: medium / medium. **Category**: code.
**Source**: competitive refresh 2026-09-27.

## E-66 — DMARC aggregate-report processing

**Status: open.**
**What**: accept DMARC `rua` reports at a mailbox we operate, parse the XML
and show which senders pass or fail for the domain. This is the part of
NCSC Mail Check that `dns.ts` doesn't replace.
**Impact/effort**: medium / high (needs inbound mail infrastructure).
**Category**: code + infrastructure. **Source**: competitive refresh 2026-09-27.

## E-68 — Emerging-threat alerts (newly exploited CVEs vs. each site's latest scan)

**Status: done (2026-10-01).** Every 6 hours (`emerging-threats.yml` →
`src/scripts/check-emerging-threats.ts`), CVEs CISA added to its KEV catalog
in the last 3 days are matched against the technology and version each paid
customer's latest scan per site saw (last 30 days), using NVD CPE
configurations and OSV.dev npm ranges. `affected` needs a detected version
inside a vulnerable range; product-seen-but-version-unknown, partial
versions, distro packages and platform-conditional ranges are
`possibly_affected` with softer wording; name-only matches never alert.
Ledger `emerging_threat_alerts` (migration 045) stops repeats; email for
every paid plan, Slack/Teams for Pro/Agency; dashboard panel and
`GET /api/emerging-threats`.
**Why**: Intruder sells this as "emerging threat scans". A newly exploited
CVE otherwise waits for the next scheduled scan (up to a week on Basic) and
even then only surfaces if a check covers it.
**Follow-ups**: WordPress plugins (needs a per-plugin CPE map or WPScan);
re-alerting when a `possibly_affected` match later becomes `affected`.
**Category**: code. **Source**: competitive (Intruder), 2026-10-01.
(E-67 is left for the untested-modules item `docs/SPRINT-PLAN.md` already
refers to.)

## E-67 — Lockfile-based, transitive dependency scanning (Snyk Open Source parity)

**Status: done (2026-10-05), PR #2.**
**What**: `dependencyManifest.ts` read only manifests' declared ranges at
the repo root and queried the lowest version each allowed, so it never saw
transitive dependencies (where most real vulnerabilities are) and could
flag versions that weren't installed. It now prefers a lockfile per
ecosystem — package-lock.json (v1–v3)/npm-shrinkwrap.json, pnpm-lock.yaml
(v5/v6/v9), yarn.lock (v1 and berry), poetry.lock, Pipfile.lock,
composer.lock, go.sum (+go.mod), gradle.lockfile, Gemfile.lock, Cargo.lock,
packages.lock.json — and keeps the manifest-range check as a disclosed
fallback. Findings say lockfile-exact vs manifest-range, direct vs
transitive, "introduced via a > b > c" and the fixed version; checkIds are
unchanged (new slugs ruby/cargo/nuget). OSV.dev is queried with
`/v1/querybatch` (pagination followed) plus `/v1/vulns/{id}`; a failed batch
is an `error` result. Two `osv.ts` bugs fixed on the way: `next_page_token`
was ignored (long advisory lists were cut off), and only SEMVER ranges were
read, so PyPI/Maven/RubyGems/NuGet/Packagist fix versions were lost.
The scan stores a bounded inventory of every package; the CycloneDX SBOM
is built from it (correct purls incl. `pkg:maven/group/artifact`, scope,
dependency graph, linked vulnerabilities) instead of parsing finding
titles, which remains only for scans stored before this change.
**Why**: the core of what Snyk Open Source sells; manifest ranges alone
were both incomplete and imprecise.
**Parsers are pure** (`dependencyLockfiles.ts`, `parseLockfile()`), for a
follow-up that diffs base vs head lockfiles on pull requests.
**Known limits**: root-directory files only (no monorepo sub-packages);
one lockfile per ecosystem; Maven has no lockfile unless Gradle locking is
on; Pipfile.lock, go.sum and gradle.lockfile record no graph; 2000-package
cap per repo.
**Category**: code. **Source**: competitive gap (Snyk comparison).

## E-69 — Static code analysis (SAST) of the connected repository

**Status: done (first slice).**
**What**: `src/worker/tools/sast.ts` shallow-clones the connected repo
(shared `src/lib/repoClone.ts`) and runs the Opengrep engine with our own
rule pack, `sast-rules/` — 34 rules, taint mode where the engine supports
it, for JavaScript/TypeScript, Python and PHP: SQL built from request input,
eval/Function/vm, shell commands, unsafe deserialisation, PHP include,
open redirects, TLS verification off, Flask/Django/Laravel debug on, JWT
verification off. Findings are `sast.<rule-id>:<hash of path|line|rule>`,
capped at 50 (most severe first), with CWE-based compliance refs, fix
difficulty and per-language remediation. Scheduled scans only (full and
osint profiles).
**Why not Semgrep's rules**: the Semgrep Rules License v1.0 forbids use in a
competing commercial SaaS, and opengrep-rules is archived "for research,
testing & benchmarking" — so the rules are written from scratch here and the
engine (LGPL-2.1) runs as a separate binary.
**Follow-ups**: more frameworks (Koa/Fastify sources, FastAPI parameters),
Java/Go/Ruby rule sets, cross-file taint (`--taint-intrafile`) once its
false-positive rate is measured on real repos, and a per-repo
false-positive feedback loop (see E-64).
**Category**: code. **Source**: SAST build, 2026-10-01.

## E-70 — Site crawler, with page-level checks on every crawled page

**Status: open — next up.** Full brief in `docs/NEXT-STEPS.md` item 1.
**What**: bounded, read-only, robots-aware crawl (~50 pages, depth 3, same
origin) feeding headers, cookies, mixed content, SRI, script inventory and
error disclosure per page, aggregated so one site-wide gap is one finding.
**Why**: almost every page-level check sees only the homepage today.
**Impact/effort**: very high / medium-high. **Category**: code.
**Source**: industry-grade gap analysis, 2026-10-05.

## E-71 — Pull-request dependency checks

**Status: open.** Brief in `docs/NEXT-STEPS.md` item 2.
**What**: `POST /api/v1/dependency-diff` plus `mode: dependencies` in the
GitHub Action, reusing E-67's lockfile parsers to report only newly
introduced vulnerable packages on a PR.
**Impact/effort**: high / medium. **Category**: code.
**Source**: competitor analysis (Snyk), 2026-10-01.

## E-72 — Fix sqlmap result reading; verify xsser output (E-18)

**Status: open.** Brief in `docs/NEXT-STEPS.md` item 3.
**What**: `sqlmap.ts` reads a log path sqlmap never writes, so it can never
report a finding; `xsser.ts`'s parser has never been checked against the
real binary. Fix both against real captured output.
**Impact/effort**: high / low-medium. **Category**: code (bug).
**Source**: scanner test-hardening pass, 2026-10-01.

## E-73 — Scanner accuracy benchmark suite

**Status: open.** Brief in `docs/NEXT-STEPS.md` item 4.
**What**: a corpus of known-vulnerable and known-clean targets with
must-find / must-not-find checkIds, run in CI, reporting precision and
recall per module and failing on regressions.
**Impact/effort**: high / medium. **Category**: testing.
**Source**: industry-grade gap analysis, 2026-10-05.

## E-74 — Cross-site findings view with bulk triage

**Status: open.** Brief in `docs/NEXT-STEPS.md` item 5.
**What**: `/dashboard/findings` — every open finding across all sites,
filterable and groupable, with bulk triage (E-64's bulk API) and export.
**Impact/effort**: high / medium. **Category**: code (UI).
**Source**: industry-grade gap analysis, 2026-10-05.

## E-75 — Request/response evidence on findings

**Status: open.** Brief in `docs/LAUNCH-PRIORITY.md` item 3.
**What**: store a bounded, redacted request and response for each finding
that came from an HTTP probe, and show it in the finding card, PDF and CSV.
No credential or session value may be stored; deleted with the scan.
**Why**: proof drives trust and fixes; enterprise tools show it.
**Impact/effort**: high / medium. **Category**: code.
**Source**: launch-readiness review, 2026-10-18.

## E-76 — Single sign-on (SAML) for the top plan

**Status: open — only if a customer asks.** Brief in `docs/LAUNCH-PRIORITY.md` item 4.
**What**: SAML login for one identity provider mapped to the existing team
roles. The earlier SSO/RBAC/SCIM modules were deleted on 2026-10-13 (no
importers); migrations 034-036 remain.
**Impact/effort**: medium / medium-high. **Category**: code.
**Source**: launch-readiness review, 2026-10-18.

## E-77 — CMS and client-side library depth

**Status: in progress.** One PR per item, each with tests and a benchmark case.
**What**:
1. ~~Passive WordPress plugin discovery~~ done (PR #60): slugs come from the
   page's own `/wp-content/plugins/<slug>/` references, not only a fixed list.
2. ~~WordPress theme detection and theme vulnerabilities~~ done (PR #61):
   `style.css` header version, WPScan `/themes/{slug}`.
3. ~~retire.js data for JS libraries~~ done: `scanners/retireJs.ts` replaces
   the 7 hand-kept `LIB_PATTERNS` with the retire.js repository (~76
   libraries, published vulnerable ranges and severities), fetched at scan
   time from a pinned commit. Detection uses retire.js's own URL, filename,
   file-banner and SHA-1 extractors over up to 10 script bodies. If the data
   can't be loaded the legacy patterns still run. Apache-2.0, attributed in
   `docs/THIRD-PARTY-NOTICES.md`.
4. ~~badsecrets~~ done: `src/worker/tools/badsecrets.ts`, known/default
   framework keys behind cookies, ViewState and JWTs (passive mode; AGPL-3.0,
   run unmodified as a separate program per the owner's decision 2026-10-19).
5. katana crawl seeding (MIT, pinned + SHA-256).
6. More CMS fingerprints: PrestaShop, OpenCart, TYPO3, Umbraco, Craft,
   Moodle; Joomla component and Drupal module versions.
**Impact/effort**: high / medium. **Category**: code (detection).
**Source**: CMS/tooling gap review, 2026-10-18.
