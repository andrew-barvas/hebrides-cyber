# Sprint Plan — next 3 sprints

**Owns**: near-term execution ordering — what to actually work on next, in
what order, and why that order. **Does not own**: what each item *is*
(`docs/ENHANCEMENTS.md`, referenced by `E-nn` ID, never restated here) or
what "done" looks like at a stage level (`docs/ROADMAP.md`'s POC/Beta/Live
criteria — this plan is how you get there, not a replacement for it). If
this file and `ROADMAP.md` ever disagree on priority, `ROADMAP.md`'s
business-readiness blocks win — a sprint doesn't get to skip a legal/billing
blocker to ship a feature.

Written for continued solo/small-team capacity (as everything else in this
repo has been) — 2-week sprints, one person's realistic throughput per
sprint, not a multi-engineer team's. If more people join, sprints compress;
the ordering and dependencies below don't change.

**As of 2026-08-28**: `E-01` (Basic/Pro scheduled-scan access) and `E-09`/
`E-23` (Terms of Service + footer links) already shipped since the backlog
was written — removed from the plan below rather than left in as
already-done padding. Re-check `git log` against `docs/ENHANCEMENTS.md`
before starting Sprint 1 in case more has landed since this was written —
this file will drift the same way `ROADMAP.md`'s own status columns do.

---

## Sprint 1 — Revenue integrity, plan enforcement, signup attention

**Theme**: nothing in Sprint 2/3 matters commercially if paid signup is
broken or the Basic/Pro/Agency ladder doesn't actually gate anything. This
sprint fixes what's already sold before building what's new.

**Status legend**: ✅ done · 🔄 in progress · ⛔ blocked (not a dev task, or
waiting on someone else) · ⬜ not started. This column is a live todo list —
update it as work lands, don't let it drift from `git log`.

| Priority | ID | What | Status | Why this sprint |
|---|---|---|---|---|
| 1 | **E-07** | Configure live Stripe Price IDs | ⛔ blocked — needs owner's Stripe Dashboard access | Blocks the entire paid funnel end to end — highest-priority item in the whole backlog. **Not a dev task** — needs the account owner's Stripe Dashboard access (Claude Code's sandbox is authenticated to a different Stripe account and can't do this). Do this on day 1, in parallel with everything else below. |
| 2 | **E-02** | Server-side plan enforcement audit (teams, webhooks, keys, shares, AI fix, target-auth) | 🔄 partially done (2026-08-28) — the 3 advertised-but-unenforced gaps fixed (target-auth, team create/invite, connect-repo); AI-fix/keys/webhooks-limits/tickets/shares left open pending an owner decision, see E-02's own entry | 14 capabilities currently have zero plan gate — the Basic/Pro/Agency ladder exists in Stripe and marketing copy but mostly not in the product. `docs/ROADMAP.md` BETA-4's exit criterion depends on this directly. |
| 3 | **E-16** | In-app first-run onboarding checklist (verify domain → run first scan → read report → set an alert channel) | ✅ done (2026-08-28) — not yet manually verified in a browser against a real staging account | The explicit "user signup attention" ask — naturally sequenced after E-01 (already done) since there's no point checklisting "add a target" for a plan that couldn't before. |
| 4 | **E-05** | Rate-limit the public contact form | ✅ done (2026-08-28) | Only fully-open unauthenticated write path in the app; `checkRateLimit()` already exists, this is applying an existing pattern. Cheap, do it this sprint rather than let it sit. |
| 5 | **E-08** | Consolidate admin auth checks onto `requireAdmin()` | ✅ done (2026-08-28) | Two hand-rolled, differently-implemented admin checks are how the `is_admin` RLS-class of bug recurs. Small, mechanical, worth doing before Sprint 2 touches admin-adjacent dashboard code. |
| 6 | **E-19** | Delete the stale duplicate `on-demand-scan.yml` | ✅ already done (predates this sprint plan) | Trivial, zero-risk cleanup; bundle with the above rather than schedule its own slot. |

**Since this plan was written, also shipped (not originally in Sprint 1,
noting here so the todo list stays honest about what's actually left)**:
E-29 (Go/Maven dependency-manifest coverage — raised mid-sprint from a
competitive-gap question, not originally scoped, done 2026-08-28).

**Sprint 1 exit check**: `docs/FUNCTIONALITY-MATRIX.md` §6's "❌ No gate at
all" count drops from 14 toward 0 (won't hit 0 in one sprint — re-run the
audit and re-generate the matrix at sprint end, don't estimate it), Stripe
Checkout completes end-to-end for all three tiers against real Stripe
(`docs/ROADMAP.md` POC-3), and a new signup sees the onboarding checklist.

---

## Sprint 2 — Dashboards & reporting

**Theme**: the explicit "dashboards, reporting" ask. Both items below reuse
data the product already computes (`scan_results`, `compliance.ts`'s
per-scan mapping) — this is a dashboard/query-shape sprint, not new scanning
work.

**Status legend**: same as Sprint 1's.

| Priority | ID | What | Status | Why this sprint |
|---|---|---|---|---|
| 1 | **E-27** | Multi-target "fleet" rollup dashboard | ✅ done (2026-09-04) — not yet manually verified in a browser against a real staging Agency account | The Security Overview currently shows only the most-recently-completed scan across *all* monitored targets — an Agency account with up to 15 targets has no fleet view. Direct product gap against the "Agency = multi-site monitoring" pricing differentiator, and the highest-value of the two new dashboard items since it's the only way multi-site customers can actually use what they're paying for. |
| 2 | **E-28** | Findings-by-category and compliance-coverage trend reporting | ✅ done (2026-09-04) — not yet manually verified in a browser | Extends `ScoreTrend.tsx` beyond a single score number to "which categories are improving," using data `compliance.ts` already computes but never charts. Sequenced after E-27 since both need the same per-target/all-targets selector — build that selector once, not twice. |
| 3 | **E-03** | Observability: error tracking (Sentry / App Insights) | 🔄 code done (2026-09-04) — ⛔ not actually capturing anything until you create a Sentry account and set `SENTRY_DSN` | `docs/ROADMAP.md`'s own stated exception — this is allowed to land before its nominal Beta slot because Sprint 2 is adding real new dashboard surface area, and right now a failure in it is invisible. Bring forward, don't skip. |
| 4 | **E-04** | Health check endpoint | ✅ done (2026-09-04) | Small, pairs directly with E-03 (an alert needs something to alert *from*), same rationale for pulling it forward. |

**Sprint 2 is now fully complete** as far as code goes — E-03's activation
is the one item still needing you, same shape as E-07's Stripe blocker in
Sprint 1: the code ships safely either way, but the actual capability
needs an external account only you can create.

**Since this plan was written, also shipped (not originally in Sprint 2,
noting here so the todo list stays honest)**: technical SEO infrastructure
(sitemap.xml, robots.txt, metadataBase, LocalBusiness structured data) and
a stale-domain cleanup across 16 files (never-registered `hebridescyber.com`
→ the real, live `hebridescyber.co.uk`) — raised from the domain-wiring and
"improve our SEO" conversation, not originally scoped. E-30 (per-finding
retest button) logged as a new backlog item, not yet built.

**Sprint 2 exit check**: an Agency test account with 3+ monitored targets
can see all of them (score, last-scanned, open-findings count) in one view
without hunting through single-scan history; a category/compliance trend
chart renders for a target with 2+ historical scans; a deliberately-thrown
canary error in staging shows up in the error tracker within a minute.

---

## Sprint 3 — Hardening & the rest of the plan-enforcement/legal tail

**Theme**: the remaining items that block `docs/ROADMAP.md`'s Beta/Live
criteria but aren't urgent enough to have displaced Sprints 1-2. Lower
priority within this sprint means "do these if time allows," not "skip."

| Priority | ID | What | Status | Why here |
|---|---|---|---|---|
| 1 | **E-10** | Data retention: implement the cleanup job, reconcile the two promises | ✅ done (2026-09-05) | Blocks `ROADMAP.md` BETA-3 (customer deletion requests) — a real, live legal gap, not a nice-to-have. |
| 2 | **E-06** | Runtime schema validation at API boundaries (zod) | ✅ done (2026-09-13) | Credibility risk for a security product specifically to ship without one; all 21 write routes now validated. |
| 3 | **E-11** | Fix `send-monthly-digest.ts`'s N+1 query pattern | ✅ done (2026-09-05) | Same failure class that already broke daily-blog/weekly-newsletter once. |
| 4 | **E-17** | Paginate/cap the remaining unbounded admin queries | ✅ done (2026-09-05) | Blocks `ROADMAP.md` LIVE-3. |
| 5 | **E-12** | Rate-limit the remaining expensive per-click routes | ✅ done (2026-09-05) | Rounds out E-05's work from Sprint 1. |
| 6 | **E-18** | Verify `xsser.ts`/`commix.ts` against a real vulnerable target | 🔄 partial (2026-09-05) | commix verified; xsser still needs a real binary test. |

**Sprint 3 is now fully complete** (all items either done or as far as they
can go without a real xsser binary).

**Originally "not in these 3 sprints"** — several have since shipped in
Sprint 4: E-14 (done), E-15 (done), E-20 (done), E-22 (done), E-25 (done).
Still deferred: E-13 (Supabase backup/restore documentation), E-21
(httpOnly-cookie auth migration — explicitly large), E-24 (harvested item),
E-26 (Terraform scaffold).

**Sprint 3 exit check**: re-run `docs/FUNCTIONALITY-MATRIX.md`'s audit and
confirm the ❌-gate count from Sprint 1 has actually reached 0; a seeded test
account's deletion request removes every row keyed to it within the stated
window; `docs/ROADMAP.md`'s Beta business-readiness + product criteria are
either green or have a named blocker that isn't on this plan's own list.

---

## Sprint 4 — Production stability + feature expansion (2026-09-11 – 2026-09-13)

**Theme**: Ship the feature expansion (CMS/OSINT/WAF/API scanning tools,
Partner Portal, asset inventory, critical path analysis, Fix Wizard, diff
view, scan replay, team roles, scan profiles), fix a live production
incident (unapplied migrations), and close hardening items (E-14, E-22,
E-25, E-06 zod backfill).

| Priority | ID | What | Status |
|---|---|---|---|
| 0 | **E-49** | Apply migrations 019-026 to production Supabase | ⛔ blocked — needs owner to paste the combined script into Supabase SQL editor (script prepared) |
| 0a | — | Fix tsc error in `replay.test.ts` (CI blocker) | ✅ done (2026-09-13) |
| 1 | **E-35–E-48** | Feature expansion: 21+ extended tools, Partner Portal, asset inventory, critical paths, Fix Wizard, diff view, replay, team roles, scan profiles, subscriptions RLS fix, COEP header | ✅ done (2026-09-11, pushed as 11 commits) |
| 2 | **E-14** | ZAP_API_KEY `"changeme"` → `not_configured` | ✅ done (2026-09-13) |
| 3 | **E-22** | security.txt RFC 9116 `Expires` field | ✅ done (2026-09-13) |
| 4 | **E-25** | `Promise.allSettled` in `runAllChecks()` | ✅ done (2026-09-13) |
| 5 | **E-06** | Zod validation backfill for ~20 write routes | ✅ done (2026-09-13) |
| 6 | — | Regenerate stale docs (ENHANCEMENTS, FUNCTIONALITY-MATRIX, ROADMAP, SPRINT-PLAN) | ✅ done (2026-09-13) |
| 7 | — | Migration 026: `monitored_targets` UPDATE RLS policy | ✅ done (2026-09-13, file created; needs application to production — see E-49) |
| 8 | **E-02** | Document remaining ungated capabilities as "intentionally open" | ✅ done (2026-09-13, in FUNCTIONALITY-MATRIX.md) |

| 9 | **E-15** | "Generate fix PR" button in scan detail page | ✅ done (2026-09-13) |
| 10 | **E-20** | `pull_request` trigger + split check/deploy jobs in `deploy.yml` | ✅ done (2026-09-13) |
| 11 | **E-49** | Migration schema check in CI pipeline | ✅ done (2026-09-13) |

**Sprint 4 exit check**: `npx tsc --noEmit` clean, CI passes, all four docs
regenerated, E-14/E-22/E-25 closed, E-06 zod backfill applied to all write
routes, E-15/E-20/E-49 shipped. **Blocked until E-49 (manual)**: production
incident is resolved only when migrations 019-026 are applied to the live
Supabase database — the script is prepared at `sql/migrations/` (idempotent,
safe to re-run), but needs manual application via the Supabase SQL editor.
The CI migration check (E-49 automation) will now block deploys if
migrations are missing.

---

---

## Sprint 5 — Production closure + pipeline hardening (2026-09-14 – 2026-09-28)

**Theme**: close the live incident completely, remove the manual migration
step so it can never recur, and give the pipeline a real safety net for
future deploys.

| Priority | ID | What | Status | Why |
|---|---|---|---|---|
| 0 | **E-49** (manual) | Apply migrations 019–026 to production Supabase | ⛔ blocked — owner pastes the prepared script in the Supabase SQL Editor | Incident is not resolved until this is done; admin panel, monitored-targets UI, and asset-inventory views all fail until then |
| 1 | **E-56** | Full migration automation — `supabase db push` in CI | ⬜ | Turns the manual apply step into a zero-touch CI operation; needs `DATABASE_URL` added as a GitHub secret (owner action) then ~10 lines in deploy.yml |
| 2 | — | Free staging environment | ⬜ | Azure SWA preview deployments are automatic on PR; needs a second free-tier Supabase project (owner action) and `STAGING_SUPABASE_*` secrets wired to `deploy.yml`'s `pull_request` build |
| 3 | — | GitHub branch-protection rules | ⛔ manual | Completes E-20's full intent — requires the `check` job to pass before any PR can merge; GitHub Settings > Branches (owner action, not code) |
| 4 | **E-57** | Health check curl in post-deploy step | ⬜ | 3-line deploy.yml change; makes BETA-2's verify-method actually green |
| 5 | **E-03** | Sentry account + `SENTRY_DSN` in Azure app settings | ⛔ manual | Code shipped 2026-09-04; BETA-1 stays red until a real DSN is set (owner action — free Sentry Developer plan, 5k errors/month) |

**Owner-action items (not code)**: 0 (Supabase SQL Editor), 3 (GitHub
settings), 5 (Sentry account). All three can be done in under 30 minutes
combined and unlock everything else in this sprint.

**Sprint 5 exit check**: admin panel loads without error, CI applies
migrations automatically on the next push, PR preview environments exist,
branch protection blocks merges without a passing `check`, health endpoint
curled post-deploy, first real Sentry error appears within 60s of a
triggered canary.

---

## Sprint 6 — Revenue unblock + auth security (2026-09-29 – 2026-10-12)

**Theme**: make paying work end-to-end and fix the one structural auth
security issue (localStorage JWT) before it becomes a liability.

| Priority | ID | What | Status | Why |
|---|---|---|---|---|
| 1 | **E-07** | Configure live Stripe Price IDs | ⛔ blocked on owner's Stripe Dashboard access | Still the highest-priority item in the whole backlog — paid signup is completely broken without real Price IDs. Not a dev task |
| 2 | **E-21** | Migrate auth off localStorage to httpOnly cookies | ⬜ | Supabase JWT currently stored in localStorage → readable by any XSS. Large but high-priority for a security product; see E-21's own entry for the migration strategy |
| 3 | **E-13** | Document + actually test Supabase backup/restore | ⬜ | LIVE-4 blocker; restoring from a backup has never actually been exercised against a real project |
| 4 | — | POC verification with a real demo account | ⬜ manual | Run POC-1 through POC-4 against production (`npm run seed:users`, then trigger a scan, follow the flow the roadmap describes) — marks those rows green rather than just "probably correct" |

**Sprint 6 exit check**: Stripe Checkout completes end-to-end for all three
tiers against real Stripe; auth tokens are in httpOnly cookies (no
localStorage JWT visible to JS); a Supabase restore has been demonstrated
against a scratch project; POC-1/POC-4 are green on ROADMAP.md.

---

## Sprint 7 — User-facing feature expansion (2026-10-13 – 2026-10-26)

**Theme**: richer notifications (close the gap between "webhook users" and
everyone else), better UX, and the first export capability.

| Priority | ID | What | Status | Why |
|---|---|---|---|---|
| 1 | **E-50** | Email notifications on scan completion | ⬜ | Currently zero proactive contact for customers without Slack/Teams. Resend is already wired; this follows `sendSlackAlert`'s pattern exactly |
| 2 | **E-51** | Custom notification rules (score threshold, severity filter) | ⬜ | Without a threshold, every nightly "score went from 91 to 90" fires an alert — trains owners to ignore notifications. Two migration columns + a conditional |
| 3 | **E-30** | Per-finding "retest" button | ⬜ | Already logged and scoped — a targeted re-run of one check module rather than a full rescan |
| 4 | **E-52** | Score-trend sparklines on the fleet / monitored-targets view | ⬜ | E-27 fleet view shows current score only; sparkline needs 7 rows from `scans` per target — the data is already there |
| 5 | **E-53** | CSV / JSON findings export | ⬜ | Low effort (client-side transform), meaningful for customers doing manual triage or feeding into a GRC tool |

**Sprint 7 exit check**: a customer with no Slack/Teams integration receives
a scan-completion email; threshold rules suppress low-delta score-change
noise; per-finding retest triggers a real re-run in on-demand workflow; fleet
view shows trend direction per target; "Download findings" button produces a
valid CSV.

---

## Sprint 8 — Advanced scanning + integrations (2026-10-27 – 2026-11-09)

**Theme**: expand the scanner surface to cloud/API scope and connect to the
on-call tooling security teams already use.

| Priority | ID | What | Status | Why |
|---|---|---|---|---|
| 1 | **E-32** | Cloud posture scanning (AWS/Azure/GCP) | ⬜ | Credential-onboarding design is the hard part (see E-32's own entry) — the scanning logic is straightforward once that's settled. Real competitive differentiator vs. web-only scanners |
| 2 | **E-33** | API-spec testing (OpenAPI/Swagger-driven) | ⬜ | `api_specs` table was created by migration 023; spec-driven testing finds what a crawler can't — every declared but unlinkable endpoint |
| 3 | **E-54** | PagerDuty / Opsgenie alert integration | ⬜ | Extends the existing `ticket_integrations` / `ticket_links` pattern to on-call tooling; resolves incidents automatically when findings are fixed |
| 4 | **E-55** | CVSS-scored findings | ⬜ | CVE-backed findings already carry a CVSS score from OSV/NVD — just not surfaced to the user. Adds a vector-string badge to `FindingCard` and the CVSS field to CSV export |
| 5 | **E-26** | Terraform scaffold — complete the Container Apps path | ⬜ | Unblocks the SWA → Container Apps migration when SWA's free-tier execution ceiling becomes a real constraint again (it already forced the queue-worker architecture once) |

**Sprint 8 exit check**: at least one cloud provider's public misconfiguration
checks run for a connected account; a customer-supplied OpenAPI spec drives
systematic endpoint testing; a Critical finding fires a PagerDuty incident
and resolves it automatically on the next clean scan; CVSS scores appear on
CVE-backed findings; Terraform plan runs clean for Container Apps.

---

## After Sprint 8

Deferred long-horizon items (explicitly not forgotten):
- E-21 if not done in Sprint 6 (httpOnly cookie auth — large but the right
  long-term auth model).
- SOC 2 / ISO 27001 — out of scope for the segment this product serves, per
  `docs/COMPETITIVE-ANALYSIS.md` §6(c); revisit only if a customer
  explicitly blocks on it.
- 24/7 MDR / dark-web monitoring beyond HIBP — same §6(c) decision.
- Full white-label reseller path (Partner Portal beyond what E-39 shipped) —
  needs pricing design before code.

Re-run `docs/FUNCTIONALITY-MATRIX.md`'s audit and re-check `docs/ROADMAP.md`
Beta/Live criteria before committing to Sprint 9 scope.
