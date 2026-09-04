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
| 3 | **E-16** | In-app first-run onboarding checklist (verify domain → run first scan → read report → set an alert channel) | ⬜ not started, next up | The explicit "user signup attention" ask — naturally sequenced after E-01 (already done) since there's no point checklisting "add a target" for a plan that couldn't before. |
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

| Priority | ID | What | Why this sprint |
|---|---|---|---|
| 1 | **E-27** | Multi-target "fleet" rollup dashboard | The Security Overview currently shows only the most-recently-completed scan across *all* monitored targets — an Agency account with up to 15 targets has no fleet view. Direct product gap against the "Agency = multi-site monitoring" pricing differentiator, and the highest-value of the two new dashboard items since it's the only way multi-site customers can actually use what they're paying for. |
| 2 | **E-28** | Findings-by-category and compliance-coverage trend reporting | Extends `ScoreTrend.tsx` beyond a single score number to "which categories are improving," using data `compliance.ts` already computes but never charts. Sequenced after E-27 since both need the same per-target/all-targets selector — build that selector once, not twice. |
| 3 | **E-03** | Observability: error tracking (Sentry / App Insights) | `docs/ROADMAP.md`'s own stated exception — this is allowed to land before its nominal Beta slot because Sprint 2 is adding real new dashboard surface area, and right now a failure in it is invisible. Bring forward, don't skip. |
| 4 | **E-04** | Health check endpoint | Small, pairs directly with E-03 (an alert needs something to alert *from*), same rationale for pulling it forward. |

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

| Priority | ID | What | Why here |
|---|---|---|---|
| 1 | **E-10** | Data retention: implement the cleanup job, reconcile the two promises | Blocks `ROADMAP.md` BETA-3 (customer deletion requests) — a real, live legal gap, not a nice-to-have. Confirm the actual retention windows with the account owner before building automation around unverified numbers (the item's own caveat). |
| 2 | **E-06** | Runtime schema validation at API boundaries (zod) | Credibility risk for a security product specifically to ship without one; do incrementally (new routes first) rather than a big-bang rewrite, as the item itself recommends. |
| 3 | **E-11** | Fix `send-monthly-digest.ts`'s N+1 query pattern | Same failure class that already broke daily-blog/weekly-newsletter once (Azure Functions execution ceiling) — fix before it repeats, not after. |
| 4 | **E-17** | Paginate/cap the remaining unbounded admin queries | Blocks `ROADMAP.md` LIVE-3 (admin figures currently sampled/capped, not exact). |
| 5 | **E-12** | Rate-limit the remaining expensive per-click routes | Rounds out E-05's work from Sprint 1 — do them as one category, not scattered. |
| 6 | **E-18** | Verify `xsser.ts`/`commix.ts` against a real vulnerable target | Cheap verification task, closes `ROADMAP.md` BETA-7. |

**Explicitly not in these 3 sprints** (real, tracked, deliberately deferred —
see `docs/ENHANCEMENTS.md` for each): E-13 (Supabase backup/restore
documentation), E-14 (`ZAP_API_KEY` default), E-15 (remediation-PR UI entry
point), E-20 (`pull_request` trigger on `deploy.yml`), E-21 (httpOnly-cookie
auth migration — explicitly large, the roadmap itself says "deliberately
scheduled rather than opportunistic," don't squeeze it in), E-22
(`security.txt` `Expires` field), E-24/E-25 (harvested-but-lower-priority
items from the frozen engineering log), E-26 (Terraform scaffold/reality
mismatch — infra cleanup, not customer-facing).

**Sprint 3 exit check**: re-run `docs/FUNCTIONALITY-MATRIX.md`'s audit and
confirm the ❌-gate count from Sprint 1 has actually reached 0; a seeded test
account's deletion request removes every row keyed to it within the stated
window; `docs/ROADMAP.md`'s Beta business-readiness + product criteria are
either green or have a named blocker that isn't on this plan's own list.

---

## After these 3 sprints

Re-generate `docs/FUNCTIONALITY-MATRIX.md` and re-check every `docs/ROADMAP.md`
Beta criterion before planning a Sprint 4 — don't extend this plan by
guessing at what's left. The honest next candidates, unordered, are E-13/
E-14/E-15/E-20/E-21/E-22 from the "explicitly not in these 3 sprints" list
above, plus whatever `docs/COMPETITIVE-ANALYSIS.md`'s next refresh surfaces
(its own §1 documents the refresh procedure — it degrades visibly if
neglected, not silently).
