# Roadmap

**This is a readiness ladder for an already-live, monetised product — not
stages of existence.** Hebrides Cyber is deployed, publicly reachable, and
able to take a customer's card details today. Calling the current state
"POC" would be false and would produce a plan that ignores the fact that a
real customer can be charged £20/mo right now for scheduled scans they may
never receive (`docs/ENHANCEMENTS.md` E-01). The stage names below describe
what's *safe to claim* about the product at each point, not what's been
built.

- **Stage 0** — where things actually are, stated plainly.
- **POC** — "provably correct on one path." The product demonstrably does
  the thing it charges for, for at least one paid plan, end to end.
- **Beta** — "safe to onboard strangers." Legal, plan enforcement, data
  deletion, and observability are in place; a failure is detectable and the
  business is allowed to sell what it's selling.
- **Live** — "safe to market and scale." Support model, integrity of the
  billing/pricing surface, and growth-readiness.

Every criterion is an assertion with a **verification method someone other
than the author can execute** — mechanical where possible. A stage is done
when *every* listed criterion is green, not "mostly." Criteria reference
`docs/ENHANCEMENTS.md` items by ID rather than restating them — read the
linked item for the actual scope. No dates, no effort estimates anywhere in
this file (those live in `ENHANCEMENTS.md`, where they're cheap to revise).

---

## Stage 0 — where we actually are

- Live on Azure Static Web Apps, deployed on every push to `master`.
- Taking Stripe Checkout payments — except paid signup itself is currently
  broken (`STRIPE_PRICE_*` unset, `docs/ENHANCEMENTS.md` E-07).
- A privilege-escalation bug in `public.users`' RLS existed until this
  session's migration `017` — fixed, but its prior existence is why nothing
  in this document should be taken on faith; it should be re-derived from
  `docs/FUNCTIONALITY-MATRIX.md`, which is built by reading code.
- Free-tier scan cap and rate limiting are real and server-enforced.
  Almost everything else in the plan-gating ladder (`FUNCTIONALITY-MATRIX.md`
  §5/§6) is not.
- 326 unit/integration tests, coverage floor 18/16/18/19
  (statements/branches/functions/lines) — a genuine floor, not a target,
  and it only moves up.
- Zero production error visibility (`docs/ENHANCEMENTS.md` E-03).

---

## POC — "provably correct on one path"

### Business-readiness block

| ID | Assertion | Verify |
|---|---|---|
| POC-B1 | Stripe Price IDs are live for all three tiers | Checkout completes end-to-end for Basic/Pro/Agency against staging Stripe — `docs/ENHANCEMENTS.md` E-07 |

### Product criteria

| ID | Assertion | Verify | Status |
|---|---|---|---|
| POC-1 | A Basic subscriber can register a monitored target and receives a scheduled scan within the plan's cadence window | Staging Basic account → add target → run `npm run queue:enqueue-scheduled-scans` with a clock override → assert a `scans` row for that target | **UI/enforcement gap fixed** (`docs/ENHANCEMENTS.md` E-01 — `MonitoredTargets.tsx` now renders for any active plan, per-plan cap enforced server-side via `sql/migrations/018_monitored_targets_plan_cap.sql`); cadence logic itself was already correct. **Not yet verified against staging** — the verify method in this row's own third column hasn't actually been run since the fix landed, so don't mark this row green without doing that |
| POC-2 | No authenticated non-admin user can set `is_admin` on their own row | Integration test issuing the UPDATE via the anon key against a real Postgres/RLS instance, asserting 0 rows affected | **Fixed** (migration `017`) — verify the assertion holds against the deployed Supabase project, not just locally |
| POC-3 | Paid signup completes end-to-end for all three price tiers | One Playwright test per tier against staging Stripe | **Fails today** (depends on POC-B1) |
| POC-4 | A scan created via the public API (`POST /api/v1/scans`) and one created via the dashboard produce the same report shape | Compare `GET /api/v1/scans/{id}` output for one of each | Not yet verified — likely true (`executeScan()` is the single entry point per `CLAUDE.md`), but not asserted by a test |
| POC-5 | The extended active-tool suite (nmap/nuclei/sqlmap/xsser/commix/ZAP) runs successfully in the real scheduled-scan environment, not just `not_configured` | Trigger `scheduled-scans.yml` manually against a known-vulnerable staging target, confirm findings from at least one extended tool appear | Untested — `xsser`/`commix` specifically carry an unverified-against-a-real-binary caveat (`docs/ENHANCEMENTS.md` E-18) |

**POC non-goals**: new scanner modules, cloud IAM auditing, SOC 2/ISO,
marketing-site work, support tooling. Explicitly parked, not forgotten.

---

## Beta — "safe to onboard strangers"

### Business-readiness block

| ID | Assertion | Verify |
|---|---|---|
| BETA-B1 | Terms of Service is published and linked from checkout | Manual check + `docs/ENHANCEMENTS.md` E-09 |
| BETA-B2 | Retention promises in `docs/security.md` and `/privacy` agree with each other and with what the code actually does | Diff the two documents' retention sections; `docs/ENHANCEMENTS.md` E-10 |
| BETA-B3 | Manual pen-test engagements (£300/£800/£1,800 on `/pricing`) are backed by professional indemnity insurance and a signed contract template, **or** are pulled from public pricing until they are | Confirm with the owner directly — README's own ops checklist has this unticked as of this writing. **Flagged here deliberately**: this roadmap treats the pricing as live per the owner's explicit instruction, but "live" and "insured" are different claims, and this criterion exists so the gap doesn't get silently forgotten because it was "already decided" |

### Product criteria

| ID | Assertion | Verify | Status |
|---|---|---|---|
| BETA-1 | Every unhandled server error in the last 24h is visible in one place with a request/correlation id | Trigger a canary error, locate it in the tracker within 60s | Blocked on `docs/ENHANCEMENTS.md` E-03 |
| BETA-2 | `GET /api/health` returns 200 with Supabase/Stripe/queue-depth sub-checks, 503 when any is degraded | `curl` in CI immediately post-deploy | Blocked on E-04 |
| BETA-3 | A customer can request deletion; every row keyed to their account is gone within the window stated on `/privacy` | Script + re-query test against a seeded account | Blocked on BETA-B2 (the window must be decided first) + E-10 |
| BETA-4 | Every plan-gated capability in `docs/FUNCTIONALITY-MATRIX.md`'s Enforcement column reads ✅ server — zero ⚠️/❌ rows | Re-generate the matrix's enforcement column from the code, count non-✅ rows, assert zero | Currently 14 ❌ + 3 ⚠️ rows — this is why the matrix exists: it makes this criterion countable. Blocked on E-01, E-02 |
| BETA-5 | `deploy.yml`'s quality gates run on `pull_request`, and a failing check blocks merge, not just deploy | A deliberately-failing PR cannot merge (branch protection configured) | Blocked on E-20 |
| BETA-6 | Every public, unauthenticated write route has abuse protection (rate limit, or is otherwise justified as safe — e.g. Stripe-signature-verified) | Enumerate `src/pages/api/**` public routes, assert each is covered | `contact.ts` currently isn't — blocked on E-05 |
| BETA-7 | `xsser.ts`/`commix.ts` findings are verified against at least one known-vulnerable reference target, not just shipped on faith | Manual run against a deliberately vulnerable staging app, confirm expected findings appear | Blocked on E-18 |

**Beta non-goals**: SOC 2/ISO, 24/7 support, enterprise procurement
apparatus (DPA templates, security questionnaires) — see
`docs/COMPETITIVE-ANALYSIS.md` §6(c), these are explicitly out of scope for
the segment this product serves, not just deferred.

**Exception to "no stage N+1 before stage N is green"**: E-03/E-04
(observability, health check) are listed under Beta but may need to land
*during* POC verification, because POC-1 and POC-5 are hard to verify in a
real deployed environment without them. This is the one deliberate
exception in this document — don't use it as a general excuse to pull other
Beta/Live work forward.

---

## Live — "safe to market and scale"

### Business-readiness block

| ID | Assertion | Verify |
|---|---|---|
| LIVE-B1 | VAT status and invoicing are correctly handled for UK/EU subscribers | Accountant sign-off |
| LIVE-B2 | A support channel exists with a stated (even if modest) response-time expectation | Published on the site, matches actual practice |

### Product criteria

| ID | Assertion | Verify | Status |
|---|---|---|---|
| LIVE-1 | 100% of public unauthenticated API routes are rate-limited | A test enumerating `src/pages/api/**` and asserting every public handler is wrapped, so it can't regress | Blocked on E-05, E-12 |
| LIVE-2 | p95 scan completion time is under a stated threshold over a rolling 7 days | Requires BETA-1/BETA-2 to be measurable at all — explicit dependency | Not yet defined |
| LIVE-3 | Admin dashboard figures (customer count, MRR, scan totals) are exact, not sampled/capped | `admin/overview.ts`'s unbounded-but-1000-row-ceilinged queries and `admin/metrics.ts`'s 500-scan sample both fixed | Blocked on E-17 |
| LIVE-4 | A documented, tested Supabase restore procedure exists | Actually perform a restore against a scratch project and confirm data integrity, not just read the docs | Blocked on E-13 |
| LIVE-5 | Session auth no longer depends on client-readable localStorage for protected-route access | `src/proxy.ts` performs real server-side redirect for an unauthenticated request to `/dashboard` or `/admin` | Blocked on E-21 — large, deliberately scheduled rather than opportunistic |

**Parked past Live** (explicitly deferred, not silently dropped): cloud IAM
auditing, SOC 2/ISO 27001, 24/7 monitoring/MDR, full crawl-behind-login
scanning, malware/dark-web checks beyond Safe Browsing + HIBP (already
shipped, see `docs/ENHANCEMENTS.md` E-24's note) — all explicitly ruled out
for the segment this product serves in `docs/COMPETITIVE-ANALYSIS.md` §6(c)
and §8, not just "not done yet."

---

## Reading this roadmap

- A criterion with no `docs/ENHANCEMENTS.md` ID attached and no "Status"
  needs one written before it's actionable — don't let a bare assertion sit
  here unlinked.
- "Blocked on E-nn" means exactly that — don't mark a criterion green
  without its blocking enhancement actually having shipped.
- Re-verify `docs/FUNCTIONALITY-MATRIX.md` before trusting any "currently
  fails"/"currently X rows" status above — this file is written once and
  will drift; the matrix is the thing to regenerate from code.
