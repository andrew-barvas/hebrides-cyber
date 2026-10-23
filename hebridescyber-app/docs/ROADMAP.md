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

For a concrete, sprint-by-sprint execution order that gets you toward the
criteria below, see `docs/SPRINT-PLAN.md` — this file states what "done"
looks like, that one states what to actually work on next.

---

## Stage 0 — where we actually are

*Reconciled 2026-10-15 against the code and `docs/NEXT-STEPS.md` (the live
"what shipped" ledger). The earlier version of this section had drifted —
it still cited "914 tests", "Stripe broken" and a "20 enterprise gaps closed"
list naming modules that have since been **deleted** (`rbac.ts`,
`scimProvisioning.ts`, `mspPortal.ts`, `customScanPolicies.ts`,
`riskScoring.ts`, `graphqlApi.ts`, `ssoSaml.ts`, `orgModel.ts`, `cicdSdk.ts`).
Treat `docs/NEXT-STEPS.md` + `docs/FUNCTIONALITY-MATRIX.md` as authoritative;
this section is a dated snapshot, not a live tracker.*

- Live on Azure Static Web Apps, deployed on every push to `master`;
  **migrations auto-apply on deploy** (`DATABASE_URL` set, baseline through
  047 recorded, files through 059 applied — `src/scripts/apply-migrations.ts`).
- **Stripe signup still blocked** — `STRIPE_PRICE_*` unset, so `/api/health`
  reads "degraded" (`docs/ENHANCEMENTS.md` E-07, `docs/OWNER-SETUP.md` §2).
  Still the top business blocker.
- The historical `public.users` privilege-escalation hole was closed in
  migration `017`; the self-set-plan hole in `024`. Both have real-Postgres
  RLS tests (`tests/db/rls.db.test.ts`). Nothing here should be taken on
  faith — re-derive from `docs/FUNCTIONALITY-MATRIX.md`, built from code.
- Plan gating is now largely server-enforced (`docs/FUNCTIONALITY-MATRIX.md`
  §6): the 4 advertised-but-unenforced gaps are fixed; the remaining ungated
  items are capabilities no page sells per-tier (an open product decision,
  not a bug).
- **~3,100 unit/integration tests**, coverage floor **73/66/74/74**
  (statements/branches/functions/lines) — a genuine floor that only moves
  up — plus a real-Postgres RLS/DB suite (`tests/db/`), an accuracy
  benchmark (`bench/`), and a self-dependency CVE audit
  (`dependency-audit.yml`). Next.js is on 16.4.1 (the RCE-patched release).
- **Security posture materially hardened this session (2026-10-14/15):**
  all stored customer secrets encrypted at rest (AES-256-GCM,
  `credentialEncryption.ts` — review findings S-1/S-2); SSRF guard bypasses
  closed (`ownership.ts`); CI Actions SHA-pinned + Dependabot (finding I-4);
  risk score now CVSS/KEV/EPSS-weighted (`scanners/riskScore.ts`); CMS SEO
  persistence bug fixed; sign-up + password-reset pages added (P1-2);
  `scans.error_detail` captured and surfaced in admin. See
  `docs/PRODUCT-REVIEW-2026-10.md` and `docs/NEXT-STEPS.md`'s shipped table.
- The earlier "20 enterprise competitor gaps" claim was **corrected**: much
  of it was unwired library code, now deleted (see `FUNCTIONALITY-MATRIX.md`
  §5b and `COMPETITIVE-ANALYSIS.md` §8). What genuinely ships: 2FA, per-key
  IP allow-listing, multi-site + white-label (Partner Portal), 7-framework
  compliance reporting, SIEM/ServiceNow/Jira/Linear/GitHub ticketing,
  SLA monitoring, scheduled reports, GraphQL endpoint *scanning*. There is
  **no** org/RBAC/SSO/SCIM/MSP multi-tenancy in the application.
- Error-tracking code is shipped but still a **no-op until `SENTRY_DSN` is
  set** (`docs/OWNER-SETUP.md` §3) — the capability existing and the code
  existing remain two different facts. The new `scans.error_detail` column
  is the interim visibility.

---

## POC — "provably correct on one path"

### Business-readiness block

| ID | Assertion | Verify |
|---|---|---|
| POC-B1 | Stripe Price IDs are live for all three tiers | Checkout completes end-to-end for Basic/Pro/Agency against production Stripe — `docs/ENHANCEMENTS.md` E-07 |

### Product criteria

| ID | Assertion | Verify | Status |
|---|---|---|---|
| POC-1 | A Basic subscriber can register a monitored target and receives a scheduled scan within the plan's cadence window | Staging Basic account → add target → run `npm run queue:enqueue-scheduled-scans` with a clock override → assert a `scans` row for that target | **UI/enforcement gap fixed** (`docs/ENHANCEMENTS.md` E-01 — `MonitoredTargets.tsx` now renders for any active plan, per-plan cap enforced server-side via `sql/migrations/018_monitored_targets_plan_cap.sql`); cadence logic itself was already correct. **Not yet verified against production (with a demo account)** — the verify method in this row's own third column hasn't actually been run since the fix landed, so don't mark this row green without doing that |
| POC-2 | No authenticated non-admin user can set `is_admin` on their own row | Integration test issuing the UPDATE via the anon key against a real Postgres/RLS instance, asserting 0 rows affected | **Fixed** (migration `017`) — verify the assertion holds against the deployed Supabase project, not just locally |
| POC-3 | Paid signup completes end-to-end for all three price tiers | One Playwright test per tier against production Stripe | **Fails today** (depends on POC-B1) |
| POC-4 | A scan created via the public API (`POST /api/v1/scans`) and one created via the dashboard produce the same report shape | Compare `GET /api/v1/scans/{id}` output for one of each | **Verified by construction (2026-10-15):** both paths enqueue to the same `executeScan()` and both the public API (`src/pages/api/v1/scans/[id].ts:48`) and the dashboard (`src/app/dashboard/scans/[id]/page.tsx`, via `/api/v1/scans/{id}/…` + the shared `ScanReport` type) return the one `buildScanReport()` output. Its contract is locked by `src/lib/scanReport.test.ts` (triage field, fixed_findings, proof_of_exploit). There is no second report builder to drift from |
| POC-5 | The extended active-tool suite (nmap/nuclei/sqlmap/xsser/commix/ZAP) runs successfully in the real scheduled-scan environment, not just `not_configured` | Trigger `scheduled-scans.yml` manually against a known-vulnerable staging target, confirm findings from at least one extended tool appear | Untested — `xsser`/`commix` specifically carry an unverified-against-a-real-binary caveat (`docs/ENHANCEMENTS.md` E-18) |

**POC non-goals**: new scanner modules, cloud IAM auditing, SOC 2/ISO,
marketing-site work, support tooling. Explicitly parked, not forgotten.

---

## Beta — "safe to onboard strangers"

### Business-readiness block

| ID | Assertion | Verify |
|---|---|---|
| BETA-B1 | Terms of Service is published and linked from checkout | Manual check + `docs/ENHANCEMENTS.md` E-09. **Published** (`src/app/terms/page.tsx`, linked from the footer and `/pricing`'s subscribe section, 27 Aug 2026) — **not yet solicitor-reviewed**, see that page's caveats and `docs/legal/terms-of-service-draft.md`'s "still open" checklist. Treat the publication half as done, the review half as still open |
| BETA-B2 | Retention promises in `docs/security.md` and `/privacy` agree with each other | Diff the two documents' retention sections. **Docs agree** as of the `docs/decisions/ENGINEERING-LOG-2026-08.md` split — `security.md` now defers to `/privacy`'s figures rather than stating its own. The *code* implementing either promise still doesn't exist (`docs/ENHANCEMENTS.md` E-10, blocks BETA-3) — that's this criterion's dependency, not this criterion itself |
| BETA-B3 | Manual pen-test engagements (£300/£800/£1,800 on `/pricing`) are backed by professional indemnity insurance and a signed contract template, **or** are pulled from public pricing until they are | Confirm with the owner directly — README's own ops checklist has this unticked as of this writing. **Flagged here deliberately**: this roadmap treats the pricing as live per the owner's explicit instruction, but "live" and "insured" are different claims, and this criterion exists so the gap doesn't get silently forgotten because it was "already decided" |

### Product criteria

| ID | Assertion | Verify | Status |
|---|---|---|---|
| BETA-1 | Every unhandled server error in the last 24h is visible in one place with a request/correlation id | Trigger a canary error, locate it in the tracker within 60s | Code shipped (E-03) — **still needs `SENTRY_DSN`** (`docs/OWNER-SETUP.md` §3) before it goes green. Interim: a failed scan now records a human-readable reason in `scans.error_detail` (migration 058), surfaced in the admin Scans tab |
| BETA-2 | `GET /api/health` returns 200 with Supabase/Stripe/queue-depth sub-checks, 503 when any is degraded | `curl` in CI immediately post-deploy | **Done** (E-04, 2026-09-04) — verified via unit tests; the "curl in CI immediately post-deploy" verify method itself hasn't been added to `deploy.yml`, worth doing as a follow-up |
| BETA-3 | A customer can request deletion; every row keyed to their account is gone within the window stated on `/privacy` | Script + re-query test against a seeded account | **Done** (E-10, 2026-09-05) — `/account`'s "danger zone" records the request; `src/scripts/erase-user-data.ts` performs the actual erasure (dry-run by default, human-confirmed). Not yet exercised against a real seeded staging account |
| BETA-4 | Every plan-gated capability in `docs/FUNCTIONALITY-MATRIX.md`'s Enforcement column reads ✅ server — zero ⚠️/❌ rows | Re-generate the matrix's enforcement column from the code, count non-✅ rows, assert zero | **Re-audited 2026-09-13**: down to 6 ❌ + 2 ⚠️ (was 14 ❌ + 3 ⚠️). All 4 advertised-but-unenforced gaps are now server-enforced (E-02: target-auth, team, connect-repo, authenticated-scan). Remaining 6 ❌ items are capabilities not advertised as tier-specific — gating them is a product decision, not a code bug. Per E-02's "intentionally open" decision, these stay ungated. ⚠️ = Partner Portal client-only gate + extended-tool path-gating |
| BETA-5 | `deploy.yml`'s quality gates run on `pull_request`, and a failing check blocks merge, not just deploy | A deliberately-failing PR cannot merge (branch protection configured) | **Workflow done** (E-20, 2026-09-13) — `deploy.yml` split into check+deploy jobs, `pull_request` trigger added. **Still needs** GitHub branch-protection rules configured to require the `check` job to pass before merging |
| BETA-6 | Every public, unauthenticated write route has abuse protection (rate limit, or is otherwise justified as safe — e.g. Stripe-signature-verified) | Enumerate `src/pages/api/**` public routes, assert each is covered | **Done** — `contact.ts` rate-limited (E-05, 2026-08-28); all other public write routes are either Stripe-signature-verified or admin-only |
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
| LIVE-1 | 100% of public unauthenticated API routes are rate-limited | A test enumerating `src/pages/api/**` and asserting every public handler is wrapped, so it can't regress | **Done in code** (2026-09-26) — `src/__tests__/api/rate-limit-coverage.test.ts` fails if any route is neither authenticated nor rate-limited; `badge/[scanId]`, `reports/[token]` and `health` now limit per IP with traffic-sized budgets (`checkRateLimit`'s new `policy` argument). **Not effective in production until `UPSTASH_REDIS_REST_URL`/`_TOKEN` are set** — without them every Function instance keeps its own in-memory counter |
| LIVE-2 | p95 scan completion time is under a stated threshold over a rolling 7 days | Requires BETA-1/BETA-2 to be measurable at all — explicit dependency | Not yet defined |
| LIVE-3 | Admin dashboard figures (customer count, MRR, scan totals) are exact, not sampled/capped | `admin/overview.ts`'s unbounded-but-1000-row-ceilinged queries and `admin/metrics.ts`'s 500-scan sample both fixed | **Done** (E-17, 2026-09-05) — both now use exact-count head queries; not yet manually verified against a real production (with a demo account) account with 500+ scans |
| LIVE-4 | A documented, tested Supabase restore procedure exists | Actually perform a restore against a scratch project and confirm data integrity, not just read the docs | Blocked on E-13 |
| LIVE-5 | Session auth no longer depends on client-readable localStorage for protected-route access | `src/middleware.ts` performs real server-side redirect for an unauthenticated request to `/dashboard` or `/admin` | **Done** (E-21) — sessions are cookies set by `@supabase/ssr` and verified server-side (`supabase.auth.getUser()`) by `src/middleware.ts` for `/dashboard`, `/account`, `/admin`. Verified by `tests/e2e/dashboard.spec.ts`, which asserts the raw HTTP 3xx → `/login?redirect=…` (redirects not followed, so a client-side guard couldn't pass it). Note the cookies are deliberately *not* httpOnly — the browser client has to read them; protection comes from server-side verification, not cookie opacity. The MFA (AAL2) step-up is client-side, in `AppShell` |

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

---

## Scale — "differentiated beyond the SME scanner pack"

Beyond Live. These are the next-frontier competitive gaps identified in
`docs/COMPETITIVE-ANALYSIS.md` §10 that would move Hebrides Cyber from
"good SME scanner" to "genuinely differentiated platform." Not sequenced
into sprints yet — they depend on Live criteria being green first.

*Status reconciled 2026-10-15: SCALE-1/2/3 largely shipped already — see notes.*

| ID | Capability | Why it matters | Status |
|---|---|---|---|
| SCALE-1 | **SBOM generation** (CycloneDX) | EU Cyber Resilience Act will mandate this for software vendors | **Done** — `sbomExport.ts`, `GET /api/v1/scans/{id}/sbom` (CycloneDX 1.5) |
| SCALE-2 | **External Attack Surface Management (EASM)** | Continuous asset discovery (shadow IT, forgotten subdomains). Biggest genuine gap vs Detectify/Rapid7/Qualys | **Partial** — `easmDiscovery.ts` runs crt.sh + DNS-bruteforce *per scan* (wired into `executeScan`), plus attack-surface change alerts. **Still open:** a schedule-decoupled standalone discovery pipeline + its own asset dashboard/change feed |
| SCALE-3 | **Cloud Security Posture Management (CSPM)** | AWS/Azure/GCP storage/config checks | **Partial** — `cloudPosture.ts` covers storage public-access + TLS/HTTPS config for all three clouds (E-32), credentials now encrypted at rest. **Still open:** IAM/network/encryption-at-rest depth |
| SCALE-4 | **AI/ML vulnerability prioritization** | Move beyond rule-based risk scoring to ML exploit-likelihood | **Open** — note the score is no longer a flat tally: `scanners/riskScore.ts` now weights by CVSS band, CISA KEV (×1.5/×2) and FIRST EPSS. ML prediction still needs real training data |
| SCALE-5 | **Container runtime scanning** | Beyond Trivy's static image analysis to runtime monitoring | **Open** — High effort, Kubernetes-native; `trivyScan.ts` covers static image + IaC today |
| E-66 | **DMARC aggregate-report processing** | The one NCSC Mail Check function `dns.ts` doesn't replace | **Done (2026-10-15)** — `dmarcAggregate.ts` parses RFC 7489 RUA XML (hand-rolled, namespace-tolerant); `POST /api/dmarc/ingest` (per-owner token, gunzip, rate-limited) stores a per-source summary in `dmarc_reports` (migration 060); `GET /api/dmarc/reports` + per-owner ingest-token management surface it. SCALE-2 (standalone EASM) and SCALE-3 (IAM/encryption CSPM) also shipped this session |

**Scale non-goals** (explicitly not worth building for the SME segment):
IAST/RASP (requires application instrumentation), attack path analysis
(enterprise network complexity), autonomous pen testing (too early, too
expensive). See `docs/COMPETITIVE-ANALYSIS.md` §10 for the full reasoning.

---

## Harden-then-launch stage-gates — 2026-10-22

Stage-gates for the H1–H7 sprint block. A gate is green when **every** listed
check passes, not "mostly." Execute in sprint order; see `docs/SPRINT-PLAN.md`
§ "Harden-then-launch plan" for the full sprint briefs.

| Gate | Sprint | Criterion | Verification |
|---|---|---|---|
| **H1-1** | H1 | `customer.subscription.updated` with absent metadata never writes `plan:"basic"` | `webhook.test.ts` "no-downgrade safety" describe passes |
| **H1-2** | H1 | `checkout.session.completed` with absent plan does not activate a subscription | `webhook.test.ts` "checkout.session.completed with no metadata.plan" test passes |
| **H1-3** | H1 | `subscriptionGrants({plan:"basic",status:"active"},"pro") === false` | `planAccess.test.ts` billing-safety describe passes |
| **H1-4** | H1 (owner) | Stripe Price IDs set in Azure + GitHub secrets | `GET /api/health` → `"stripe":{"ok":true}` |
| **H2-1** | H2 | Worker produces a Sentry event on a synthetic failing job | Sentry dashboard shows event with correlation id |
| **H2-2** | H2 (owner) | `SENTRY_DSN` set + `UPSTASH_REDIS_REST_URL`/`_TOKEN` set | `/api/health` shows sentry + redis healthy |
| **H3-1** | H3 | CI `verify` job passes and publishes the tool-status artifact | GitHub Actions run shows green `verify` job |
| **H3-2** | H3 | `totalChecks === 58` unit test passes | `npm run test:unit` green |
| **H3-3** | H3 | Health smoke step in `deploy.yml` passes on every deploy | `/api/health` → 200 `ok` in deploy log |
| **H4-1** | H4 | Every probe-based finding carries bounded evidence; no credential/cookie values appear | `httpProbe` evidence tests pass |
| **H4-2** | H4 | `format:"pdf"` scheduled report emails a real PDF attachment, not JSON labelled "pdf" | Send-script test passes |
| **H5-1** | H5 | All open routes have explicit tests pinning their gating decision | Route tests green |
| **H5-2** | H5 | PR #88 merged and CI green; COEP + `/blog/[slug]` post-deploy checks pass | GitHub Actions deploy green |
| **H5-3** | H5 (owner) | Branch protection rule added; marketing/grant integrity pass done | GitHub settings show required check; no unsourced stats in live copy |
| **H6-1** | H6 | Non-admin Tier-A `offensive` job downgrades to `safe` + audits `offensive_scan.refused` | Unit test asserting downgrade |
| **H6-2** | H6 | Non-admin → 403 on `offensive-authorization` consent route | API test passes |
| **H6-3** | H6 | No `offensive`/`ai-pentest`/`Strix`/`Cairn` strings in `src/app`/`src/components` | `grep` returns empty |
| **H7-1** | H7 | Admin API key posts a scan with `profile:"offensive"` and it runs (given authorization + verified domain) | API route test passes |
| **H7-2** | H7 | Non-admin key requesting `offensive` → 403 | API route test passes |
| **H7-3** | H7 (owner) | Admin API key minted for `admin@hebridescyber.co.uk` | Key exists in `api_keys` table |

**Added 2026-10-22 (Burp-parity review, see `BURP-PARITY.md`):** bounded replay, AI triage
(off by default, `AI-TRIAGE-DESIGN.md`), session-token entropy and a configurable OOB server
are built. Still open and unscheduled: Dalfox, own-probe OOB, OAuth/MFA flows, two-session IDOR,
triage precision/recall benchmark. Positioning follows the review: compete on evidence,
continuity and fixes, not tool count, and do not claim autonomous AI pentesting until a CI job
proves it.

