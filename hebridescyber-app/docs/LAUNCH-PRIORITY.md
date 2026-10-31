# Launch priority — what stands between this and a paid launch

**Last checked against the code and production: 2026-10-18.** Scope: a UK
SME launch with enterprise on-ramps. Companion to `docs/NEXT-STEPS.md`
(session handoff) and `docs/ROADMAP.md` (exit criteria). This replaces an
externally written draft; it was corrected against the repository, and the
corrections are listed at the end.

## The five, in order

### 1. Payments live (E-07) — the launch blocker

**Why:** no revenue and no self-serve upgrade until it works. Production
`/api/health` still reports `stripe ok:false` ("degraded").
**State:** the code exists (checkout, webhook with signature verification,
plan gates that honour subscription status, the Tier A price wiring). What's
missing is configuration, not code.
**MVP:** the `STRIPE_PRICE_*` secrets set, then one test-mode checkout end to end.
**Ideal:** self-serve plan changes, invoices in-app, trials, promo codes.
**Acceptance criteria**
- AC1: a test-mode checkout creates the `subscriptions` row for the right plan.
- AC2: the webhook rejects a bad signature and updates state on each of
  `checkout.session.completed`, `invoice.payment_failed` and
  `customer.subscription.deleted`.
- AC3: `/api/health` reports Stripe `ok:true`.
- AC4: steps, test card and expected database state are written in `docs/`.
**Owner action:** set the Stripe price IDs (NEXT-STEPS "Owner actions" #1).

### 2. Reliability baseline

**Why:** buyers ask what happens when it breaks.
**State:** CI gates, auto-applied migrations, a post-deploy health check
(runs on every deploy), the queue-stall recovery, and an RLS test
suite exist. Not in place: error monitoring, a public status page, a
staging environment, a rehearsed restore, and any uptime commitment (the
free hosting tier has none).
**MVP:** Sentry DSN set (E-03); a restore drill recorded in
`docs/BACKUP-RESTORE.md` (E-13); an incident and escalation runbook; a public status page linked from the footer.
**Ideal:** paid hosting with an SLA, staging, on-call cover.
**Acceptance criteria**
- AC1: a forced error appears in Sentry within a minute.
- AC2: a backup restored into a scratch project, and the result recorded.
- AC3: a runbook for "scans stuck", "site down" and "database unavailable".
- AC4: a status page URL in the footer.

### 3. Evidence on findings, and cleaner duplicates (E-75)

**Why:** proof is what turns a finding into a fix and stops disputes.
**State:** de-duplication across tools exists for confident id mappings
(`EQUIVALENCES`), and four finding types carry proof of exploitation. Most
findings carry no request/response evidence.
**MVP:** store a trimmed request and response (method, path, status,
selected headers, a short body excerpt) for each finding that came from an
HTTP probe, with secrets and cookies stripped; show it in the finding card
and the exports.
**Ideal:** replayable evidence, attack-path view.
**Acceptance criteria**
- AC1: every probe-based finding stores bounded, redacted evidence.
- AC2: the finding card and the PDF/CSV exports show it.
- AC3: a retention rule is documented and enforced (evidence is deleted with the scan).
- AC4: no credential or session value appears in stored evidence (test with seeded values).

### 4. Single sign-on (SAML) — a real build

**Why:** a procurement checkbox for larger buyers.
**State, corrected:** the single sign-on, role and provisioning modules were
**deleted on 2026-10-13** because nothing imported them. Only the database
migrations 034-036 remain. This is a build, not a wiring job. No public
page claims SSO.
**MVP:** SAML login for one identity provider, mapped to the existing team
roles, for the top plan only.
**Ideal:** provisioning (SCIM), audit export, automated onboarding.
**Acceptance criteria**
- AC1: sign-in works against one identity provider in a staging project.
- AC2: roles are applied on first login and enforced in the UI and API.
- AC3: sign-in and provisioning events appear in the audit log.
**Note:** decide whether any customer is actually asking before building it.

### 5. Prove the detection (E-73 follow-ups) and test the signed-in screens

**Why:** "industry grade" needs measured accuracy, and the signed-in
dashboard has no end-to-end tests.
**State:** the accuracy benchmark exists for the web checks; DNS, ports, recon
and the extended tools are not covered. The 9 end-to-end tests exercise
public pages only.
**Acceptance criteria**
- AC1: the benchmark covers the extended tools and reports precision and recall per module.
- AC2: signed-in end-to-end tests cover the report, triage, `/dashboard/findings` and `/account`.

## Already shipped (removed from the original list)

The site crawler (E-70), pull-request dependency checks (E-71), the
cross-site findings view (E-74) and the accuracy benchmark's first slice
(E-73) are live. See `docs/NEXT-STEPS.md`.

## Rules for every item

- Acceptance criteria are testable with documented steps.
- New features log through the existing audit log and report errors to Sentry once it exists.
- No secrets in the repository; configuration through the deployment's secrets.
- Update the docs in the same change.

## Corrections made to the original draft

| Draft said | Actually |
|---|---|
| Crawler is a top priority | Already shipped |
| SSO "actually in use": existing libraries to wire | Modules deleted 2026-10-13; a real build |
| "E-74" for evidence and de-duplication | E-74 is the cross-site view (done); evidence is E-75 |
| Create `ops/RUNBOOKS.md` | No `ops/` folder; `docs/BACKUP-RESTORE.md` exists; new runbooks go under `docs/` |
| Stripe needs a sandbox build | The code exists; it needs the price IDs and a test run |
| "Beta in production", hires, customer targets | Not established anywhere in the repo; left out |

## Second external plan (Copilot sprint plan, 2026-10-31)

An externally written 0 + 4 sprint plan was checked against the code on
2026-10-31. Most of it was already built; this is what it asked for, what
exists, and what changed.

| Plan asked for | State on 2026-10-31 |
|---|---|
| Single current-state README; dev and queue-worker runbook | Exists: `NEXT-STEPS.md` (state), `OWNER-TODO.md` (owner items), `RUNBOOK.md` (incidents, recovery), `CLAUDE.md` commands (`npm run queue:run-worker`). No new file added |
| PR template with a safety checklist | **Added:** `.github/pull_request_template.md`. Not enforced by CI; branch protection (OT-07) is the enforcement point |
| Sentry: forced test error | **Added:** `POST /api/admin/sentry-test`, "Send test error" on Admin → Overview. The DSN itself is OT-08 |
| `/api/health` with Stripe and queue depth | Already there (`src/pages/api/health.ts`): Supabase, Stripe (`balance.retrieve`) and pending queue depth. `ok:true` waits on the Stripe keys, not code |
| Webhook test asserting the `subscriptions` row | Already there: `src/__tests__/api/stripe/webhook.test.ts` (signature, the three events, no silent downgrade). A live test-mode checkout is owner-side |
| Status page link in the footer | Already wired to `NEXT_PUBLIC_STATUS_PAGE_URL` (`statusPage.ts`, `Footer.test.tsx`); the page itself is OT-27 |
| `finding_evidence` table, retention job | Not needed: evidence lives in `Finding.evidence` inside `scan_results`, bounded and redacted at capture, deleted with the scan (`data-retention-cleanup.yml` handles scan retention) |
| Evidence on more probe findings | **Extended:** header findings now carry the response they judged (redacted security headers, no body, never Set-Cookie). Backend/Firebase, GraphQL and replay are still open (`NEXT-STEPS.md` Sprint 4) |
| Evidence in finding card, PDF and CSV | Already there since Sprint 4 (2026-10-30) |
| De-duplication across tools | Already there: `findingConsolidation.ts` (`EQUIVALENCES`, corroborating tools on the card). A numeric confidence score was not added: nothing defines what it would measure |
| SAML SSO, organisations, RBAC | Teams and roles exist (`/api/team`). SAML is still a real build with no customer asking, so it is now an owner decision (OT-38), not scheduled work |
| Signed-in crawl status and "credential not accepted" in the report | **Fixed:** a rejected saved login was recorded under `extended.authCheck.crawl` but authCheck reported "checked", so the report and PDF showed nothing. `signedInCrawlStatus.ts` now drives a "signed-in crawl" card on the report and an entry in the PDF's "Checks that did not finish" |
| CI gate that fails only on new findings | Already there: the Action's `fail-on` applies to findings new since the previous scan (`action/action.yml`). Publishing it is OT-20 |
| Remediation PRs, preview mode | Fix PRs (`generate-fix-pr.ts`, repo-ownership check) and the remediation pack exist. Further automation was not started |
| AI triage annotates, never auto-suppresses | Already the design (`AI-TRIAGE-DESIGN.md`): it writes `metadata.aiTriage` only, never severity or lifecycle; triage is a human action |
| Stripe price IDs, Sentry DSN, staging target | Owner items: OT-24 (done), OT-08, OT-11 |
