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
(runs once `SITE_URL` exists), the queue-stall recovery, and an RLS test
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
