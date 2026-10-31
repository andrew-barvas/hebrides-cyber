# Enterprise gap analysis and build plan

As of 2026-10-31, against `master` at `6b5482a`. Paths are relative to
`hebridescyber-app/` unless prefixed `../`.

## Purpose and rules

This document compares what HebridesCyber does today with what
enterprise-grade scanning and exposure-management platforms offer. The
comparison set is Tenable (Nessus, Tenable.io, Tenable ASM), Qualys VMDR,
Rapid7 InsightVM, Detectify, Intruder, Burp Suite Enterprise and the
attack-surface-management (ASM) category. It then plans how to close each gap
**by building our own version**, never by reselling or wrapping a commercial
product. Open-source engines we already run (nuclei, ZAP, nmap and the rest)
stay in scope as engines; the gap work is the platform around them.

Rules this document follows:

- **Every "we have" or "we don't have" claim cites the code.** Where the
  code and another document disagree, the code wins. Competitor capabilities
  are stated at the category level from general product knowledge. They were
  not re-checked against vendor sites in this pass, and no competitor pricing
  is quoted.
- **Ordered by customer value for a UK SME-focused product.** The buyer is a
  small or medium UK organisation, often on Microsoft 365, often working
  towards Cyber Essentials or Cyber Essentials Plus, sometimes served by an
  MSP or agency. Features that only matter to a Fortune 500 security
  operations centre rank last or are listed under "Not building".
- **Fits the Lookout boundary.** Lookout is sold as "not a penetration
  test, no exploitation, no test payloads"
  (`docs/DEFENSIVE-ASSESSMENT-PLAN.md`). Every plan item says whether it is
  non-intrusive and can therefore run in the `exposure` profile. That profile
  is not on `master` yet: `ScanProfile` in `src/lib/scanProfiles.ts` is
  `safe | full | api | cms | osint | offensive | ai-pentest`, and open PR #144
  adds `exposure`. Work in open PRs #144 and #152 counts as existing work
  here (see "Work in open PRs" below).
- **Doesn't repeat approved work.** `docs/COMPETITOR-MATRIX.md` ("Capabilities
  competitors position that we do not have") already approved SARIF export,
  customer-defined nuclei templates and an instant public check on
  2026-10-30. They are referenced here, not re-planned.
- **Owner-only steps are listed, not done.** They are collected at the end as
  candidate OT items for `docs/OWNER-TODO.md`, which this session does not
  edit.

### Work in open PRs, counted as existing

Both PRs were open drafts on 2026-10-31 and are not on `master`. Their
changes were read with `gh pr diff`:

- **PR #144** (`claude/lookout-managed-assessment-dd2ec8`):
  - Adds the `exposure` profile, `EXPOSURE_TOOLS` (httpx, networkExposure,
    nmap, nuclei) and `isNonIntrusiveProfile` in `src/lib/scanProfiles.ts`.
    A test asserts that no payload-sending tool can run under it, even
    through a scan bundle.
  - Adds a non-intrusive mode to nuclei (`src/worker/tools/nuclei.ts`). It
    drops the `default-login`, `ssrf` and `oast` baseline tags, excludes
    payload tags and runs with `-ni`.
  - Adds CWE and MITRE ATT&CK references to findings
    (`src/lib/scanners/attackMap.ts`), shown in the executive report.
  - Adds migration `064_exposure_profile.sql`.
- **PR #152** (`claude/zap-passive-exposure`, stacked on #144):
  - Adds `runZap(url, { passiveOnly })` in `src/worker/tools/zap.ts`. It
    spiders, waits for the passive queue to drain and reads passive alerts.
    It never starts an active scan.
  - Adds `zap` to `EXPOSURE_TOOLS`.

What this changes below: the non-intrusive scanning boundary that every
"Lookout fit: yes" item depends on is built once these merge. Passive web
coverage under `exposure` (ZAP passive) and weakness classification by CWE
and ATT&CK (§2.5, §2.6) are not counted as gaps.

**Migration number collision.** PR #144 adds
`sql/migrations/064_exposure_profile.sql`, but `master` already has
`064_target_auth_totp.sql` from PR #156. PR #144 needs renumbering to the
next free number before it merges (CLAUDE.md rule 26).

Effort is for one developer working with Claude Code, including tests to
`docs/SCANNER-CONVENTIONS.md`'s rules and a real-binary integration test for
any new tool (CLAUDE.md rule 15). It is a rough estimate, not a quote.

---

## 1. Summary

| # | Area | Where we are | Biggest gap | Priority of the fix |
|---|---|---|---|---|
| 1 | Scanning breadth | Strong external web, TLS, DNS and email, exposure, supply chain and repo coverage across 37 extended tools | Nothing inside the customer's network or on their devices; no Microsoft 365 or Entra posture; exposed services get a port-risk rating but no CVE match | P1 |
| 2 | Asset discovery and inventory | CT-log and passive subdomain discovery every 6 hours; inventory holds domains and subdomains only | IPs, ports, services, certificates and cloud resources aren't assets; no scope confirmation, owner or criticality | P2 |
| 3 | Authenticated scanning | Cookie, Basic, recorded form login, TOTP MFA | No bearer-token or OAuth2 API auth, no SSO-provider login, no check that a session stayed logged in | P2 |
| 4 | Continuous monitoring and scheduling | Daily at best for full scans; EASM every 6 hours; scan windows; uptime; emerging-threat emails | No per-target schedule, no event-triggered rescans, on-demand scans are always passive | P2 |
| 5 | Prioritisation and risk scoring | CVSS, CISA KEV and FIRST EPSS weight each finding; attack-path rules | No asset criticality or exposure context, and no estate-wide "fix this first" list | P1 |
| 6 | Reporting and compliance | Executive PDF, 7-framework compliance view, scheduled reports, portfolio report, SBOM, CSV/JSON export | No SARIF (approved), no Cyber Essentials Plus evidence pack, no NCSC CAF mapping, no estate trend view | P2 |
| 7 | Integrations | Jira, Linear, ServiceNow, GitHub Issues; Slack, Teams; PagerDuty, Opsgenie; signed webhooks; SIEM over HTTP | Syslog declared but not built; webhook delivery has one retry; no UK MSP tools (HaloPSA, ConnectWise, Autotask); no SSO or SCIM | P2 |
| 8 | Multi-tenant RBAC and audit logging | One team per owner with four roles; audit log written for 30+ actions; per-key IP allowlists | Audit log only visible to our admins; organisation, RBAC and SSO tables exist with no code behind them | P2 |
| 9 | Remediation workflow | Triage, SLAs, tickets that close themselves on fix, single-finding retest, fix PRs, AI fix text | No assignment to a person, no approval step for risk acceptance, ticket status doesn't flow back | P2 |
| 10 | Scale and reliability | Postgres queue with `SKIP LOCKED`, 3 GitHub Actions shards per daily run | Hard ceiling of about 45 full scans per day; no fixed source IP; no queue-wait alerting | P1 |

---

## 2. Findings by area

### 2.1 Scanning breadth

**What we have.**

- A base passive suite on every scan: TLS, headers, DNS and email
  authentication, exposure probes, takeover, fingerprinting, web app, crawl,
  GraphQL, business logic, API spec, backend exposure and more (`runAllChecks()`
  in `src/lib/scanners/index.ts`; per-check detail in
  `docs/SCANNER-INVENTORY.md` §B1).
- 37 extended tools (`EXTENDED_TOOL_NAMES`, `src/lib/scanProfiles.ts`) run by
  `runExtendedTools()` in `src/lib/scanExecution.ts`. Wrappers are in
  `src/worker/tools/` and `src/lib/scanners/`. They include nuclei, ZAP,
  testssl.sh, naabu with nmap (`src/worker/tools/networkExposure.ts`), httpx,
  katana and Subfinder.
- Supply chain and code coverage when a repository is connected: Gitleaks,
  Trivy image and config, Opengrep with our 34-rule pack, zizmor and OSV
  dependency checks (`docs/SCANNER-INVENTORY.md` §A(a)).
- Cloud posture with customer credentials, limited to storage: public S3
  buckets and policies, Azure storage public access and TLS, and GCS
  public-access prevention (`src/lib/scanners/cloudPosture.ts`). The
  module's own header says IAM, network security groups and encryption at
  rest are not covered.

**Gaps against the comparison set.**

1. **No internal or device scanning.** Tenable, Qualys and Rapid7 all sell
   agents and internal scanners that audit installed software and patch
   levels. We scan only what is reachable from the internet. Every worker
   runs on GitHub-hosted runners (`../.github/workflows/scheduled-scans.yml`).
   For UK SMEs this matters most for Cyber Essentials, whose
   security-update control requires high and critical patches within 14
   days on in-scope devices. We can't show that today.
2. **Exposed services aren't matched to CVEs.** `networkExposure.ts` records
   each open port with a risk band from `portRisk.ts`, and nmap's `-sV`
   reads a product and version. Nothing turns that version into CVEs. CPE
   matching exists only for PHP and Apache from HTTP banners
   (`softwareCveDb.ts`), plus WordPress. This is the core of what Nessus
   does on an external scan, and it doesn't need any intrusive traffic.
3. **No Microsoft 365 or Entra ID posture.** Most UK SMEs run their
   identity and email on Microsoft 365. Missing MFA enforcement, legacy
   authentication left on, external mail forwarding and over-privileged
   guests are among the commonest ways they get breached. None of the
   modules under `src/lib/scanners/` call Microsoft Graph.
4. **Narrow port coverage.** naabu covers the top 1,000 TCP ports and nmap a
   fixed 13 (`src/worker/tools/nmap.ts`). There is no UDP (SNMP, IKE/IPsec,
   NTP, TFTP), which external-scan vendors cover by default.
5. **Cloud posture stops at storage.** No IAM, security group, logging or
   key-management checks (`cloudPosture.ts` header).
6. **Deliberately out of scope (see "Not building"):** IAST and RASP agents,
   mobile app testing, and our own replacement for ZAP or nuclei.

### 2.2 Asset discovery and inventory

**What we have.**

- Certificate Transparency (crt.sh) and Subfinder passive discovery
  (`src/lib/scanners/recon.ts`, `subdomains.ts`). DNS brute force runs only
  after the Tier A offensive gate clears (`src/lib/easmDiscovery.ts`).
- A standalone discovery sweep every 6 hours, separate from scan cadence
  (`src/lib/easmPipeline.ts`, `../.github/workflows/easm-discovery.yml`, cron
  `25 */6 * * *`).
- Alerts on new hostnames and on NS, MX, SPF and DMARC changes
  (`src/lib/attackSurfaceMonitor.ts`), live-host probing with httpx
  (`hostProbe.ts`), lookalike domain monitoring
  (`src/lib/lookalikeDomainMonitor.ts`), and a dashboard page
  (`src/app/dashboard/assets/page.tsx`, `src/components/AssetInventory.tsx`).

**Gaps.**

1. **The inventory only knows names.** `asset_inventory`
   (`sql/migrations/022_asset_inventory.sql`) has
   `kind in ('domain', 'subdomain')`, plus `cms_type` and `cloud_hints`.
   IP addresses, open ports, services, certificates, technologies and cloud
   resources are found during scans but stay inside each scan's JSON, not
   in the inventory. ASM tools treat each of these as a tracked asset with
   first-seen and last-seen dates.
2. **No scope decision.** A discovered host is never marked in scope, out of
   scope or not ours. ASM tools ask the customer to confirm, and that
   answer drives what gets scanned next.
3. **No business context.** There is no owner, tag, environment or
   criticality column, so prioritisation (§2.5) has nothing to weight by.
4. **Discovery seeds are domains only.** There is no discovery from IP
   ranges, ASNs, reverse DNS, or the customer's own DNS zone or cloud
   accounts. The last one is the most reliable source of shadow IT.

### 2.3 Authenticated scanning

**What we have.**

- Saved credentials of type `cookie` or `basic`
  (`sql/migrations/014_target_auth_credentials.sql`), sealed at rest
  (`src/lib/credentialEncryption.ts`).
- Login recording that drives a real browser through the site's own form
  (`src/lib/scanners/loginRecorder.ts`, `POST /api/account/record-login`),
  with TOTP MFA (`src/lib/totp.ts`, `sql/migrations/064_target_auth_totp.sql`).
- A signed-in header check and a signed-in crawl (`authenticatedCheck.ts`,
  `authenticatedCrawl.ts`), the `authCheck` extended tool.

**Gaps.**

1. **No API authentication types.** `auth_type` allows only `cookie` and
   `basic`. A bearer token, an API key in a custom header, or an OAuth2
   client-credentials grant can't be stored, so `apiSpec.ts`'s spec-driven
   checks run unauthenticated against most real APIs. Burp Suite
   Enterprise and Detectify both support these.
2. **No SSO-provider login.** Recording works when the login form is on the
   target's own site. Many SME apps sign in through Entra ID or Google.
   Following that redirect isn't supported (`docs/SCANNER-INVENTORY.md`
   Part C: "never attempts an OAuth/MFA flow itself"; TOTP has since been
   added for form logins).
3. **No session-health check.** If the session expires halfway through, the
   crawl carries on logged out and the results read as signed-in coverage.
   Enterprise DAST tools check a logged-in indicator and log in again.
4. **No access-control test with two roles.** This is planned in
   `docs/COMPETITOR-MATRIX.md` ("two-session access-control test").
   `docs/COMPETITIVE-ANALYSIS.md` §9 keeps deep IDOR testing an
   anti-feature. A read-only, two-session comparison is the bounded
   version.

### 2.4 Continuous monitoring and scheduling

**What we have.**

- Scheduled scans from one daily cron (`0 3 * * *`,
  `../.github/workflows/scheduled-scans.yml`), with cadence per plan:
  weekly on Basic, daily on Pro and Agency (`src/lib/scanCadence.ts`,
  `SCAN_INTERVAL_DAYS`).
- Maintenance windows per target (`src/lib/scanWindows.ts`, enforced in
  `src/scripts/enqueue-scheduled-scans.ts`).
- On-demand scans picked up within about a minute
  (`../.github/workflows/on-demand-scan.yml`). These are always passive:
  `runOne()` in `src/scripts/run-queued-scan-jobs.ts` treats a job with
  `scan_id` set as `safe`.
- EASM every 6 hours (§2.2), uptime monitoring (`src/lib/uptimeService.ts`),
  and emerging-threat emails that match the CISA KEV list against each
  host's detected technologies (`src/lib/emergingThreatAlerts.ts`).

**Gaps.**

1. **Daily is the fastest full scan, and the time is fixed.** There is no
   per-target schedule, no "every 4 hours, passive only" option and no
   choice of hour beyond the window filter.
2. **Nothing triggers a scan.** A new KEV entry that matches a customer's
   stack sends an email, but no check runs to confirm whether they're
   affected. Intruder and Tenable both run a targeted check for an
   emerging threat. Likewise, a new hostname found by EASM waits for the
   next scheduled scan.
3. **Paying customers can't run an extended scan on demand.** It only
   happens on the schedule.

### 2.5 Prioritisation and risk scoring

**What we have.**

- A per-finding penalty from severity, raised by CVSS (`cvssEnrich.ts`), CISA
  KEV and ransomware use, and adjusted by FIRST EPSS
  (`src/lib/scanners/riskScore.ts`, `threatIntel.ts`). This is a 0 to 100
  score per scan.
- Cross-tool de-duplication with corroboration (`src/lib/findingConsolidation.ts`).
- Attack-path rules that chain findings (`src/lib/attackPathAnalysis.ts`).
- Fix difficulty (`src/lib/scanners/fixDifficulty.ts`) and a prioritised
  list inside the executive report (`prioritise()` in
  `src/lib/executiveReport.ts`).

**Gaps.**

1. **Scoring is per scan, not per estate.** Qualys TruRisk, Rapid7 and
   Tenable's VPR produce one ranked list across every asset. Our customer
   with ten sites has ten reports to read.
2. **No asset context.** Nothing weights a finding on the login or payment
   host above the same finding on a brochure subdomain. That needs §2.2's
   criticality column first.
3. **No exposure context.** Whether a host sits behind a WAF (`whatwaf`), is
   reachable at all (`hostProbe.ts`), or has the vulnerable component
   actually loaded is known in places but not fed into the ranking.
4. A trained model (as `docs/COMPETITIVE-ANALYSIS.md` §10 #5 notes) needs
   outcome data we don't have yet. A transparent rule-based ranking fits
   an SME audience better anyway.

### 2.6 Reporting and compliance

**What we have.**

- An executive PDF (`src/lib/executiveReport.ts`, `src/lib/reportPdf.ts`) with
  custom branding. Shared report links (`src/lib/reportShares.ts`). A
  portfolio report across sites (`src/lib/portfolioReport.ts`).
- A compliance view across ISO 27001, PCI DSS, Cyber Essentials, OWASP Top
  10, CIS v8, NIS2 and DORA (`src/lib/complianceReport.ts`), carefully
  framed as an indicator, not a certification.
- Cyber Essentials readiness and self-assessment (`cyberEssentialsReadiness.ts`,
  `ceSelfAssessment.ts`). Scheduled reports (`scheduledReports.ts`).
  CycloneDX SBOM (`sbomExport.ts`). CSV and JSON export
  (`src/pages/api/v1/scans/[id]/export.ts`). A remediation pack and a trend
  API (`src/pages/api/v1/targets/[host]/trend.ts`). A public controls page
  (`/trust`, `docs/CONTROLS-EVIDENCE.md`).

**Gaps.**

1. **SARIF export.** Already approved (`docs/COMPETITOR-MATRIX.md` #2).
2. **No Cyber Essentials Plus evidence pack.** CE Plus assessors test
   external vulnerability scanning and device patching. An export that
   lays out the external scan evidence, and later the device evidence from
   §3 item P1-4, would save the customer and their assessor time.
3. **No NCSC Cyber Assessment Framework (CAF) mapping.** CAF is the UK
   framework for NIS-regulated and public-sector bodies, and
   `docs/COMPETITIVE-ANALYSIS.md` §6(c) names the Scottish public sector as
   a realistic market. `COMPLIANCE_MAP` (`src/lib/scanners/compliance.ts`)
   has no CAF entries.
4. **No trend view across the estate.** There is mean time to fix in the SLA
   dashboard (`src/components/SlaDashboard.tsx`) and a per-host trend API,
   but no chart of open risk and fix rate across all sites over time, which
   enterprise tools lead their dashboards with.

### 2.7 Integrations

**What we have.**

- Ticketing in Jira, Linear, ServiceNow and GitHub Issues
  (`src/lib/ticketProviderList.ts`, `ticketProviders.ts`), with automatic
  close once a later scan shows the fix (`src/lib/ticketAutoClose.ts`).
- Slack and Microsoft Teams (`slack.ts`, `msTeams.ts`). PagerDuty and
  Opsgenie (`oncallIntegrations.ts`).
- Signed webhooks with the same report shape as the API (`src/lib/webhooks.ts`).
- SIEM forwarding over HTTP in JSON, CEF or LEEF, called after each scan
  (`src/lib/siemIntegration.ts`, `forwardToSiem` in `scanExecution.ts`).
- A REST API with API keys, IP allowlists and rate limits (`src/lib/apiAuth.ts`,
  `src/lib/ipAllowlist.ts`, `docs/API.md`). CI templates
  (`src/lib/ciTemplates.ts`) and a GitHub App (`src/lib/githubApp.ts`).

**Gaps.**

1. **Delivery isn't durable.** Webhooks get one attempt and one quick retry
   (`webhooks.ts` header). SIEM forwarding is best-effort inline. A
   receiver that is down for five minutes loses the event.
2. **Syslog isn't built.** The `syslog` type is declared, but the code says
   "syslog type: future — needs UDP/TCP socket, not fetch"
   (`siemIntegration.ts:130`).
3. **No native Microsoft Sentinel or Splunk HTTP Event Collector format.**
   Sentinel is the SIEM that UK SMEs on Microsoft 365 E5 and Business
   Premium are most likely to have.
4. **No UK MSP tools.** HaloPSA (UK-built), ConnectWise and Autotask are
   where MSPs and agencies live, and Agency is one of our tiers. Azure
   DevOps Boards is also missing.
5. **The API is mostly read-only.** It can start scans, read them, export
   them and triage findings. Targets are created by the browser writing
   straight to `monitored_targets` under RLS with no server-side validation
   (`enablesOffensiveTools()`'s comment in `src/lib/scanProfiles.ts`
   describes `MonitoredTargets.tsx` doing this). There is no API
   for targets, assets or a findings list across the estate, and no
   published OpenAPI document.
6. **No SSO or SCIM.** See §2.8.

### 2.8 Multi-tenant RBAC and audit logging

**What we have.**

- Teams: one team per owner, with roles `admin`, `developer`, `auditor` and
  `member` (`sql/migrations/007_teams.sql`, `025_team_roles_extended.sql`).
  Only `admin` and `developer` can act on the owner's account
  (`src/lib/teamAccess.ts`).
- RLS on every table (CLAUDE.md rule 23).
- Dashboard TOTP for our own users through Supabase MFA
  (`src/components/TwoFactor.tsx`, the challenge page under
  `src/app/login/`).
- An audit log written by `src/lib/audit.ts` for more than 30
  `"<resource>.<verb>"` actions, such as `scan.started`, `finding.triaged`,
  `api_key.created`, `team_member.role_changed` and `offensive_scan.authorized`.
- A Partner Portal for Agency accounts (`src/components/PartnerPortalPanel.tsx`).

**Gaps.**

1. **Customers can't see their own audit log.** The only readers of
   `audit_logs` are `src/pages/api/admin/audit.ts` and
   `src/pages/api/admin/metrics.ts`, both for our own admins. An
   enterprise buyer's questionnaire asks for this.
2. **Organisation, RBAC and SSO tables exist without code.**
   `sql/migrations/034_organizations.sql`, `035_rbac.sql` and
   `036_sso_providers.sql` create `organizations`, `org_members`,
   `rbac_permissions` and `sso_providers`. No file in `src/` reads them, and
   the modules that once did were deleted as unwired
   (`docs/FUNCTIONALITY-MATRIX.md` §5b). `sso_providers.client_secret` is a
   plain `text` column, which would break CLAUDE.md rule 20 if it were ever
   used as is.
3. **No multi-client structure.** An MSP or agency with twenty clients has
   one account and one team. It can't give a client's staff access to only
   that client's sites.
4. **No SSO or SCIM** for logging in to HebridesCyber itself. Login is
   password or magic link (`src/lib/auth.ts`).

### 2.9 Remediation workflow

**What we have.**

- Triage as accepted risk, false positive or snoozed, always with a reason
  (`src/lib/findingTriage.ts`, `src/components/FindingTriage.tsx`).
- A lifecycle per finding with first-seen, last-seen and resolved, which
  only resolves a finding when its source ran
  (`src/lib/findingLifecycle.ts`).
- SLA targets and alerts (`slaMonitoring.ts`, `slaAlerts.ts`).
- Ticket creation and automatic close (§2.7). A single-finding retest
  (`src/pages/api/scans/[id]/retest-finding.ts`). Fix pull requests
  (`src/pages/api/generate-fix-pr.ts`). AI fix suggestions
  (`src/lib/aiRemediation.ts`). Config snippets (`src/lib/configFixes.ts`).
  A remediation pack (`/api/v1/scans/{id}/remediation-pack`).

**Gaps.**

1. **No assignee.** A finding can't be given to a named team member, and
   there is no "my findings" view.
2. **Risk acceptance has no approver.** Anyone who can triage can accept a
   risk. Enterprise tools route it to a second person and keep the
   approval with the record.
3. **Ticket status doesn't flow back.** Closing the Jira issue doesn't
   trigger a retest. Reopening it doesn't reopen the finding. Only our side
   closes tickets (`ticketAutoClose.ts`).
4. **Retest is base-suite only.** A nuclei or ZAP finding can only be
   confirmed fixed at the next scheduled scan, because `retest-finding.ts`
   runs the passive path.

### 2.10 Scale and reliability

**What we have.**

- A Postgres job queue with `claim_scan_job()` using `SKIP LOCKED`
  (`sql/migrations/008_scan_jobs.sql`), stale-job recovery (`041`), progress
  (`038`) and error detail (`058`).
- Three worker shards on GitHub-hosted runners per daily run
  (`scheduled-scans.yml`, `matrix.shard: [1, 2, 3]`), each capped at
  `MAX_JOBS_PER_RUN = 15` and `TIME_BUDGET_MS` of 25 minutes
  (`src/scripts/run-queued-scan-jobs.ts`).
- Tool kill switches (`src/lib/toolKillSwitch.ts`), a run verifier
  (`src/lib/scanRunVerification.ts`), Sentry with scrubbing, and a status
  page (`src/lib/statusPage.ts`).
- A container image and a manual Container Apps deploy path
  (`Dockerfile`, `../.github/workflows/deploy-containerapp.yml`).

**Gaps.**

1. **A hard capacity ceiling.** One daily run of 3 shards at up to 15 jobs
   each is at most 45 extended scans a day, and fewer when a shard's 25
   minutes run out first. Anything left waits a full day. At Pro's daily
   cadence that's about 45 monitored targets in total before scans start
   slipping.
2. **No fixed source IP.** Runners come from GitHub's shared ranges.
   Customers can't allowlist us in a WAF, and enterprise buyers routinely
   ask for this (`docs/COMPETITOR-MATRIX.md` #7 notes the same).
3. **No queue-wait alerting.** Nothing alerts when jobs sit unclaimed. This
   is listed as planned in `docs/COMPETITOR-MATRIX.md`.
4. **Scanner workers hold the database service-role key.** That's fine on
   our own runners but rules out a customer-run agent until an agent API
   exists (`docs/COMPETITOR-MATRIX.md` #7).

---

## 3. Build plan, ordered by customer value

Priority key: **P1** build next, because a UK SME would notice or pay for it
now. **P2** build once P1 is done, or sooner if a deal asks for it. **P3**
build only when a customer asks.

"Lookout fit" says whether the item is non-intrusive and can run in the
`exposure` profile once PR #144 lands.

### P1-1. Always-on scan workers with a fixed source IP

- **What we'd build.** A worker pool that runs all the time, sized by queue
  depth, with one static outbound IP published to customers.
- **Approach.** Run the existing `run-queued-scan-jobs.ts` loop in the
  existing `Dockerfile` image as an Azure Container Apps Job. Scale it with a
  KEDA rule on unclaimed `scan_jobs` rows. Route egress through a NAT gateway
  with a static public IP, and publish that IP on `/trust` and in the
  onboarding docs. Keep the GitHub Actions workflow as a fallback. Move the
  tool install steps from `scheduled-scans.yml` into the image, keeping the
  SHA-256 pins. Add a queue-wait metric (oldest unclaimed job age) and alert
  through the existing on-call path when it passes 2 hours.
- **Effort.** 1.5 to 2 weeks.
- **Dependencies.** Owner approval of Azure spend and the NAT IP (OT
  candidate). Terraform in `azure/terraform/` (referenced by
  `deploy-containerapp.yml`).
- **Lookout fit.** Yes. It is infrastructure, and a fixed IP makes
  "we told your WAF who we are" part of the service.

### P1-2. One "fix this first" list across the estate

- **What we'd build.** A ranked list of open findings across every site an
  account monitors, with a plain-English reason for each position. It goes
  on the dashboard, in the scheduled report and in the API.
- **Approach.** Add `criticality` (`low | normal | high`, default `normal`)
  and `environment` to `monitored_targets`. Compute an estate rank from what
  `riskScore.ts` already produces, multiplied by target criticality and by
  exposure signals we already collect: host live (`hostProbe.ts`),
  internet-facing service, WAF present (`whatwaf`), KEV listed. Keep it
  rule-based and explain each factor ("KEV listed, on a high-criticality
  host"). Read from `finding_lifecycle` so triaged findings drop out. Add
  `GET /api/v1/findings?sort=priority`.
- **Effort.** 1 to 1.5 weeks.
- **Dependencies.** A migration. None external.
- **Lookout fit.** Yes, and it is the centrepiece of a Lookout report.

### P1-3. CVE matching for exposed services

- **What we'd build.** For every open service nmap identifies, a list of
  known CVEs with KEV and EPSS context, so "port 3389 open" becomes
  "RDP on Windows Server 2012 R2, end of life, 3 KEV-listed CVEs".
- **Approach.** `nmap.ts` already parses `-sV` product and version from
  nmap's XML (`networkExposure.ts` reuses it). Also parse the `<cpe>`
  element nmap emits, which isn't read today. Keep a local CPE-to-CVE
  index built from the NVD 2.0 feeds by a nightly job, stored in Postgres
  or as a compressed artefact, because per-scan NVD API calls are rate
  limited (`softwareCveDb.ts` already hits this). Run every match through
  `threatIntel.ts` and `endOfLife.ts`. Report only version-bounded matches,
  with the matched CPE as evidence. A banner with no version is reported as
  "version unknown", never as a CVE. The checkId is
  `network-exposure.service-cve:<port>:<cve>`.
- **Effort.** 1.5 to 2 weeks, including a bench fixture.
- **Dependencies.** A free NVD API key for the feed job (OT candidate).
  `docs/SCANNER-CONVENTIONS.md` evidence rules.
- **Lookout fit.** Yes. It reads banners and sends no payloads.

### P1-4. Microsoft 365 and Entra ID posture

- **What we'd build.** Read-only checks of a customer's Microsoft 365 tenant
  for the settings behind most SME compromises.
- **Approach.** A multi-tenant Entra app registration with read-only
  Microsoft Graph permissions (`Policy.Read.All`, `Directory.Read.All`,
  `Reports.Read.All`, `MailboxSettings.Read`), granted by the customer's
  admin through the consent flow. Store the tenant ID only, not a secret,
  since our app's own credential is ours. Check that:
  - MFA is enforced for all users and for admins.
  - Legacy authentication is blocked.
  - Security defaults or Conditional Access are on.
  - The number of Global Admins is small.
  - No mailbox forwards externally.
  - Guest access isn't wide open.
  - Self-service consent to third-party apps is restricted.
  - Audit logging is enabled.

  Map each check to Cyber Essentials (user access control) and CIS
  Microsoft 365 controls in `COMPLIANCE_MAP`. Use a new `m365.*` checkId
  family. A failed Graph call is `status: "error"` (CLAUDE.md rule 7).
- **Effort.** 3 to 4 weeks, including the consent flow and revoke.
- **Dependencies.** Entra app registration and Microsoft publisher
  verification (OT candidates). A test tenant (a Microsoft 365 developer
  tenant is enough). A privacy notice update for the data read.
- **Lookout fit.** Yes. It only reads configuration with the customer's
  consent.

### P1-5. Device patch-audit agent for Cyber Essentials

- **What we'd build.** A small agent for Windows, macOS and Linux that
  reports OS version, installed software and pending updates. The server
  matches them to CVEs and end-of-life dates and shows which devices miss
  the 14-day patch rule.
- **Approach.** The agent is written in Go as a single signed binary. It
  makes outbound HTTPS calls only and has a per-device token issued from
  the dashboard. It only collects inventory and never scans the network.
  Software inventory comes from the OS's own sources: Windows registry
  uninstall keys and `Get-HotFix`, `pkgutil` and `system_profiler` on macOS,
  `dpkg`/`rpm` on Linux. On the server we build:
  - An agent API (`POST /api/agent/inventory`) that treats input as
    untrusted.
  - Matching through OSV, the P1-3 NVD index and `endOfLife.ts`.
  - A device list in the dashboard.

  The agent API with per-agent tokens is also the foundation for P3-3.
- **Effort.** 5 to 8 weeks: agent 2 to 3, API and matching 2, dashboard
  and reports 1 to 2, packaging and signing 1.
- **Dependencies.** P1-3's CVE index. A code-signing certificate and Apple
  notarisation (OT candidates). A decision on whether this belongs in
  Lookout or a separate add-on (owner).
- **Lookout fit.** Yes. It is inventory collection on devices the customer
  installs it on. It is a new product surface, so it ranks below P1-1 to
  P1-4 despite its value.

### P2-1. Asset inventory v2: every asset type, scope and owner

- **What we'd build.** IPs, open ports, services, certificates,
  technologies and cloud resources as tracked assets. Each has a scope
  status (`unconfirmed | in_scope | out_of_scope | not_ours`), an owner, tags
  and a criticality value that P1-2 can use.
- **Approach.** Widen `asset_inventory.kind` and add `parent_id`, `attributes
  jsonb`, `scope_status`, `owner_label` and `tags`. Write assets from what a
  scan already holds (`networkExposure`, `hostProbe`, `tls`, `fingerprint`,
  `cloudPosture`) in `syncAssetInventory`. Store CWE and ATT&CK references
  from PR #144's `attackMap.ts` on each finding's asset. Add a review queue in the
  dashboard for unconfirmed discoveries, where out-of-scope assets stop
  scheduled scanning. Add discovery from the customer's DNS zone when they
  connect a Cloudflare or Azure DNS read token, and from cloud accounts
  already connected for `cloudPosture`.
- **Effort.** 2 to 3 weeks.
- **Dependencies.** A migration. P1-2 reads criticality from here. If P2-1
  lands later, P1-2 starts with the target-level column.
- **Lookout fit.** Yes.

### P2-2. Authenticated scanning v2

- **What we'd build.** Bearer-token, custom-header and OAuth2
  client-credentials auth types. A logged-in indicator with automatic
  re-login. Login recording that follows an Entra ID or Google sign-in
  redirect for a dedicated test account.
- **Approach.** Extend `auth_type` and seal the new secrets per CLAUDE.md
  rule 20 (`STRING_SECRET_TARGETS`). Pass headers through `authCheck`,
  `apiSpec.ts` and katana. Store a "logged-in marker" (a selector or text)
  with the credential. `authenticatedCrawl.ts` checks it every N pages,
  re-runs `loginRecorder.ts` once, and reports `partial` if the session
  still won't hold. Extend `loginRecorder.ts` to follow identity-provider
  redirects and type into those pages, reusing `totp.ts`.
- **Effort.** 2 to 3 weeks.
- **Dependencies.** None external. A test identity-provider tenant for the
  integration test (the M365 developer tenant from P1-4 also works here).
- **Lookout fit.** Yes for signed-in passive checks. The two-role access
  test in `docs/COMPETITOR-MATRIX.md` stays outside Lookout.

### P2-3. Monitoring v2: schedules and event-triggered checks

- **What we'd build.** Per-target schedules, frequent passive scans,
  extended scans on demand for paid tiers, and checks triggered by events.
- **Approach.** Add `schedule_cron` and `passive_interval_hours` to
  `monitored_targets`, evaluated in `enqueue-scheduled-scans.ts` with
  `scanCadence.ts` as the floor for each plan. When
  `emergingThreatAlerts.ts` matches a new KEV entry to a host, enqueue a
  targeted job that runs only nuclei templates for that CVE. Nuclei's
  `-id` and `-tags cve-xxxx` support this, limited to non-intrusive
  templates. When EASM finds a host and it is confirmed in scope (P2-1),
  enqueue a passive scan of it. Allow `scan_profile` on on-demand jobs for
  Pro and above through `planGate`.
- **Effort.** 1.5 weeks.
- **Dependencies.** P1-1, since more triggers need more capacity. P2-1 for
  scope confirmation.
- **Lookout fit.** Yes, if the triggered templates are filtered the way
  PR #144 filters nuclei.

### P2-4. Customer-visible audit log

- **What we'd build.** An audit tab in the account, an export, and a
  `GET /api/v1/audit` endpoint, showing the actions `audit.ts` already
  writes for the caller's account.
- **Approach.** An RLS policy, or a `SECURITY DEFINER` reader per CLAUDE.md
  rule 25, scoped to the owner and team `admin`/`auditor` roles. Reuse the
  filter code from `auditFilters.ts`. Add the action vocabulary to
  `docs/API.md`. Forward these events to SIEM integrations as well.
- **Effort.** 3 to 4 days.
- **Dependencies.** None.
- **Lookout fit.** N/A (platform). Lookout customers will ask for it.

### P2-5. Durable outbound delivery, syslog, Sentinel and Splunk

- **What we'd build.** One delivery queue for webhooks and SIEM events,
  with retries and a dead-letter view. Syslog over TLS. Native Microsoft
  Sentinel and Splunk HTTP Event Collector targets.
- **Approach.** A Postgres table `outbound_deliveries` with exponential
  backoff over 24 hours, drained by the P1-1 workers. Show failed
  deliveries and a resend button in the integrations page. Syslog over
  TLS (RFC 5425) from the worker, since Static Web Apps functions can't open
  raw sockets. Send Sentinel events to the Logs Ingestion API through a
  Data Collection Rule. Send Splunk events to HEC JSON. Fix the CEF vendor
  string first (see §6).
- **Effort.** 1.5 to 2 weeks.
- **Dependencies.** P1-1 for a long-running drainer. A Sentinel workspace
  and a Splunk trial for integration tests (OT candidates).
- **Lookout fit.** N/A (platform).

### P2-6. Organisations and client workspaces for MSPs

- **What we'd build.** One organisation with many client workspaces. A
  user's role is set per workspace. Billing is per organisation.
- **Approach.** Decide whether to adopt or drop the orphaned
  `organizations`, `org_members` and `rbac_permissions` tables (034, 035).
  Adopting them means moving every owner-scoped RLS policy to a workspace
  key, which touches every table. Plan it as a staged migration: add
  `workspace_id` alongside `owner`, backfill one workspace per owner, move
  the policies table by table with `rls.db.test.ts` coverage, then remove
  owner-only paths. Map roles to the existing team vocabulary rather than
  inventing a new one. Fold the Partner Portal into it.
- **Effort.** 3 to 5 weeks. It is the largest refactor in this plan.
- **Dependencies.** Owner decision on MSP pricing. It should land before
  SSO (P2-7) so SSO maps to an organisation.
- **Lookout fit.** N/A. It is what makes Lookout resellable by MSPs.

### P2-7. SSO for signing in to HebridesCyber

- **What we'd build.** Sign in with Entra ID (OIDC) and SAML 2.0 for any
  identity provider, with domain-restricted just-in-time provisioning.
- **Approach.** Use Supabase Auth's own SSO support if the owner's Supabase
  plan includes it, because that's our auth platform and not a security
  product we'd be wrapping. Otherwise implement OIDC with Entra and Google
  ourselves as Supabase custom providers. Store any client secret sealed
  (CLAUDE.md rule 20). Drop or fix `sso_providers.client_secret`'s plaintext
  column. Enforce "SSO only" per organisation.
- **Effort.** 1 to 2 weeks.
- **Dependencies.** P2-6. Supabase plan check (OT candidate).
- **Lookout fit.** N/A.

### P2-8. Remediation workflow v2

- **What we'd build.** Assign findings to a team member. A "my findings"
  view. Second-person approval for accepted risk. Two-way ticket sync.
  Extended-tool retest.
- **Approach.** Add `assignee` and `accepted_by_approver` to the triage and
  lifecycle tables. Add an approval state to `findingTriage.ts` that only an
  `admin` can complete. Take inbound webhooks from Jira, Linear and GitHub,
  verified by each provider's signature: "resolved" there enqueues a
  retest, "reopened" reopens the finding. Let `retest-finding.ts` enqueue a
  job that runs only the tool that produced the finding, through
  `resolveToolConfig` with one tool enabled.
- **Effort.** 2 weeks.
- **Dependencies.** P1-1 for extended retests.
- **Lookout fit.** Yes for the workflow. A retest runs the same
  non-intrusive tool that found the issue.

### P2-9. UK compliance packs and estate trends

- **What we'd build.** A Cyber Essentials Plus evidence pack. An NCSC CAF
  mapping. An estate trend view (open risk, new against fixed, time to fix
  by severity over time). SARIF, already approved, ships alongside.
- **Approach.** Add CAF outcomes to `COMPLIANCE_MAP` only where a check
  genuinely evidences one (CLAUDE.md rule 13). Build a CE Plus export from
  `cyberEssentialsReadiness.ts`, the external scan, and the P1-5 device
  data when present, carrying the existing "indicator, not certification"
  disclaimer. Compute trends from `finding_lifecycle`.
- **Effort.** 1.5 weeks, plus 1 to 2 days for SARIF.
- **Dependencies.** P1-5 for the device half of the CE Plus pack.
- **Lookout fit.** Yes.

### P2-10. UK MSP and DevOps ticketing

- **What we'd build.** HaloPSA, ConnectWise PSA, Autotask and Azure DevOps
  Boards as ticket providers.
- **Approach.** Add each to `TICKET_PROVIDERS` and `ticketProviders.ts`
  following the ServiceNow and GitHub pattern, including auto-close and
  P2-8's inbound sync. HaloPSA first, because it is UK-built and common
  among UK MSPs.
- **Effort.** 3 to 4 days per provider.
- **Dependencies.** Partner or sandbox accounts (OT candidates). Read
  CLAUDE.md rule 21 before touching `ticket_integrations`.
- **Lookout fit.** N/A.

### P2-11. A complete public API

- **What we'd build.** Endpoints for targets (create, update, verify,
  delete), assets, findings across the estate, and the audit log, plus a
  published OpenAPI 3.1 document.
- **Approach.** Move target writes behind `/api/v1/targets` with server-side
  validation, closing the direct-browser-write path described in §2.7
  gap 5. Generate the
  OpenAPI file from route schemas and serve it from `/docs/api`.
- **Effort.** 1.5 weeks.
- **Dependencies.** P2-1 for assets. P2-4 for audit.
- **Lookout fit.** N/A.

### P3-1. Wider network and cloud coverage

- **What we'd build.** UDP checks for the top 50 ports. A full TCP sweep on
  opt-in. IPv6 targets. Cloud posture beyond storage: IAM, security groups,
  logging and key management on AWS, Azure and GCP.
- **Approach.** Use naabu's UDP mode or nmap `-sU` against a short list,
  with an integration test. Extend `cloudPosture.ts` check by check, using
  the same read-only, signed-fetch pattern. This is our own check set, not
  a Prowler wrapper, per this document's brief.
- **Effort.** 1 week for UDP and IPv6. 3 to 4 weeks for cloud breadth.
- **Dependencies.** P1-1 (UDP scanning needs a privileged container).
- **Lookout fit.** Yes for discovery and configuration reads.

### P3-2. SCIM 2.0 provisioning

- **What we'd build.** User provisioning and removal from Entra ID or Okta.
- **Approach.** A `/scim/v2/Users` and `/Groups` endpoint per organisation,
  with a bearer token per organisation, mapped to workspace roles.
- **Effort.** 1 to 1.5 weeks.
- **Dependencies.** P2-6 and P2-7.
- **Lookout fit.** N/A.

### P3-3. Customer-run scanner for internal applications

- **What we'd build.** The worker container, run inside a customer's
  network, pulling jobs over HTTPS. This is `docs/COMPETITOR-MATRIX.md` #7,
  restated here because it is the internal half of §2.1 gap 1.
- **Approach.** Reuse P1-5's agent API and token model: claim, submit and
  heartbeat. Results are treated as untrusted. No database credentials
  leave our infrastructure.
- **Effort.** 2 to 3 weeks after P1-5.
- **Dependencies.** P1-5's agent API.
- **Lookout fit.** Yes with the `exposure` profile. It is the same tools
  pointed at an internal target.

---

## 4. Sequence at a glance

| Order | Item | Effort | Unblocks |
|---|---|---|---|
| 1 | P1-1 Always-on workers, fixed IP | 1.5–2 wk | P2-3, P2-5, P2-8, P3-1 |
| 2 | P1-2 Estate "fix first" list | 1–1.5 wk | Lookout report |
| 3 | P1-3 Service CVE matching | 1.5–2 wk | P1-5 |
| 4 | P1-4 Microsoft 365 / Entra posture | 3–4 wk | P2-2 test tenant |
| 5 | P1-5 Device patch-audit agent | 5–8 wk | P2-9 CE Plus pack, P3-3 |
| 6 | P2-4 Customer audit log | 3–4 d | P2-11 |
| 7 | P2-1 Asset inventory v2 | 2–3 wk | P1-2 refinement, P2-3, P2-11 |
| 8 | P2-3 Monitoring v2 | 1.5 wk | |
| 9 | P2-2 Authenticated scanning v2 | 2–3 wk | |
| 10 | P2-8 Remediation workflow v2 | 2 wk | |
| 11 | P2-9 UK compliance packs, SARIF | 1.5 wk | |
| 12 | P2-5 Durable delivery, syslog, Sentinel | 1.5–2 wk | |
| 13 | P2-6 Organisations and workspaces | 3–5 wk | P2-7, P3-2 |
| 14 | P2-7 SSO | 1–2 wk | P3-2 |
| 15 | P2-10 MSP ticketing | 3–4 d each | |
| 16 | P2-11 Complete public API | 1.5 wk | |
| 17 | P3-1, P3-2, P3-3 | as asked | |

P2-4 is small and stands alone, so it can be pulled forward whenever there is
a gap. Total for P1 is roughly 12 to 17 weeks. Total for P2 is roughly 17 to
24 weeks.

---

## 5. Not building

These match `docs/COMPETITIVE-ANALYSIS.md` §9 and `docs/COMPETITOR-MATRIX.md`
("Not worth building"), and are restated so this plan isn't read as
endorsing them:

- **IAST and RASP agents inside customer applications.** They need a
  runtime agent per language, and that deployment model doesn't fit SME
  self-serve.
- **Mobile app testing.** It is a different product category.
- **A proprietary DAST or vulnerability engine to replace ZAP or nuclei.**
  Effort goes into the platform around the engines.
- **24/7 managed detection and response.** That is a headcount problem, not
  a feature (`docs/COMPETITIVE-ANALYSIS.md` §6(c)).
- **Machine-learned risk scoring.** There is no outcome data to train on,
  and SME customers are better served by a ranking they can read (P1-2).
- **Deep IDOR testing by default.** It stays an anti-feature. The bounded
  two-session test remains a Tier A item outside Lookout.

---

## 6. Code issues found during this review

These were found while reading the code for this analysis and are **not fixed
here**, because this was a documentation pass. Each is small enough for its own
change:

1. **The CEF vendor string has a Cyrillic letter.**
   `src/lib/siemIntegration.ts:45` writes `HebridesСyber` where the `С` is
   U+0421 (Cyrillic capital Es), not a Latin `C`. A SIEM rule or parser
   matching vendor `HebridesCyber` won't match our events.
2. **Syslog is offered by the type but not implemented**
   (`siemIntegration.ts:29` and `:130`). A row saved with `type: "syslog"`
   delivers nothing. Check whether the UI can create one.
3. **Migration 064 is taken twice.** Open PR #144's `064_exposure_profile.sql`
   collides with `master`'s `064_target_auth_totp.sql` (see "Work in open
   PRs").
4. **Orphaned tables.** `organizations`, `org_members`, `rbac_permissions`
   and `sso_providers` (migrations 034 to 036) have no code reading or
   writing them. `sso_providers.client_secret` is plaintext. Either adopt
   them in P2-6 and P2-7 or drop them in a migration.

---

## 7. Owner-only steps (candidate OT items)

For the owner to add to `docs/OWNER-TODO.md` if they agree. This session did
not edit that file.

| Needed for | Step |
|---|---|
| P1-1 | Approve Azure spend for an always-on Container Apps Job and a NAT gateway with a static IP. Decide whether to publish the IP. |
| P1-3 | Request a free NVD API key and add it as a repository secret. |
| P1-4 | Create a multi-tenant Entra app registration under the company's Microsoft tenant and complete Microsoft publisher verification. Create a Microsoft 365 developer tenant for testing. |
| P1-5 | Buy a code-signing certificate (Windows), join the Apple Developer Program for notarisation, and decide whether the agent is part of Lookout or a paid add-on. |
| P2-5 | Set up a Microsoft Sentinel workspace and a Splunk trial for integration tests. |
| P2-6 | Decide MSP pricing and whether workspaces are per seat or per client. |
| P2-7 | Confirm whether the Supabase plan includes SAML SSO. |
| P2-10 | Apply for HaloPSA, ConnectWise and Autotask partner or sandbox access. |
| All | Approve this ordering, or re-rank it. |
