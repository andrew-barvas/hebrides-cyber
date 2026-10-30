# Plan: defensive managed-assessment spin-off ("working name: Lookout")

**Status (2026-10-28):**
- Plan approved by the owner and committed for handover.
- Step 1 is done.
- Step 2: done. Scanner facts are verified against `SCANNER-INVENTORY.md` and the code. The branch was synced with master on 2026-10-28 (`c845963`) and 2026-10-30 (`88c14c5`). Two assumptions in the first draft were wrong and are corrected below (ZAP runs an *active* scan; nuclei's baseline tags include probing templates).
- Steps 3 to 9 have not started.
- Q1, Q1b, Q2 and Q3 were answered by the owner on 2026-10-30 (see "Owner decisions"). Implementation has not started.

## Context

The owner wants a second paid product for HebridesCyber: a managed, defensively framed assessment service built on the existing scanner. It needs:

- a product concept and positioning
- the service workflow
- defensive-safe tool integrations
- a business case
- website-ready copy

It must not include exploitation, payloads or offensive guidance.

This plan is written so another model can pick it up cold. Step 1 commits it to the repo for exactly that reason.

### Facts established from the repo

These are worktree paths on branch `claude/awesome-pentest-defensive-review-ab2b1b` (draft PR andrew-barvas/hebrides-cyber#130).

**Tier A is the offensive tier.** It is gated by the per-target `offensive_scan_authorizations` table in `hebridescyber-app/src/scripts/run-queued-scan-jobs.ts` and hidden from pricing by owner decision on 2026-10-23 ("do not market"; see the comment at `hebridescyber-app/src/app/pricing/page.tsx` L38-42). OT-13 requires PI insurance and a solicitor's ToS review before any offensive traffic.
- **Consequence:** the new product must **not** be sold as "Tier A". It has to be built on the non-intrusive/standard scan pipeline. The brief's phrase "leverages TierA" needs an owner decision (Q1 below).

**Pricing today** (`pricing/page.tsx`):
- Subscriptions: Basic £20/mo, Pro £35/mo, Agency £75/mo.
- One-off audits: £300, £800 and £1,800.
- Billing is **monthly only**. There are no quarterly or annual prices.

**Stripe:**
- Checkout is `hebridescyber-app/src/pages/api/stripe/create-checkout-session.ts`. `PRICE_IDS` maps plans to `STRIPE_PRICE_*` env vars and returns 503 if one is missing.
- Feature gating is in `src/lib/planAccess.ts`. `plan` is free text, so a new plan needs no migration.

**Website:**
- Next.js App Router with Tailwind theme tokens. Use `text-cybertext`, never `text-white`; never run `shadcn init`.
- Landing sections live inline in `src/app/page.tsx` and use a `Card` helper.
- Services are a typed `Service[]` array (`name, icon, desc, includes[], meta?, tag?`) in `src/app/services/page.tsx`. This is the natural home for the new product.
- Nav is in `src/components/Header.tsx` L82-86.
- Marketing copy sources: `marketing/01-homepage-copy.md` and `marketing/03-pricing-page.md`.

**Brand rules** (`marketing/02-branding.md`, `marketing/06-marketing-plan.md`, OT-14):
- Voice: professional, direct, accessible.
- Solo operator: no 24/7, SOC or IR-SLA claims, and no unbuilt features.

**Legal:** `src/app/terms/page.tsx` §2 ("The service") must list the new product, and §4 ("Authorisation to scan") already covers ownership/authorisation warranties.

**Branch is behind master.** It is missing `hebridescyber-app/docs/PRODUCT-IDEAS.md` (P-01 to P-05) and newer edits to `SCANNER-INVENTORY.md`, among others.

### Verified scanner facts (2026-10-28 exploration)

**"Tier A" is a subscription plan, not a set of tools.**
- `src/lib/planAccess.ts:13-23` defines `PlanTier = "pro" | "agency" | "tier_a"`.
- Tools are chosen by **scan profile** in `src/lib/scanProfiles.ts:110`: `safe | full | api | cms | osint | offensive | ai-pentest`.
- `OFFENSIVE_ONLY_TOOLS` (`:103-108`) = contentDiscovery (ffuf), credentialSpray (hydra), strix, cairn.
- Profile resolution and gating:
  - `src/scripts/run-queued-scan-jobs.ts:133-169`, with the offensive gate at `:254-282`.
  - `src/lib/scanExecution.ts:154-896` (`runExtendedTools`), plus the kill switch.

**Of the brief's tools, only nmap and ZAP exist today.**
- **nmap:** `src/worker/tools/nmap.ts`, plus naabu+nmap in `networkExposure.ts`.
- **ZAP:** `src/worker/tools/zap.ts`, as a daemon in `.github/workflows/scheduled-scans.yml:489`.
- **Fingerprinting** is written in-house, Wappalyzer-style (`src/lib/scanners/fingerprint.ts`).
- **Subdomains** come from subfinder plus crt.sh (`src/lib/scanners/subdomains.ts`). **amass was considered and rejected** (`:9`).
- **Not present:** masscan, WhatWeb, OpenVAS/GVM, Nikto, Wapiti.
- **Other tools in use:**
  - httpx, testssl.sh, nuclei, WhatWaf
  - wpscan/cmsmap
  - crawlers: katana, gospider, photon, kiterunner, arjun
  - badsecrets
  - repository scanning: trivy, gitleaks, opengrep, zizmor
  - **sqlmap, commix, dalfox**

**Update after master sync:** `scanProfiles.ts` now has `EXCLUDED_FROM_FULL` (wpscan, cmsmap, photon are held out of `full` because CI cannot verify them). sqlmap, commix and dalfox are **still** in `full`.

**Important:** sqlmap, commix and dalfox (injection testers) run in the **`full` profile**, which is the default for monitored targets (`scanProfiles.ts:117`).
- A "defensive-safe, no payloads" product therefore **must not use `full`**.
- Use `safe`, or a new curated profile/bundle (e.g. `exposure`) that excludes injection and offensive tools. Bundles are in migration `021`; profile overrides are in `scanProfiles.ts`.
- Flag this to the owner too. It affects how the existing scanner itself is described (OT-14).

**Findings model:**
- There is no findings table. Findings are JSON in `scan_results.results`. The `Finding` type is at `src/lib/scanners/index.ts:95-179`.
- Already present: `cveIds`, `cvssScore/Vector` (`cvssEnrich.ts`), `threatIntel` (KEV/EPSS), `complianceRefs` (`compliance.ts:32-47`: Cyber Essentials, OWASP, CIS, ISO 27001 and more), and fix effort.
- **No CWE field, no ATT&CK, no business-impact field.**
- Cross-scan tracking: `finding_lifecycle` (migration 043), triage in `finding_triage` (046).

**Reports:** HTML is built in TypeScript and printed to PDF with Playwright.
- `src/lib/executiveReport.ts:123`, `src/lib/portfolioReport.ts`, `src/lib/complianceReport.ts`, `src/lib/reportPdf.ts`.
- Email: `src/lib/scheduledReports.ts` via Resend.

**Authorisation:**
- Domain verification by DNS TXT or a well-known file (`src/lib/ownership.ts`), enforced at enqueue, at run-scan and in the worker.
- Offensive consent is in `offensive_scan_authorizations` (migration 051), but **no screen calls its route**.

**Scheduling:**
- GitHub Actions cron `scheduled-scans.yml` (enqueue → 3 worker shards → verify job).
- Cadence is in `src/lib/scanCadence.ts`. Since the 2026-10-28 master sync `tier_a` is there (daily, #132), so the old OT-04 gap is closed.

**Prior art:** `docs/SPRINT-PLAN.md:618-635` (H6/H7) sketches a future `pentest.hebridescyber.co.uk` on the offensive tier. `docs/PRODUCT-REVIEW-2026-10.md` calls that tier "vaporware". This product deliberately takes the **non-offensive** route instead.

### Fit with `PRODUCT-IDEAS.md` (read 2026-10-30)

That file is the registry for new products (`P-nn`), with a required template: who pays, problem, what we reuse, what's new, effort, first test, kill criteria. Greenlit ideas become `E-nn` items in `ENHANCEMENTS.md`.

- **Register Lookout as `P-06` there** (IDs are never renumbered) using that template, with status `idea`. This plan stays the detailed design.
- **Overlaps to resolve:**
  - `P-04` (insurance readiness pack) is also an add-on here.
  - `P-05` (agency client workspaces) overlaps with Agency.
  - `P-01` (Kit Watch) is the nearest "managed" idea.
- **First test and kill criteria are mandatory.** Proposed: sell 3 pilot Lookout reviews by hand using the existing scanner and a manually written report. Kill it if fewer than 2 of 5 prospects would pay £149/mo, or if a quarterly report takes more than 4 analyst hours.
- **Prerequisite noted there:** plan checks in the UI must go through `planAccess.ts` (PR #110 was closed unmerged; #132 fixed Tier A access).

## Owner decisions (2026-10-30)

| Q | Decision | What it means for the work |
|---|---|---|
| Q1 | **Add OpenVAS and Nikto now.** | New installs, version pins/SHA-256 and real-binary `*.integration.test.ts` in CI for both (CLAUDE.md rule 15), plus wrappers under `src/worker/tools/`, new `EXTENDED_TOOL_NAMES` keys, and entries in `SCANNER-INVENTORY.md`. See risks below. |
| Q1b | **Move sqlmap, commix and dalfox out of `full`.** | Add them to `EXCLUDED_FROM_FULL` in `src/lib/scanProfiles.ts`. They stay available via `api`, `offensive` and `ai-pentest`. Separate PR from this product. |
| Q2 | **Lookout; Essentials £149/mo, Assured £299/mo**, with the quarterly and annual prices in the plan. | Prices go into copy and Stripe. Name still needs a trademark/domain check (not done). |
| Q3 | **Stripe checkout from day one.** | Owner creates 4 Stripe prices (2 tiers x quarterly and annual, plus monthly = 6) and adds env vars; code changes in `create-checkout-session.ts`, `planAccess.ts`, pricing page and webhook. Billing is monthly-only today, so quarterly/annual is new. |

### Risks created by these decisions (read before starting)

- **OpenVAS on GitHub Actions.** GVM needs a large vulnerability-feed sync, a database and several services, which is heavy for the current ephemeral runners in `scheduled-scans.yml` and slow to start per job. Prototype it first (feed size, time-to-first-scan, runner cost) and, if it does not fit, run it on a small dedicated VM or container and call it from the worker. Decide only after the prototype; do not block the other work on it.
- **Nikto is noisy.** It sends many probe requests and many known-bad test URLs. It must run only on ownership-verified domains, be rate-limited, and be covered by the ToS wording (OT-13, solicitor). It is not injection testing, but it is not passive either; say so accurately in copy.
- **Safe-check configuration.** OpenVAS must use a scan config that excludes destructive and denial-of-service checks, and this must be tested, not assumed. Nikto must exclude its DoS/exploit-related tuning categories. Put both settings in the wrapper, not in a runtime option the customer can change.
- **Stripe before the pilot.** Selling by checkout before the first-test pilot (see PRODUCT-IDEAS fit) removes the cheap demand test. Mitigation: keep the pricing page entry gated by a visible "limited places" cap and a manual onboarding call after payment, and still run the pilot criteria on the first 5 customers.
- **Analyst hours.** Checkout makes it easy to oversell. Enforce the per-tier hour caps and an onboarding limit per month, in the copy and the terms.
- **OT-14.** Every launch claim must match a built, tested feature. Do not publish copy naming OpenVAS or Nikto until their integration tests pass in CI.

## Defensive reference sources (added 2026-10-30)

Four public resources the owner asked to include. They fit different places, so each has a stated home. Rule for all of them: **link to them and map to their IDs; do not copy rule text or scrape them at runtime.** Confirm each licence before reuse (see the last column).

| Source | What it gives | Best fit | How to use it | Licence (verify before reuse) |
|---|---|---|---|---|
| **MITRE ATT&CK** (attack.mitre.org), Techniques | Technique IDs and names, with mitigations and data sources | **Scanner + Lookout reports** | The `attackRefs` map keyed on check ID base (step 5). Examples for exposure findings: T1190 Exploit Public-Facing Application, T1133 External Remote Services, T1078 Valid Accounts, T1595 Active Scanning (as the attacker's view of the exposure). Store ID, name and URL only | Free to use under MITRE's ATT&CK terms of use; keep the attribution |
| **MITRE ATT&CK** Software (attack.mitre.org/software) | Entries for named tools and malware (e.g. mimikatz, Responder, Rubeus, Empire, impacket), each with technique mappings and detection links | **awesome-pentest catalogue**, not the scanner | Post-compromise tooling does not map to an external exposure scan, so it adds nothing to Lookout findings. Use it for the catalogue's deferred step 3: join on tool name, record the `Sxxxx` ID, mark the rest "unmapped" (see `research/awesome-pentest/HANDOVER.md`) | As above |
| **SigmaHQ rules** (github.com/SigmaHQ/sigma) | Vendor-neutral detection rules tagged with ATT&CK and a log source | **Lookout, optional "detection guidance" add-on** (Assured) | Report appendix: for a finding's technique, link to the matching Sigma rules and name the log source the customer would need. Most SMEs have no SIEM, so keep this as a short "what to log" note, not a deliverable | Check the Detection Rule License (DRL) 1.1 terms before quoting any rule |
| **Elastic detection-rules** (github.com/elastic/detection-rules) | Production detections with the telemetry required and ATT&CK tags | **Lookout, same add-on** | Link only. **Do not bundle rule text.** | **Elastic License 2.0**, which restricts offering the content as a hosted or managed service. Treat as link-only unless a solicitor says otherwise |
| **Splunk Security Content** (github.com/splunk/security_content) | Detections and analytic stories with data sources and ATT&CK tags | **Lookout, same add-on** | Link only, for customers who already run Splunk | Check the repository licence before reuse |
| **MITRE CAR** (car.mitre.org) | Analytics tied to techniques and data sources, with pseudocode | **Lookout reports; also useful for the customer's IT supplier** | Use to name the data source a technique needs (e.g. web server logs, firewall logs) in the "what to log" note | Check the repository licence before reuse |

**Where this lands in the build:**
- Step 5: `attackRefs` entries get an optional `detectionLinks` list (URLs to ATT&CK technique, Sigma, Elastic, Splunk and CAR pages), held in the same static map file as the technique IDs. Curated by hand, per **technique** (about 15 to 25 techniques cover the exposure findings), not per tool.
- Step 7: the copy may say "mapped to MITRE ATT&CK" once `attackRefs` ships. It may **not** claim Lookout provides SIEM detections or monitoring.
- Scanner: only the ATT&CK Techniques mapping applies, and only if the owner wants it in the main product's findings too. Add it as a separate `E-nn` in `ENHANCEMENTS.md` if so.
- A quarterly review task: re-check the technique IDs against the current ATT&CK version, since IDs and names change between releases.

## Work ownership (2026-10-30, to avoid duplicated effort)

Several Claude sessions work in this repo. Claim a step here (edit this table in your PR) before starting it.

| Step | Owner | Status |
|---|---|---|
| Plan, copy draft, P-06, OT-33 to OT-36 | awesome-pentest defensive review session (PR #130) | Done |
| `exposure` scan profile, migration, restricted nuclei tags, profile tests | awesome-pentest defensive review session | Not started |
| ZAP passive-only mode | unclaimed | Not started |
| `attackRefs` map and report rendering | unclaimed | Not started |
| OpenVAS prototype, Nikto wrapper | unclaimed | Not started |
| awesome-pentest ATT&CK Software join (catalogue step 3) | unclaimed | Not started |

Known overlapping sessions and PRs: "Lookout managed-assessment plan" (a second session on the same topic; message sent), #139 (stale-docs pass, edits `USER-GUIDE.md`, which #137 also touched), #135 (OT-28 to OT-32, so Lookout uses OT-33 to OT-36). Two idle sessions ("Pentest tools defensive catalogue", "Defensive threat intelligence catalogue builder") started the awesome-pentest catalogue earlier and have no commits; the catalogue under `research/awesome-pentest/` supersedes them.

## Steps

### 1. Commit this plan for handover
- Copy this file to `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md`.
- Commit it to `claude/awesome-pentest-defensive-review-ab2b1b`, push, and add one line to the PR #130 description pointing at it.

### 2. Sync and verify the scanner facts (DONE 2026-10-30)
- Bring the branch up to date with `master` using the ccd_host `sync_with_base_branch` tool. Don't run `git merge` by hand.
- Read `hebridescyber-app/docs/SCANNER-INVENTORY.md`, `hebridescyber-app/CLAUDE.md` ("Tier A offensive scanning") and `docs/PRODUCT-IDEAS.md`.
- Record in the plan doc:
  - which of the brief's tools (Nmap, Masscan, Amass, WhatWeb/Wappalyzer, OpenVAS, Nikto, Wapiti, ZAP passive) already run, and in which tier
  - the findings schema fields (severity, CWE, CVSS, any ATT&CK)
  - where reports are generated

### 3. Classify the tools (goes in the plan doc's integration table)

Grade every tool by **traffic class**, not just "defensive". This matters for the ToS, OT-13 and accurate copy.

Prefer tools that already exist. Only add a new tool where it fills a real gap.

| Tool | Status | Role | Traffic class | Proposed gating |
|---|---|---|---|---|
| subfinder + crt.sh (exists) | Use; it does the job Amass would | External attack-surface / subdomain inventory | Passive (third-party data) | Standard |
| In-house fingerprint + httpx (exists) | Use; it does the job WhatWeb/Wappalyzer would | Technology and version fingerprinting mapped to CVEs | Light active (normal HTTP) | Standard |
| testssl.sh (exists) | Use | TLS configuration weaknesses | Light active | Standard |
| ZAP (exists) | **Not as it stands.** `src/worker/tools/zap.ts` runs a spider **plus a full active scan** (`/JSON/ascan/action/scan/`, L128-142). Needs a new passive-only mode (spider, then read passive alerts, no ascan) before it can go in this product. Until then, exclude | Header, cookie and config weaknesses | Active scan = intrusive; passive-only = light active | Standard once a passive-only mode exists |
| nmap / naabu (exists) | Use | Open-port and service exposure map | Active, non-intrusive | Standard, verified domains/IPs only |
| nuclei (exists) | Use **only with a restricted tag list**. `BASELINE_TAGS` in `src/worker/tools/nuclei.ts:105` is `cve, exposure, misconfig, default-login, takeover, ssrf, oast`. `default-login` tests default credentials and `ssrf`/`oast` send out-of-band callback payloads, so neither belongs here. Needs a code change so the profile can pass its own tag list (e.g. `exposure, misconfig, takeover, cve`) | Known misconfigurations and exposed panels | Active | Standard once the tag list is restricted and the owner has approved it |
| Masscan | **Don't add**; naabu covers it | — | — | — |
| Amass, WhatWeb | **Don't add**; duplicates (amass already rejected in `subdomains.ts:9`) | — | — | — |
| OpenVAS/GVM | Not present; heavy to host on GitHub Actions workers | Network vulnerability detection | Active | Owner decision (Q1); probably a later phase |
| Nikto | Not present | Web-server misconfiguration | Active, noisy | Owner decision (Q1); mostly overlaps nuclei |
| Wapiti, sqlmap, commix, dalfox | Wapiti absent; the other three exist in `full` | Injection testing | **Intrusive: sends test payloads** | **Exclude** from this product |

Notes:
- Each row in the doc also gets "what defenders learn", e.g. "the exposure map shows which services should be firewalled", "fingerprints map to CVEs in the patch list".
- Don't write tool commands or attack detail into the doc or the copy.

### 4. Write the product concept

Target: `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md`, in a section of its own.

**Name:**
- Working name "Lookout by HebridesCyber" (a nod to coastal watch), sold as a "managed exposure review".
- Alternatives for the owner: "Beacon", "Harbour Watch".

**Positioning:** a managed external exposure and configuration review for UK SMEs. A human-written, risk-based quarterly report on top of continuous automated detection. It is **not** a penetration test, and no exploitation is performed.

**Customer:**
- UK SMEs with 10 to 250 staff and no in-house security person.
- Typical triggers: Cyber Essentials, a cyber-insurance questionnaire, or a supplier/customer security questionnaire.

**How it differs from the scanner subscriptions:**
- The scanner is self-serve: dashboard alerts, per site.
- Lookout is managed and organisation-wide:
  - the whole external estate (domains, subdomains and IPs found via Amass)
  - analyst triage and false-positive removal
  - a business-impact report
  - a remediation call
  - re-test of fixes

**Recurring tiers** (proposed prices for owner approval; must fit a solo operator's hours):

| Tier | Monthly | Quarterly | Annual | Includes |
|---|---|---|---|---|
| Essentials | £149/mo | £399 per quarter | £1,490/yr | Continuous automated scans, quarterly analyst report, 30-minute review call |
| Assured | £299/mo | £799 per quarter | £2,990/yr | Monthly report, fix re-test, questionnaire support (Cyber Essentials / insurance), 2 calls per quarter |

**Add-ons:**
- Cyber Essentials readiness pack
- Cyber-insurance evidence pack (this is `P-04` in `PRODUCT-IDEAS.md`; build it there rather than twice)
- Extra IP range
- Board-ready summary
- CI/CD hardening workshop, using the existing £300 offering

Always cap analyst hours per tier and write the cap down.

### 5. Define the service workflow and reporting

**Workflow:**
- **Intake:** signed authorisation (ToS §4), asset list, domain/IP verification, and a contact for alerts.
- **Scoping:** confirm verified assets and exclusions, and set scan windows and rate limits.
- **Automated scanning:** the existing scheduler, with standard-tier tools only.
- **Defensive analysis:** dedup, false-positive triage, and prioritisation by exposure × severity × business impact.

**Report:**
- Executive summary in business-impact language.
- Top risks with plain-English fixes.
- For each finding: severity, CWE/CVE, and a **MITRE ATT&CK technique an adversary could use against this exposure** (e.g. an exposed RDP service maps to T1133 External Remote Services, an outdated public app to T1190 Exploit Public-Facing Application).
  - Map at the **finding-type level**, from a small curated table, citing attack.mitre.org.
  - Don't write per-tool attack mappings.
- Trend versus last period, and a remediation tracker.

**Feedback loop:**
- Assets Lookout discovers become monitored sites in the scanner.
- Triage verdicts (false positive / accepted risk) feed scanner suppression rules.
- Recurring finding types become new automated checks.

**Data model:**
- Add an optional `attackRefs` field (plus optional `cwe` and `businessImpact`) to `Finding` in `src/lib/scanners/index.ts`.
- Fill it in a final enrichment pass keyed on the **base of the `checkId`** (the part before its first `:`), mirroring `compliance.ts` and `fixDifficulty.ts`. Both run in `summariseResults()` and again for extended and cloud findings in `executeScan()`. Put the map in a static file such as `src/lib/scanners/attackMap.ts`.
- Follow the convention in `SCANNER-INVENTORY.md`: a `checkId` with no entry gets no refs, meaning "not yet categorised" or "genuinely doesn't fit", never a forced mapping.
- No SQL migration is needed, because findings are JSON.
- Render the new fields in `executiveReport.ts`.

**New scan profile (`exposure`):**
- Add it to `ScanProfile` and `SCAN_PROFILES` in `src/lib/scanProfiles.ts`. Proposed tools: `subdomains`, `httpx`, `deepTls`, `networkExposure`, `nmap`, and `nuclei` with a restricted tag list. ZAP only once a passive-only mode exists. `safe` already runs the base passive suite on top of these.
- **A SQL migration is needed** (unlike the findings fields). `monitored_targets.scan_profile` and `scan_jobs.scan_profile` have CHECK constraints listing the allowed profiles (`sql/migrations/020_scan_profiles.sql`, widened in `051_offensive_profile.sql:28-34`). Add a new migration that widens both to include `'exposure'`, following the 051 pattern.
- **On-demand scans are always `safe`** (`run-queued-scan-jobs.ts`). Only scheduled jobs use the target's profile or bundle, so Lookout runs on the schedule.
- Cover the new profile with unit tests in `src/lib/scanProfiles.test.ts`:
  - it never enables sqlmap, commix, dalfox, or anything in `OFFENSIVE_ONLY_TOOLS`
  - it never enables `zap` unless the passive-only mode is in
  - `enablesOffensiveTools()` returns false for it
- CLAUDE.md rule 15: any tool in a profile needs a real-binary `*.integration.test.ts` in CI. nmap, zap and arjun have one; real-binary integration tests exist today for nmap, networkExposure (naabu+nmap), httpx (`httpProbe`), nuclei and zap. **deepTls (testssl.sh) and subdomains (subfinder) have none**, so either add tests or leave them out of the first release of the profile.

### 6. Write the business case (in the plan doc)
- **Why SMEs buy it:** compliance and insurance pressure, no in-house expertise, and they want a human answer rather than a dashboard. It is cheaper than a one-off pen test (£800 to £1,800) and it recurs.
- **How it complements the scanner:** it's an upsell path from Pro/Agency and reuses the same pipeline and reports. Scanner customers who outgrow self-serve move to Lookout.
- **Overhead, stated honestly:** automation does the detection, but analyst time is real. Cap the hours per tier, template the reports, and limit how many customers are onboarded per month. Don't claim "zero overhead".

### 7. Draft website copy
- Write the copy to `marketing/17-lookout-managed-exposure-review.md`:
  - landing section (headline, subhead, CTA)
  - a pitch paragraph of 60 to 90 words
  - a features list of 6 to 8 bullets
  - a "Why choose us" section with 3 or 4 cards: local and accountable, engineers who explain, no exploitation or disruption, clear fixed pricing
- Follow the brand voice. Name no tools in customer-facing copy beyond "industry-standard, non-intrusive scanners".
- Keep every claim true to built features (OT-14). Say "not a penetration test" plainly.
- Use the canonical domain `www.hebridescyber.co.uk`.

### 8. Site integration (Q1 to Q3 are decided)
- Add a `Service` entry to `src/app/services/page.tsx`. Q3 chose Stripe checkout, so the call to action is a checkout button, not an enquiry link; keep an "Enquire" link for annual or custom scopes.
- Optionally add a landing `Card` in `src/app/page.tsx`.
- Add the product to terms §2.
- Stripe: add `PRICE_IDS` entries and env vars for each tier and period in `create-checkout-session.ts`, add `lookout_essentials` and `lookout_assured` to the plan type and `planAccess.ts`, handle them in `webhook.ts`, and extend `pricing-checkout.spec.ts`. The owner creates the Stripe prices first (OT item).

### 9. Owner to-dos
Add OT items to `hebridescyber-app/docs/OWNER-TODO.md`:
- approve name and prices
- decide Q1 (gating for OpenVAS and Nikto)
- create the six Stripe prices (monthly, quarterly, annual for each tier) and add the env vars
- solicitor wording for "managed exposure review" in the ToS

## Open questions for the owner

Q1 to Q3 are answered (see "Owner decisions"). Remaining:

- **Q4:** where should OpenVAS run if the Actions prototype does not fit: a small dedicated VM, or a Container Apps job? (Decide after the prototype.)
- **Q5:** is a pilot-first launch acceptable in addition to checkout (first 5 customers get a manual onboarding call and the cap above)?
- **Q6:** has the name "Lookout" been checked for an existing UK trademark and a free domain/subdomain?

## Verification
- Run `npm run lint`, `npm run typecheck` and the unit tests in `hebridescyber-app` after any TSX change. Run `pricing/page.test.tsx` if pricing is touched.
- Check `/services` in a dev preview in light and dark themes and at 375px.
- Review the copy against the OT-14 checklist: every feature claim maps to built code or the documented manual service.
- Grep the new docs and copy for command lines, payload terms or exploit wording. There should be none.
- Confirm the plan doc is on the remote branch and linked from PR #130.
