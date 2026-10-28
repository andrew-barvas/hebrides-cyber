# Plan: defensive managed-assessment spin-off ("working name: Lookout")

**Status (2026-10-28):**
- Plan approved by the owner and committed for handover.
- Step 1 is done.
- Step 2: scanner facts are verified (below). The branch was synced with master on 2026-10-28 (merge `c845963`); `PRODUCT-IDEAS.md` and the newer `SCANNER-INVENTORY.md` are now available to read, which is still to do.
- Steps 3 to 9 have not started.
- Q1 to Q3 are still open with the owner.

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

## Steps

### 1. Commit this plan for handover
- Copy this file to `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md`.
- Commit it to `claude/awesome-pentest-defensive-review-ab2b1b`, push, and add one line to the PR #130 description pointing at it.

### 2. Sync and verify the scanner facts
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
| ZAP, passive rules only (exists) | Use; confirm no active-scan rules run in the new profile | Header, cookie and config weaknesses | Light active | Standard |
| nmap / naabu (exists) | Use | Open-port and service exposure map | Active, non-intrusive | Standard, verified domains/IPs only |
| nuclei (exists) | Use with exposure/misconfig/tech tags only; exclude intrusive tags | Known misconfigurations and exposed panels | Active | Standard, with an owner check on the tag list |
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
- Cyber-insurance evidence pack (links to PRODUCT-IDEAS P-04)
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
- Fill it in a final enrichment pass keyed on `checkId`, mirroring `src/lib/scanners/compliance.ts` with a static map file such as `src/lib/scanners/attackMap.ts`.
- No SQL migration is needed, because findings are JSON.
- Render the new fields in `executiveReport.ts`.

**New scan profile:**
- Add an `exposure` profile to `scanProfiles.ts`: `safe` + network exposure + testssl + nuclei (non-intrusive tags) + ZAP passive.
- Add unit tests asserting it never enables sqlmap, commix, dalfox, or any `OFFENSIVE_ONLY_TOOLS`.

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

### 8. Site integration (only after owner approval of Q1 to Q3)
- Add a `Service` entry to `src/app/services/page.tsx`, with "Enquire" pointing to `/contact`. No Stripe checkout yet.
- Optionally add a landing `Card` in `src/app/page.tsx`.
- Add the product to terms §2.
- Quarterly and annual Stripe prices plus `PRICE_IDS` entries become a later step: they need owner-created prices (an OT item in `hebridescyber-app/docs/OWNER-TODO.md`).

### 9. Owner to-dos
Add OT items to `hebridescyber-app/docs/OWNER-TODO.md`:
- approve name and prices
- decide Q1 (gating for OpenVAS and Nikto)
- create the Stripe prices
- solicitor wording for "managed exposure review" in the ToS

## Open questions for the owner
- **Q1:** Should OpenVAS and Nikto be added at all (neither exists today), or deferred? Injection testers (Wapiti, sqlmap, commix, dalfox) are excluded in either case.
- **Q1b:** sqlmap, commix and dalfox run in the default `full` profile of the existing scanner. Is that intended, given the copy and OT-13? This is separate from the new product, but it was found during this work.
- **Q2:** Do you approve the working name and price points, or want alternatives?
- **Q3:** Should it launch as enquiry-only (recommended), or with Stripe checkout from day one?

## Verification
- Run `npm run lint`, `npm run typecheck` and the unit tests in `hebridescyber-app` after any TSX change. Run `pricing/page.test.tsx` if pricing is touched.
- Check `/services` in a dev preview in light and dark themes and at 375px.
- Review the copy against the OT-14 checklist: every feature claim maps to built code or the documented manual service.
- Grep the new docs and copy for command lines, payload terms or exploit wording. There should be none.
- Confirm the plan doc is on the remote branch and linked from PR #130.
