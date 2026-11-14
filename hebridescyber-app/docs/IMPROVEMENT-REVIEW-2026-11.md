# Improvement review: next tasks, product ideas, platform lessons, UX (2026-11-14)

Written after the 2026-11-14 batch (PRs #219 to #230). It covers the next 10 dev tasks, five ideas per product, what leading security platforms do that we could learn from, and UI/UX fixes found by reviewing the live pages.

**How far to trust it:**
- Competitor features come from a few web searches, mostly vendor pages and review sites, so they are vendor-reported.
- The UI review covered the public pages on a local production build, at desktop and phone widths.
- The signed-in dashboard couldn't be loaded locally, so it was judged from the code.

## Progress and corrections (same day)

Three of these tasks turned out to be partly built already, which the review missed. Status:

| Task | Status |
|---|---|
| 1. Free check on the homepage | #233 |
| 2. Plan through sign-up to checkout | #234, which also fixes an open redirect in `/auth/callback` |
| 3. "Check it's fixed" | Already built (`RetestFindingButton`) but hidden in the collapsed remediation. #235 surfaces it |
| 4. Team accounts | **Already built** (migrations 007 and 025: roles, shared read access, team section). The gap was inviting someone without an account, fixed in #239 |
| 5. Lookout report builder | Design in [`NEXT-BUILDS-DESIGN-2026-11.md`](NEXT-BUILDS-DESIGN-2026-11.md); owner decisions marked |
| 6. Per-host screenshots | #230 captures the scanned page; the estate version is designed in the same file |
| 7. Public profile and badge | #238, which also fixes the existing score badge, previously blocked from loading on other sites |
| 8. Platform fix guides | #236 |
| 9. PoC-in-GitHub | #237. It needs no nightly job or table: one API call lists every CVE |
| 10. Google Workspace checks | Designed in the same file; needs OT-58 |

## Next 10 dev tasks

1. **Make the free check the homepage's main action.**
   - The hero's main button, "Book a free Security Score scan", goes to `/contact`, even though `/check` gives a result in seconds with no sign-up.
   - Put a website box in the hero that runs the check in place, and keep "View services & pricing" as the second button.
   - This is the cheapest conversion gain on the site.
2. **Remove the sign-in dead end at checkout.**
   - `/pricing` tells a signed-out visitor to "sign in or create an account, then come back to subscribe".
   - Instead, carry the chosen plan through sign-up (email link) and land the visitor back in Stripe checkout.
3. **"Check it's fixed" on each finding.**
   - Re-run only the check that produced a finding, on demand, and close it if it's gone, instead of waiting for the next scheduled scan.
   - Intruder and others market this, and it is the moment a small customer feels the product working.
4. **Team accounts with roles.**
   - Owner, member and read-only users on one account, with the audit log the admin panel already has.
   - There is no multi-user model today (`ROADMAP.md` Stage 0), and every agency and most businesses past five staff need one.
5. **Lookout analyst report builder.**
   - The engineer picks findings, writes the commentary, and publishes a dated PDF and portal page that the customer signs off.
   - The service design (`DEFENSIVE-ASSESSMENT-PLAN.md`) depends on this, and nothing builds it yet.
6. **Per-host screenshots for Lookout.** #230 captures the scanned page. Lookout needs one per live web host across the estate, stored as real images rather than inline data, plus an estate gallery in the report.
7. **Public security profile and badge (opt-in).**
   - A customer can publish a page with their current grade, the date of the last check and which controls pass, plus an embeddable badge.
   - UpGuard and Vanta both sell trust pages. For us it is also a marketing loop: every badge links back.
8. **Platform-specific fix guides.**
   - Tailor remediation to the platform the scan detected: WordPress, Shopify, Wix, Squarespace, Microsoft 365 or Google Workspace DNS.
   - Generic advice is where small customers give up. The fingerprint data already exists (`fingerprint.ts`).
9. **Nightly PoC-in-GitHub sync.** It adds a second public-exploit source to #223's Exploit-DB flag. It needs a small table and a nightly job, because the data is one file per CVE in a large repository.
10. **Google Workspace posture checks.**
    - The same consent-based, read-only pattern as `m365Posture.ts`, using CISA ScubaGoggles as the reference (see `M365-POSTURE.md`).
    - Many local businesses use Workspace rather than Microsoft 365.

## Five ideas per product

### Scanner

| Idea | Benefit |
|---|---|
| "Check it's fixed" per finding (task 3) | Instant reward for fixing; fewer stale findings |
| Team accounts and roles (task 4) | Unlocks agencies and larger SMEs |
| Public security profile and badge (task 7) | Trust signal for the customer, free referrals for us |
| Platform-specific fix guides (task 8) | Higher fix rate, fewer support questions |
| "One thing to fix this week" email, from the existing digest and the "fix this first" ranking | Keeps customers engaged between scans; a small, achievable step |

### Lookout

| Idea | Benefit |
|---|---|
| Analyst report builder and customer sign-off (task 5) | The core of the managed service; makes each report repeatable at low cost |
| Estate screenshots and an estate map of hosts, services and certificates | The owner sees their whole footprint on one page, which is the "aha" of an exposure review |
| Leaked-credential monitoring in each report (HIBP domain search, `HIBP_API_KEY`, OT-17) | A leading cause of SME breaches, and checking it sends no traffic to the customer |
| Lookalike-domain watch in the report (tables from migration 053 already exist) | Catches phishing set up against the customer, which they rarely notice |
| Cyber Essentials and insurance evidence pack generated from the report | The "Assured" tier promises help with questionnaires; generating the evidence turns hours into minutes |

### Exploit (governance and delivery only; no attack tooling)

| Idea | Benefit |
|---|---|
| Scoping and authorisation portal: questionnaire, rules of engagement with e-signature, authorised contacts and testing windows | Every test starts with a signed, unambiguous scope, which insurers and solicitors (OT-13) will ask for |
| Live engagement status with a customer stop button (the week-8 engine has abort) | The customer stays in control, which builds trust with first-time buyers |
| Findings delivered as they're confirmed, into Jira, DefectDojo (#222) or SARIF | Fixing starts during the test, not weeks later |
| Retest workflow: the customer marks a finding fixed, a tester verifies it, the report updates | Retests are where buyers feel overcharged elsewhere |
| Attestation letter for insurers and procurement after the retest | The document the buyer actually needs, produced from evidence |

## What leading platforms do that we could learn from

| Platform | What they lead on (vendor-reported) | What we could take |
|---|---|---|
| Aikido | Noise reduction through reachability and context, auto-triage, fix pull requests from findings | Turn on AI triage (`AI_TRIAGE`, off today) once its precision is benchmarked; extend `generate-fix-pr` to more finding types |
| Intruder | Emerging-threat scans within hours of disclosure; notify only when something new is found; one prioritised list across sources; attack-surface view with first-seen dates | We have emerging-threat alerts and "fix this first". Add a "first seen" column and a "notify only on new" setting |
| Vanta | Trust centre with gated documents, and AI-drafted answers to security questionnaires | Public security profile (task 7); later, draft questionnaire answers from scan evidence |
| UpGuard | Trust pages, remediation progress per asset, an executive threat-posture view, customisable AI triage | Remediation progress per site in the portfolio report, plus an executive summary page for the owner |

**Security of our own platform**, from the same comparison. Buyers will expect:
- SSO (SAML, OT-48)
- roles (task 4)
- an exportable audit log
- our own Cyber Essentials and a public `/trust` page with evidence (OT-38 to OT-41)

Today `/trust` exists but has no certification behind it.

## UI and UX fixes from the review

1. **Homepage main button** goes to a contact form instead of the free check (task 1).
2. **Positioning is inconsistent.** The hero says "for SaaS teams and growing businesses", the footer says "for UK small businesses", and most pages talk to small businesses. Pick one primary audience for the hero.
3. **Pricing lists one-off "Full manual pen test" packages** (£300 to £1,800) at the top. Until OT-13 (solicitor and insurance) is done, that sits awkwardly with keeping Exploit unmarketed. This is the owner's decision; `ROADMAP.md` BETA-B3 already flags it.
4. **Signed-out subscribe dead end** (task 2).
5. **Page titles:** `/signup` shows the homepage title. Give every page its own title.
6. **Sign-up email:**
   - Sign-up is email-link only. Supabase's built-in email service is heavily rate-limited, typically a few messages an hour, so a launch day could stall sign-ups.
   - This is the owner's step: custom SMTP for Supabase Auth (OT-57).
   - Consider adding Google sign-in, which `auth.ts` already supports.
7. **Cookie banner on phones** covers the bottom of the page until dismissed. Make it a slimmer bar on small screens.
8. **Dashboard (from the code):** add an estimated time to the "first scan running" state, and bulk triage plus "assign to" on the Findings Explorer once roles exist.

## Sources

- [Aikido Security review 2026](https://thectoclub.com/tools/aikido-security-review/)
- [Aikido release notes](https://releasebot.io/updates/aikido)
- [Intruder emerging threat scanning](https://www.intruder.io/use-cases/emerging-threat-scanning)
- [Intruder changelog](https://feedback.intruder.io/changelog)
- [Intruder container image scanning](https://www.businesswire.com/news/home/20260409802213/en/Intruder-Bolsters-its-Cloud-Security-Offerings-with-the-Release-of-Container-Image-Scanning)
- [Vanta Trust Center](https://www.vanta.com/products/trust-center)
- [Vanta questionnaire automation](https://www.vanta.com/products/questionnaire-automation)
- [UpGuard release notes](https://www.upguard.com/releases)
