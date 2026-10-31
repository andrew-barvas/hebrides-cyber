# Competitive analysis

Scope: automated web-security-scanning SaaS for UK SMEs and agencies. This
compares **Hebrides Cyber the product** against other products and
substitutes that win the same buying decision. For consultancy service-line
market pricing (manual pen tests, IR retainers, compliance advisory), see
`../marketing/09-competitor-services-catalogue.md` — that's a different
question with a different answer, and this file doesn't duplicate it.

For what Hebrides Cyber actually does today (as opposed to what's claimed
below), see `docs/FUNCTIONALITY-MATRIX.md` — every advantage claimed in §5
is checked against that file, not against marketing copy.

For a dimension-by-dimension side-by-side (what each side ships, checked
against the code, plus the gaps a small team could close with its own version),
see `docs/COMPETITOR-MATRIX.md`. It follows the same rule as this file: no
competitor claim without a source and a date.

---

## 1. Method, as-of date, refresh procedure

**As of: 2026-08-23, refreshed 2026-09-27 (§12).** Competitor cells below carry their own verified-on
date; a cell without one has not been independently checked and should be
treated as unverified until it is.

**Refresh procedure** (do this quarterly, or before any pricing/positioning
decision that leans on this doc):
1. For each competitor in §2, load their current pricing page and feature
   page; note the date.
2. Re-score only the dimensions in §3 whose evidence has changed — don't
   re-score everything from memory each time, that's how rubric drift
   happens. Update the cell's evidence line and date.
3. Re-check §6's "structurally unfixable solo" list — a solo-operator
   constraint (no 24/7 team, no formal certs) doesn't change quarter to
   quarter, so this section should be the most stable part of the document.
   If it *has* changed (e.g. a co-founder joins, SOC 2 gets started), that's
   worth flagging explicitly since it unblocks segments §9 currently rules
   out.
4. Anything more than 2 quarters old anywhere in §4 should be treated as
   stale for a pricing decision, even if nobody's gotten round to refreshing
   it — this doc degrading *visibly* (a stale date) is the point; it must
   never be edited to remove a date without re-verifying the claim.

This document should never assert a price or a competitor limitation
without a source and a date attached to the specific cell.

---

## 2. The competitive frame

### Head-on (same product category)

| Competitor | Positioning |
|---|---|
| **Intruder.io** | UK, SME-focused automated vulnerability scanning. The direct competitor — sets both the price ceiling and the credibility bar for this segment. |
| **Probely** | DAST, API-first, developer-shaped. Closest to Hebrides Cyber on CI/API positioning. |
| **Astra Security** | SME scanner + VAPT hybrid, aggressive pricing, strong on the certificate/trust-badge play. |
| **Pentest-Tools.com** | Closest on *price floor*. Tool-menu shaped (pick individual scanners) rather than product-shaped (one score, one report). |
| **Beagle Security** | SME automated DAST, similar price band to Hebrides Cyber. |
| **Detectify** | Has moved upmarket into External Attack Surface Management (EASM). Included as a trajectory reference — where this category tends to go once it has funding — not a head-to-head at today's price point. |
| **Invicti / Acunetix** | Enterprise DAST. A ceiling comparison only — they define what "real DAST" means to a technical buyer, useful for calibrating D2 below, not a segment Hebrides Cyber competes for today. |

### Local, direct competitor (different category, same town)

Found 2026-09-04, not part of the original analysis pass — a real gap, not
a minor omission, given the location match:

| Competitor | Positioning |
|---|---|
| **Closed Door Security** (`cdsec.co.uk`) | Founded in Stornoway — same town as Hebrides Cyber. 15+ years, 1070+ assessments, 320+ clients, CREST-certified, three global offices, NHS/UK-banking/manufacturing client base. Manual/enterprise-assurance pentesting + a PTaaS platform (real-time findings dashboard, on-demand retest booking, live remediation validation loop), not automated SME self-serve scanning — a genuinely different category from the head-on list above, not a rescoring of it. |

This is **not** a company to out-rank on generic "cyber security Stornoway"
search terms as a brand-new entrant — 15 years of backlinks, case studies,
and CREST credibility win that outright. The differentiated lane is the one
already established in §9: automated, affordable, SME/compliance-triggered
self-serve, not enterprise-assurance consultancy — go after long-tail,
differentiated search terms (e.g. "affordable Cyber Essentials scan UK
small business"), not head-to-head on their exact terms. See §6 for how the
account owner's own background changes what's actually reachable here
beyond pure SEO positioning.

### Substitutes that actually win the deal

More relevant than the head-on list for a £20/mo product, because these are
what a UK SME actually compares against, whether or not they think of it as
"a competitor":

| Substitute | Why it wins the deal instead |
|---|---|
| **NCSC Early Warning** (Web Check and Mail Check **retired 31 March 2026**) | Early Warning is still free for UK organisations with a static IP or domain: daily threat alerts and weekly vulnerability/open-port alerts. Web Check and Mail Check, which covered website and email configuration, were retired, and NCSC now tells organisations to use commercial EASM products ([NCSC, retiring Mail Check and Web Check](https://www.ncsc.gov.uk/blog-post/retiring-mail-check-web-check), verified 2026-09-27). "The government already checks this" is no longer true for web and email configuration. See §12. |
| **Free point tools** (SSL Labs, Mozilla Observatory, securityheaders.com, OWASP ZAP, Nuclei) | The direct "why would I pay for this" objection — someone technical enough to ask can assemble a rough equivalent for free. |
| **Snyk / Dependabot / GitHub Advanced Security** | Dependency-side only, but owns the developer's attention and budget line before Hebrides Cyber gets a look. |
| **Cloudflare** (already installed) | Does WAF + basic hygiene; *feels* like coverage even where it isn't equivalent. |
| **The incumbent web agency / MSP** | The existing relationship, and the default answer to "who handles our website security" for a non-technical buyer. |
| **IASME Cyber Essentials assessment bodies** | "We need CE for a contract" is a real UK SME buying trigger, and the assessor's fee is the competing spend, not a security-scanner subscription. |
| **Do nothing** | The most common actual outcome. Any positioning argument that doesn't address this directly is incomplete. |

---

## 3. Rubric — 12 dimensions, scored 0–3

Chosen to be **structural**, not feature-tick or price-based, so this
section doesn't need re-doing every refresh — only §4's cells do.

| # | Dimension | 0 | 1 | 2 | 3 |
|---|---|---|---|---|---|
| D1 | **Buying trigger served** | none identifiable | one trigger, weakly | one trigger, clearly | multiple triggers (compliance + dev hygiene + agency reporting) |
| D2 | **Scan depth ladder** | passive-only | + unauthenticated active | + authenticated recheck | + full crawl-behind-login |
| D3 | **Evidence discipline / FP posture** | no stated policy | claims accuracy, unevidenced | some FP-reduction mechanism | explicit "never report what you can't evidence" + documented mechanism |
| D4 | **Change over time** | one-shot report only | re-scan, no diff | New/Fixed diffing | + trend graphs over time |
| D5 | **Remediation depth ladder** | none | generic advice | stack-tailored advice | + ticket creation + merged PR |
| D6 | **Workflow integration surface** | none | CI gate only | + REST API/webhooks | + chat (Slack/Teams) + ticketing (Jira/Linear) |
| D7 | **Compliance framing** | none | generic "security score" | one framework mapped | multiple frameworks, UK-specific (Cyber Essentials) |
| D8 | **Agency/multi-tenant ergonomics** | single-tenant only | multiple targets, one report style | + white-label | + reseller/billing tooling |
| D9 | **Commercial shape** | enterprise-only, quote-gated | mid-market, annual contract | monthly, per-seat | monthly, per-target, real free tier |
| D10 | **Onboarding friction / time-to-first-value** | sales call required | signup + setup call | signup + manual config | scan within minutes of signup |
| D11 | **Trust apparatus** | none published | a company page | + published methodology, sample reports | + SOC 2/ISO, verifiable company track record |
| D12 | **Support model** | none | self-serve docs only | + human triage | + retainer/SLA |

---

## 4. Scored matrix

Format per cell: **level — evidence — source — verified-on**.

| | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | D11 | D12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Hebrides Cyber** | 3 — compliance (CE mapping) + breach scare (score/badge) + dev hygiene (CI gate) + agency reporting (white-label) — internal, `docs/FUNCTIONALITY-MATRIX.md` — 2026-08-23 | 3 — passive suite + extended active-tool suite (scheduled only) + a real signed-in crawl-behind-login (`authenticatedCrawl.ts`) — internal — 2026-10-12 (score corrected, see §8) | 3 — explicit rule in `docs/SCANNER-CONVENTIONS.md` §4, baseline-diffing false-positive machinery in `httpProbe.ts` — internal — 2026-08-23 | 3 — `findingsDiff.ts` New/Fixed + `ScoreTrend.tsx` — internal — 2026-08-23 | 3 — generic → AI-tailored (`ai-fix.ts`) → ticket (`create-ticket.ts`) → merged PR (`generate-fix-pr.ts`, dependency bumps) — internal — 2026-08-23; **note**: no UI entry point for the PR step, see `docs/ENHANCEMENTS.md` E-15 | 3 — CI Action, REST API, webhooks, Slack, Teams, Jira, Linear — internal — 2026-08-23 | 3 — Cyber Essentials + OWASP Top 10 + CIS Controls v8 — internal — 2026-08-23 | 2 — multi-site + white-label; no reseller billing — internal — 2026-08-23; **note**: multi-site is client-gated only, `FUNCTIONALITY-MATRIX.md` §5 | 3 — £20/mo, per-account not per-seat, 1 free scan — `../marketing/03-pricing-page.md` — 2026-08-23 | 3 — one-click scan post-signup, domain-ownership verification required before results (real, not decorative) — internal — 2026-08-23 | 1 — no published methodology page beyond `/what-we-check`, no sample report gallery, no SOC 2/ISO, solo-operator — internal — 2026-08-23 | 1 — self-serve only, no human triage or SLA today — internal — 2026-08-23 |
| Intruder.io | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Probely | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Astra Security | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Pentest-Tools.com | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Beagle Security | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Detectify (trajectory only) | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |
| Invicti/Acunetix (ceiling only) | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* | *unverified* |

**Competitor rows are deliberately left unscored rather than filled from
memory.** Scoring a competitor without checking their current site is
exactly the kind of unevidenced claim this document's own D3 dimension
penalises — and this product's stated discipline (`docs/SCANNER-CONVENTIONS.md`
§4) is "never report a finding you cannot evidence." An LLM-recalled guess
at Intruder.io's current CI integration or Astra's current pricing tier is
not evidence; it's exactly the kind of claim that goes stale silently and
gets repeated as fact. **Filling in a row is a ~15-minute task per
competitor** (load their pricing + features pages, score against §3's
rubric, cite + date each cell) — do it as a deliberate pass using the
refresh procedure in §1, not as part of a documentation sweep.

---

## 5. Genuine advantages (checked against the code, not marketing copy)

- **Four-rung remediation ladder** (D5=3) — generic text, AI-tailored fix,
  ticket creation with dedupe/auto-close, and a real merged PR for safe
  dependency bumps. Rare below enterprise price points; most SME-tier
  competitors stop at "here's what to fix," not "here's a PR that fixes it."
- **New/Fixed diffing at a £20/mo entry price** (D4=3) — most tools in this
  price band re-report the same findings every scan; the diff is what makes
  a repeat scan worth running.
- **CI gate scoped to newly-introduced findings only** — the packaged
  GitHub Action fails a build only on findings not present in the prior
  scan of that target, specifically to avoid the "red-lines on day one, gets
  disabled" failure mode common to naive CI security gates.
- **Cyber Essentials mapping as a first-class output** (D7=3) — genuinely
  differentiated for the UK SME segment specifically; most of the head-on
  competitor list is US-headquartered and doesn't lead with UK-specific
  compliance framing.
- **Tech-scoped nuclei templates** rather than the tool's full default
  set — narrower, faster, less noisy per scan than a naive integration.
- **Documented evidence discipline** (D3=3) — not just a claim; enforced by
  a written convention (`docs/SCANNER-CONVENTIONS.md`) and concrete
  mechanisms (`httpProbe.ts`'s baseline/catch-all detection).

---

## 6. Genuine disadvantages — three categories

### (a) Fixable by code

- Plan enforcement barely exists (`docs/FUNCTIONALITY-MATRIX.md` §6) — most
  advertised tier differences aren't actually gated.
- No published sample-report gallery or `/methodology` depth beyond
  `/what-we-check` — a code+content task, not a structural one.
- Near-zero observability — can't currently debug a production failure
  after the fact.

### (b) Fixable by money/time, not urgent code work

- No SOC 2/ISO 27001 — meaningful for enterprise trust (D11) but not for
  the SME segment this product actually targets; expensive and slow to
  pursue, and arguably the wrong investment before Beta-stage basics are
  solid (see `docs/ROADMAP.md`).
- No sample-report-driven case studies — needs real paying customers first.

### (c) Structurally unfixable solo (bounds which segments to *not* chase)

**Revised 2026-09-04** — the original version of this section assumed a
generic solo founder with no prior enterprise track record. That's not
accurate here: the account owner has 15+ years SecDevOps/cloud delivery and
transformation at Lockheed Martin and Leidos, plus 15 years in Scottish
public-sector digital transformation delivery. That background doesn't
change the *technical* constraints below, but it directly crosses the
*trust* wall that made them "structural" in the first place — the whole
reason this list existed was that a generic solo operator has no track
record an enterprise or public-sector buyer would credit. This owner
already has one, and specifically in Scottish public sector, which is a
real, narrow advantage neither Closed Door Security's generic UK/global
positioning nor any of the head-on SME-scanner competitors can claim.

- **CREST accreditation** — the technical exams (CPSA → CRT) test hands-on
  offensive/exploitation skill specifically, a different skill from
  delivery/transformation management; still needs real dedicated technical
  prep regardless of this background (see
  `marketing/10-formalisation-and-funding-roadmap.md` §4). **But**
  company-level CREST accreditation (what actually matters for competing on
  tenders) doesn't require the founder personally hold CRT — it requires
  *employing or subcontracting* CREST-certified testers under a documented
  methodology. That's a realistic structure now: this owner's credibility
  drives the sales/delivery relationship, CREST-level testing is
  subcontracted or built out over time. Reclassified from "unfixable" to
  **(b) fixable by money/time** — a genuine near-term roadmap item, not a
  permanently closed door.
- **Enterprise procurement apparatus** (security questionnaires, DPA
  templates, SOC 2) — still real paperwork/process work, but no longer
  blocked on *credibility* to even get in the room; the owner's own
  delivery track record substitutes for the "no track record" problem a
  generic solo founder has. Reclassified to **(b)**.
- **No 24/7 monitoring or MDR** — this one **stays structurally unfixed for
  now**: it's a genuine headcount/coverage problem (someone has to be awake
  at 3am), independent of anyone's credibility or delivery background.
  Partnering it out (`../marketing/09-competitor-services-catalogue.md` §2)
  remains the right answer until there's real headcount.
- **No formal incident-response SLA at scale** — same reasoning as 24/7:
  a retainer for one or two clients is credible now; a general "guaranteed
  response window" product feature still needs headcount, not just trust.

**Revised output of this section**: the SME self-serve/compliance-triggered
positioning in §9 remains correct as the *product's* near-term lane — none
of this changes what `docs/SPRINT-PLAN.md` should build next. But the
*business's* addressable market is wider than "solo indie SaaS" implied:
Scottish public-sector and enterprise-assurance work are realistic
medium-term targets specifically because of who's running this, not just
what the product does. Worth reflecting in
`marketing/10-formalisation-and-funding-roadmap.md`'s HIE funding case
(a founder with this pedigree is a materially stronger funding
application) and in future positioning work — not something to silently
fold into the current sprint's automated-scanner roadmap.

---

## 7. Missing/weak features → enhancement backlog

Every genuine gap identified above or during the production-readiness audit
is tracked with a stable ID in `docs/ENHANCEMENTS.md`, tagged with its §6
category (fixable-by-code / fixable-by-money-time / structurally-unfixable-solo).
Not restated here — see that file for the itemised list, and
`docs/ROADMAP.md` for which of them are sequenced into a stage.

---

## 8. Enterprise features closed (Sprint 9-13 update)

> **Correction (2026-09-27, updated 2026-10-12).** Much of this section
> describes library modules, not shipped features. A check of importers
> found that `ssoSaml`, `rbac`, `scimProvisioning`, `orgModel`, `mspPortal`,
> `customScanPolicies`, `riskScoring`, `cicdSdk`, `graphqlApi` and
> `easmDiscovery` have **no importers outside their own tests**. No page,
> API route or scan step uses them. Do not cite them in sales material or
> score them in §4 until they're wired in. **Update (2026-10-12): `ssoSaml`,
> `orgModel` and `cicdSdk` are now confirmed deleted from `src/` entirely**
> (see `FUNCTIONALITY-MATRIX.md` §5b) — don't cite them even as "unwired",
> they don't exist. **`proofOfExploit` (and the `xssConfirm` it calls) were wired
> into `scanExecution.ts` in PR #11** and are no longer in this unwired
> list. **`easmDiscovery` was wired into `scanExecution.ts` on 2026-10-12**
> (crt.sh on every scan, DNS brute-force gated behind the Tier A offensive
> profile) and is also no longer in this unwired list — see
> `docs/SCANNER-INVENTORY.md` §B3 and `CLAUDE.md` "EASM discovery".
> `ipAllowlist` (per-API-key, 2026-09-27), `complianceReport` (export
> endpoint + button), `slaMonitoring` (`/dashboard/sla`),
> `siemIntegration`, `scanWindows` and `scheduledReports` are live. See
> §12 for the full list.

**As of 2026-09-14**, all 20 enterprise competitor gaps identified in the
original competitive audit have been implemented. This is a significant
shift — when §4 was written (2026-08-23), most of these were aspirational.
Updated self-scoring for dimensions affected:

- **D6** stays 3 — now also includes ServiceNow, GitHub Issues, SIEM
  (syslog + webhook), expanded CI/CD SDK, and a GraphQL API endpoint
- **D7** upgraded from 3 → **3+** — now covers 7 frameworks (ISO 27001,
  PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2, DORA)
  with per-control pass/fail reporting, not just finding-level mapping
- **D8 correction (2026-10-12): stays 2, not 3.** The 3 above credited MSP
  portal, RBAC, SCIM and org/workspace model — all unwired per the
  correction box above, two of them (`ssoSaml`, `orgModel`) now deleted
  outright. The real D8 story is narrower: the shipped, live, Agency-gated
  Partner Portal (`PartnerPortalPanel.tsx`) plus white-labelling — multi-site
  + white-label, no reseller billing, which is exactly a 2 on this rubric.
- **D2 correction (2026-10-12): upgrade 2 → 3.** `authenticatedCrawl.ts`
  now runs a real signed-in crawl (header/cookie/CSP/mixed-content/SRI
  checks across every page it can reach while logged in, not just the
  start page) — this is crawl-behind-login per the D2 rubric. It still
  does not do per-user IDOR data-access testing (§9) or multi-step
  OAuth/MFA login flows (it only replays a saved cookie/Basic credential).

### Enterprise feature inventory (for competitive positioning)

**Do not cite the "Unwired/deleted" rows below in sales material or
competitive positioning** — they are not usable by any customer today.

| Category | Features | Code | Status |
|---|---|---|---|
| Identity | IP allowlisting (per-API-key) | `ipAllowlist.ts` | Live |
| Identity | SSO/SAML, RBAC (4-level), SCIM 2.0 | `ssoSaml.ts`, `rbac.ts`, `scimProvisioning.ts` (all **deleted**) | Deleted |
| Multi-tenancy | Partner Portal (Agency-gated, white-label) | `PartnerPortalPanel.tsx` | Live |
| Multi-tenancy | Org/workspace model, MSP per-client health portal, custom scan policies | `orgModel.ts`, `mspPortal.ts`, `customScanPolicies.ts` (all **deleted**) | Deleted |
| Compliance | 7-framework reporting, SLA monitoring | `complianceReport.ts`, `slaMonitoring.ts` | Live |
| Compliance | 5-factor risk scoring | `riskScoring.ts` (**deleted**) | Deleted |
| Integrations | SIEM, ServiceNow, GitHub Issues | `siemIntegration.ts`, `ticketProviders.ts` | Live |
| Integrations | CI/CD SDK | `cicdSdk.ts` (**deleted** — the real, live CI/CD integration is `public/ci/hebrides-scan.sh`, see CLAUDE.md "CI templates") | Deleted |
| Integrations | Standalone GraphQL schema/query API | `graphqlApi.ts` (**deleted**) | Deleted |
| Scanning | GraphQL vulnerability scanning (wired PR #12), proof-of-exploit (wired PR #11), scan windows, scheduled reports | `scanners/graphql.ts`, `proofOfExploit.ts`, `scanWindows.ts`, `scheduledReports.ts` | Live |

---

## 9. Anti-features — what NOT to build

*Renumbered from §8 after Sprint 9-13 update.*

Pairs with `docs/USER-GUIDE.md` §6 ("what this product deliberately does
not do"). Some competitors' features are deliberately not worth matching:

- **Deep IDOR testing (one logged-in user reaching another's specific
  data)** — real value, but turns this from an automated scanner into a
  manual-pentest-adjacent liability surface a solo operator can't safely
  support at scale (false positives on business logic are expensive to get
  wrong, and the legal/consent surface gets much larger). (A signed-in
  crawl across the authenticated site now does exist — see
  `docs/USER-GUIDE.md` §4.1 / §6 — this is specifically about per-user
  data-access testing, which still isn't attempted.)
- **Brute-forcing or destructive payloads, by default** — several
  competitors' "deep scan" modes do this unconditionally; here it is
  opt-in only, behind the Tier A plan, a per-target written authorisation,
  and a verified domain (`docs/USER-GUIDE.md` §6) — never on by default,
  because it risks actually breaking a customer's production site, which
  is a worse outcome than a missed finding for anyone who hasn't
  explicitly asked for it.
- **Cloud IAM auditing (ScoutSuite/Prowler-style)** — acknowledged gap, but
  building it before a real credential-onboarding-with-consent flow exists
  would mean asking for cloud account access before the product has earned
  that level of trust.

---

## 10. Next-frontier competitive gaps (post-Sprint 13)

With all 20 original enterprise gaps closed, these are the genuine
remaining differentiators competitors have that Hebrides Cyber does not.
Scored by relevance to the SME segment this product actually serves.

### High priority (SME-relevant, realistic to build)

| # | Gap | Who has it | Why it matters for SMEs | Effort |
|---|---|---|---|---|
| 1 | **SBOM generation** (CycloneDX/SPDX) | Snyk, Qualys, most enterprise tools | EU Cyber Resilience Act (effective 2027) will mandate SBOM for software vendors selling into EU. `dependencyManifest.ts` already has the data — needs standards-compliant formatting only | Low |
| 2 | **External Attack Surface Management (EASM)** | Detectify, Rapid7, Qualys, Intruder (new) | Continuous discovery of shadow IT, forgotten subdomains, cloud assets the customer didn't know about. Even SMEs have orphan subdomains. Extends existing `recon.ts`/`subdomains.ts` into a scheduled pipeline | Medium |
| 3 | **Cloud Security Posture Management (CSPM)** | Qualys, Rapid7, Wiz, Orca | AWS/Azure/GCP public S3 buckets, overly-permissive IAM, unencrypted storage. Every SME uses cloud now. Already scoped as E-32 | Medium |

### Medium priority (valuable but less urgent)

| # | Gap | Who has it | Notes |
|---|---|---|---|
| 4 | **Container runtime scanning** | Qualys, Rapid7, Sysdig | Beyond `trivyScan.ts`'s static image analysis to runtime monitoring. Requires Kubernetes access; niche for SMEs |
| 5 | **AI/ML vulnerability prioritization** | Qualys TruRisk, Rapid7 InsightVM | ML-trained exploit-likelihood scoring vs the live rule-based severity scoring (`scoreFromFindings`, `scanners/index.ts`). Requires training data from real scan results |
| 6 | **Dark web / threat intel monitoring** | Detectify, Intruder enterprise, Recorded Future | Credential leak monitoring beyond HIBP. High value but needs data partnerships |

### Low priority (enterprise-only, not worth building for SME segment)

| # | Gap | Who has it | Why NOT to build it |
|---|---|---|---|
| 7 | **IAST/RASP** (agent-based interactive testing) | Invicti, Acunetix, Contrast Security | Requires instrumenting the running application — enterprise deployment model incompatible with SME self-serve |
| 8 | **Mobile app security testing** | Probely, Invicti, NowSecure | APK/IPA analysis is a different product category entirely; would dilute focus |
| 9 | **Attack path analysis** | Qualys, XM Cyber, Pentera | Automated attack graph traversal — needs enterprise network complexity to be meaningful |
| 10 | **Autonomous AI pen testing** | Pentera, NodeZero, Horizon3.ai; open-source: Strix (Apache 2.0), Cairn (AGPL-3.0), Hermes (MIT) | **Reclassified from "watch space" to high priority** — see Sprint 17 update below. Open-source AI pentest agents (Strix, Cairn, Hermes) were chained together in a documented July–September 2026 campaign that compromised 27+ companies at $25.46/target average. SME pricing is already here via the open-source path. Strix (Apache 2.0) is the integration candidate for defensive use |

### Sprint 15 update (2026-09-14): table-stakes and differentiators closed

The following gaps were closed in Sprint 15 alongside the SBOM/EASM work:

| Item | Status | Notes |
|---|---|---|
| **SBOM generation** (CycloneDX 1.5) | ✅ done | `sbomExport.ts` + `GET /api/v1/scans/{id}/sbom` |
| **EASM discovery** | ✅ done (wired into `executeScan` 2026-10-12, see §8's correction note above) | `easmDiscovery.ts` — crt.sh (every scan) + HTTP probing + DNS brute-force (Tier A offensive profile only) → `asset_inventory` |
| **Scheduled report delivery** | ✅ done | Was 80% built; `send-scheduled-reports.ts` + hourly cron now sends due reports |
| **Scheduled reports dashboard UI** | ✅ done | `ScheduledReportsConfig` component on dashboard |
| **CVSS badges on findings** (E-55) | ✅ already done | Data flowed through; FindingCard already rendered badges |
| **CSV/JSON download** (E-53) | ✅ already done | Both UI button and API endpoint existed |
| **Score-trend sparklines** (E-52) | ✅ already done | `FleetOverview.tsx` MiniSparkline already rendered |
| **`/sbom` landing page** | ✅ done | SEO page for SBOM compliance searches |
| **`/agencies` landing page** | ✅ done | Conversion page for Agency tier |

Remaining high-priority gap: **CSPM** (E-32, Cloud Security Posture Management)
— sequenced into Sprint 16.

### Sprint 16 update (2026-09-15): cloud posture scanning + auth hardening

| Item | Status | Notes |
|------|--------|-------|
| **E-21 httpOnly cookie auth** | ✅ done | Already migrated to @supabase/ssr. Fixed middleware location |
| **E-32 Cloud posture (AWS)** | ✅ done | SigV4-signed S3 checks: PublicAccessBlock, BucketPolicyStatus, account-level block |
| **E-32 Cloud posture (Azure)** | ✅ done | Storage public blob access, HTTPS enforcement, TLS version checks |
| **E-32 Cloud posture (GCP)** | ✅ done | JWT-bearer OAuth2 token exchange (no SDK dependency) + GCS bucket checks: Public Access Prevention, uniform bucket-level access, IAM `allUsers`/`allAuthenticatedUsers` bindings |
| **Cloud credentials API** | ✅ done | CRUD at /api/account/cloud-credentials, Agency-plan gated, all three providers |
| **Cloud credentials UI** | ✅ done | CloudCredentialsConfig component on dashboard |
| **Compliance mapping** | ✅ done | 9 cloudPosture.* checkIds (AWS/Azure/GCP) mapped to 7 frameworks |
| **Remediation text** | ✅ done | AWS CLI + Azure CLI + gcloud CLI fix guidance for all 9 check types |

CSPM gap is now **closed for AWS, Azure, and GCP** — the third provider was
completed in a later pass once the credentials-storage side (schema + API
route) had already shipped for GCP; only the GCS-scanning logic itself was
outstanding.

### Competitive positioning after Sprint 16

Hebrides Cyber now has **feature parity or superiority** versus SME-tier
competitors (Intruder, Probely, Beagle, Pentest-Tools) on every dimension
except trust apparatus (D11) and support model (D12) — both of which are
business maturity gaps, not code gaps. The product's enterprise feature set
(SCIM, MSP portal, RBAC, 7-framework compliance, SIEM, SLA monitoring)
exceeds what most SME-priced competitors offer at any tier. With SBOM
generation, EASM, and now **cloud posture scanning (AWS + Azure + GCP)**
live, the product leads on regulatory readiness (EU CRA), attack surface
visibility, and cloud security — areas where most SME-priced competitors
offer nothing. The CSPM gap that was the last major competitive shortfall
is now closed.

No remaining high-priority code gaps after Sprint 16.

### Sprint 16.5 update (2026-09-15): pre-launch polish + competitor table-stakes

Final competitive audit before Sprint 17 (business/launch sprint).
Competitor pricing verified 2026-09-15:

| Competitor | Lowest paid tier | Verified |
|---|---|---|
| **Intruder.io** | $299/mo (Essential) — *superseded, see §12* | 2026-09-15 |
| **Probely** | EUR 98/mo (Pro) | 2026-09-15 |
| **Astra Security** | $69/mo (Scanner) | 2026-09-15 |
| **Beagle Security** | $49/mo (Startup) | 2026-09-15 |
| **Pentest-Tools.com** | $95/mo (Basic) | 2026-09-15 |
| **HostedScan** (new entrant) | $39/mo (Basic) | 2026-09-15 |

**Note**: Crashtest Security was acquired by Veracode (2024) and is no
longer an independent competitor in this segment.

Key emerging industry trends (2026):
- MCP-based auto-remediation agents gaining traction
- **Autonomous AI pentest agents have arrived at SME pricing** — the
  July–September 2026 Strix/Cairn/Hermes campaign (documented by Palo Alto
  Unit 42, Gambit Security, BleepingComputer, SecurityWeek) compromised 27+
  companies and stole 600,000+ payment card records at $25.46/target average
  cost. Open-source tools (Strix: Apache 2.0, Hermes: MIT) make this
  accessible to anyone with an LLM API key. **This invalidates the prior
  "12-18 months from SME pricing" assessment** — the threat is live now, and
  the tools are commercially viable for defensive use. SMEs (online retailers
  especially) are the primary target segment. Hebrides Cyber's existing scan
  suite already covers the vulnerability classes these agents exploit (OWASP
  Top 10, injection, XSS, SSRF, auth bypass, exposed endpoints, outdated
  libraries); Strix integration as a premium tier is the next step — see
  Sprint 18 scope
- NIS2/DORA/CRA compliance becoming table-stakes for EU-selling SaaS

Items closed in Sprint 16.5:

| Item | Status | Notes |
|---|---|---|
| **E-50 Email notifications** | ✅ done | `scanCompletionEmail.ts` + Resend integration |
| **E-51 Notification thresholds** | ✅ done | `notificationRules.ts` — score threshold + severity filter |
| **Notification preferences UI** | ✅ done | `NotificationPrefsSection` on dashboard |
| **Notification preferences API** | ✅ done | `GET/PATCH /api/account/notification-prefs` |
| **Mobile optimisation** | ✅ done | 8 components fixed — responsive inputs, flex-wrap, break-all |
| **Theme bug fix** | ✅ done | `placeholder-white/30` → `placeholder-cybertext/30` across 7 files (19 occurrences) |

Hebrides Cyber at £20/mo now undercuts every head-on competitor by 2-15x
while matching or exceeding their feature sets. The product is
launch-ready. Sprint 17 is a business/launch sprint.

### Sprint 17 update (2026-09-24): AI-agent threat landscape shift

**Major industry event**: the July–September 2026 autonomous AI attack
campaign (Unit 42 / Gambit Security / BleepingComputer / SecurityWeek).
Three open-source tools were chained together by a Chinese-speaking threat
actor:

| Tool | Role in campaign | License | Defensive viability |
|------|-----------------|---------|-------------------|
| **Strix** (usestrix/strix, 43k+ stars) | Autonomous vulnerability discovery — 146 deep scans, 633 hours of scanner time | Apache 2.0 | **Safe for commercial integration** |
| **Cairn** (oritera/Cairn) | End-to-end exploitation — ran autonomously for hours per target until achieving shell/admin access | AGPL-3.0 | **Problematic** — copyleft requirement rules out direct SaaS integration without legal review |
| **Hermes** (NousResearch/hermes-agent) | Orchestrator — 1,951 commands across 260 sessions, coordinated the other two | MIT | **Safe for commercial integration** — general-purpose agent platform, not security-specific |

**Campaign impact**: 27+ companies compromised, 600,000+ payment card
records stolen. Total cost: $12k–$18k in LLM API fees, averaging
**$25.46 per compromised target**. Online retailers and SMEs with web
presence were the primary targets — exactly Hebrides Cyber's customer
segment. Campaign reportedly still active.

**Competitive implications**:
- Gap #10 ("Autonomous pen testing") reclassified from "Low priority /
  watch space" to **"High priority / threat-driven"** — the assumption that
  this was "12-18 months from SME pricing" is falsified
- No head-on competitor (Intruder, Probely, Astra, Beagle, Pentest-Tools,
  HostedScan) offers AI-agent-powered pentesting at SME pricing
- Hebrides Cyber's existing 24+ tool suite already covers the OWASP Top 10
  vulnerability classes these agents exploit — the defensive coverage
  exists; the positioning opportunity is making customers aware of the
  threat and offering Strix-powered validation as a premium tier
- **Strix integration** (Apache 2.0) scoped for Sprint 18 as a premium scan
  profile — adds LLM-powered vulnerability chaining and proof-of-concept
  exploit validation on top of the existing tool suite
- **Cairn excluded** from integration plans due to AGPL-3.0 licensing
- **Hermes** (MIT) scoped as a long-term operational agent (customer-facing
  AI assistant, scan orchestration) — post-launch, depends on Container
  Apps deployment path and customer base justifying the infrastructure

**New marketing assets**: `/ai-threats` landing page, AI-threat-angle cold
outreach template, LinkedIn content series — all leveraging the documented
campaign as compelling, specific, timely sales material for SME buyers.

---

## 12. Refresh — 2026-09-27

Every competitor figure below was read from the vendor's own pricing page
on 2026-09-27. Prices are as displayed, before tax.

### What changed in the market since 2026-09-15

- **NCSC retired Web Check and Mail Check on 31 March 2026** and now
  recommends commercial External Attack Surface Management (EASM) products,
  publishing an [EASM buyer's guide](https://www.ncsc.gov.uk/guidance/external-attack-surface-management-buyers-guide)
  for choosing one ([announcement](https://www.ncsc.gov.uk/blog-post/retiring-mail-check-web-check)).
  This is the most important change for this product. The UK SMEs that
  relied on a free government website and email check now have to buy
  one, and NCSC has written the checklist they'll use. Early Warning
  continues.
- **Intruder** no longer publishes prices. It now has a free tier (weekly
  external scans, 5 web apps, 1 cloud account, 3 users) and sales-led
  Cloud/Pro/Enterprise plans with an AI analyst ("GregAI") and AI
  investigation credits. AI pentesting is sold separately from $3,500 per
  test ([pricing](https://www.intruder.io/pricing)).
- **Beagle Security** raised its entry tier from $49 to **$99/mo**
  (Essential: 2 tests/month, authenticated testing, LLM-based reports;
  Advanced $299/mo adds API/GraphQL, compliance reports, Slack/Teams,
  branded reports). Its free tier includes SSL and **domain expiry**
  tracking ([pricing](https://beaglesecurity.com/pricing)).
- **Probely is now Snyk API & Web.** Snyk acquired Probely and sells its
  DAST inside Snyk's developer-seat pricing
  ([Snyk announcement](https://snyk.io/news/snyk-acquires-developer-first-dast-provider-probely/)).
  The "EUR 98/mo" row in §10 no longer describes a product you can buy.
- **Astra** now sells an autonomous "Pentest Auto" at $199/mo per target
  alongside its scanner ($69/mo Lite, one target, three scans a month)
  ([pricing](https://www.getastra.com/pricing)).
- **HostedScan** is unchanged at $39/mo for 5 targets, built on open-source
  scanners (Nmap, SSLyze, ZAP, OpenVAS, Nuclei). Authenticated scans start
  at $109/mo and white-label at $189/mo ([pricing](https://hostedscan.com/pricing)).
- **Pentest-Tools.com**: from $95/mo (NetSec, billed yearly), $140
  (WebNetSec, full DAST + authenticated) and $190 (Pentest Suite)
  ([pricing](https://pentest-tools.com/pricing)).
- **Detectify**: €0 Starter platform fee, then €2,500 / €5,000 / €15,000
  a year plus per-asset charges for surface monitoring, application and
  API scanning ([pricing](https://detectify.com/pricing)).

### Verified snapshot

| | Entry paid price | Free tier | Authenticated web scanning | Attack-surface discovery | Cloud posture | White-label |
|---|---|---|---|---|---|---|
| **Hebrides Cyber** | £20/mo (Basic) | 1 scan | Header/cookie recheck behind a credential only (not a crawl) | CT-log subdomains, dangling-DNS check; no continuous inventory yet | AWS/Azure/GCP storage (Agency) | Agency £75/mo |
| Intruder | not published | yes (5 web apps, weekly) | Cloud plan and up | Enterprise ("shadow IT discovery") | 1 account free, 3 on Cloud | not listed |
| HostedScan | $39/mo | not listed | $109/mo | "attack surface mapping" on Basic | integrations (AWS, Azure) | $189/mo |
| Beagle Security | $99/mo | 1 lite test/month | yes, $99/mo | "application discovery" | no | $49/report add-on |
| Astra | $69/mo (1 target) | no | yes, all tiers | not listed | from $99/mo | not listed |
| Pentest-Tools.com | $95/mo (yearly) | up to 5 assets | $140/mo | recon tools, $95/mo | $95/mo | not listed |
| Detectify | €2,500/yr + per asset | Starter platform, assets paid | yes | core product (surface monitoring) | no | €5,000/yr |

Hebrides Cyber remains the cheapest paid entry point by a wide margin. The
real depth gap versus every paid competitor is **authenticated crawling
and scanning** (D2); see §9 for why it's deliberately out of scope for now.

### The NCSC EASM checklist, mapped to what actually ships

Categories from NCSC's buyer's guide. "Live" means a page, route or scan
step uses it today, not that a library exists.

| NCSC category | Status | Where |
|---|---|---|
| Asset discovery (domains, subdomains, IPs) | Live | CT-log subdomains (`recon.ts`, `easmDiscovery.ts` — wired into `executeScan` 2026-10-12), Shodan InternetDB |
| Technology identification | Live | `fingerprint.ts` (40+ technologies) |
| Service identification | Live | `ports.ts`, Shodan; `nmap` in the scheduled suite |
| DNS configuration | Live | `dns.ts` |
| Web presence (screenshots, page parsing) | Partial | `playwright.ts` page health; no screenshots |
| TLS certificate monitoring | Live | `tls.ts`, `deepTls.ts` |
| Supplier / external dependencies | Partial | SRI on cross-origin scripts; no third-party script inventory yet |
| Email security (SPF, DMARC, MTA-STS) | Live | `dns.ts` (SPF, DKIM, DMARC, MTA-STS, TLS-RPT). No DMARC aggregate-report processing, which Mail Check did |
| DNS security / domain takeover | **Live, new** | `takeover.ts` (2026-09-27) |
| Exposed services | Live | `ports.ts`, `exposure.ts`, `directoryListing.ts` |
| Vulnerability assessment | Live | passive suite on every scan; active suite on scheduled scans |
| Threat-intelligence correlation / likelihood ranking | **Live, new** | `threatIntel.ts`: CISA KEV + FIRST EPSS (2026-09-27) |
| Workflow (comments, status tracking) | Partial | ticketing with dedupe/auto-close; no in-app accept-risk or false-positive state |
| Historical trending and comparison | Live | New/Fixed diffing, score trends, SLA time-to-fix |
| Reports and raw exports | Live | PDF, CSV/JSON, per-framework compliance export |
| SIEM / ticketing integrations | Live | SIEM forwarding; Jira, Linear, ServiceNow, GitHub Issues |
| Cloud / asset-database connectors | Partial | cloud storage posture (AWS/Azure/GCP) |
| Configurable risk prioritisation | Partial | per-account SLA targets; no ML/5-factor scoring beyond the live severity scoring |
| Hierarchical access control | Partial | team members (`teamAccess.ts`); no formal RBAC permission matrix |

### Built in this refresh

- **CISA KEV + FIRST EPSS on every CVE-backed finding** (`threatIntel.ts`).
  Findings get an "Actively exploited" badge, ransomware use and an EPSS
  likelihood, and are sorted first within their severity. The same data
  appears as `threat_intel` in the API and as CSV columns. Severity is
  never changed. This answers NCSC's "how are findings ranked by
  likelihood?" with the two public standards rather than a proprietary
  score.
- **Dangling DNS / subdomain takeover detection** (`takeover.ts`). It
  covers the site and every CT-log subdomain across 15 provider patterns,
  and reports only when the provider proves the resource is gone. It runs
  on every scan, including the free one. In most competitors this sits
  inside a paid EASM tier.
- **Domain registration expiry and transfer lock** (`domainRegistration.ts`,
  RDAP). This matches the one free-tier feature Beagle had that we didn't,
  and covers the outage that takes down both website and email.
- Earlier the same week: remediation SLAs, the per-framework compliance
  export, per-API-key IP allowlists, and ServiceNow + GitHub Issues
  ticketing.

### Next candidates, in value order

1. **Position as the NCSC Web Check / Mail Check replacement** (marketing,
   not code). A landing page that maps the retired checks and the EASM
   checklist to our coverage, honestly including the "Partial" rows above.
   Of everything here, this is the most time-sensitive.
2. **Third-party script inventory and change alerts.** List every external
   script source per page and alert when a new one appears. This covers
   NCSC's "external dependencies" and PCI DSS v4.0.1 requirements 6.4.3
   (script inventory and authorisation on payment pages) and 11.6.1
   (change and tamper detection). Most SME scanners have nothing here. It
   needs a decision on how a "new since last scan" finding resolves, so
   it doesn't read as "fixed" a scan later.
3. ~~**Wire `easmDiscovery.ts` into the scheduled pipeline**~~ done
   2026-10-12 — it runs per scan (`executeScan`), not yet on an independent
   schedule; a fully schedule-decoupled version is still a possible later step.
4. **Finding workflow state**: accept-risk, false-positive and snooze,
   each with a reason and expiry. Intruder, HostedScan and NCSC's
   checklist all expect it. Accepted findings would pause SLA clocks.
5. **Lookalike-domain monitoring.** Generate typo and homoglyph
   permutations of the domain and flag registered ones, especially those
   with MX records (phishing-capable). It's passive DNS only.
6. **DMARC aggregate-report processing**, the part of Mail Check that
   `dns.ts` doesn't replace. It's the heaviest item on this list: it
   needs an inbound report mailbox and parsing.
7. Fix the passive-scan-after-full-scan diff so active-tool findings aren't
   reported "fixed" (spawned as its own task). It affects ticket
   auto-close, not just SLA.

**Update 2026-10-05.** Items 1, 2 and 4 are done (E-61, E-62, E-64). From a
Snyk/Intruder comparison (2026-10-01) we also shipped emerging-threat alerts
(Intruder's "emerging threat scans", E-68), lockfile + transitive dependency
scanning with a full CycloneDX SBOM (Snyk Open Source parity, E-67) and SAST
with Opengrep and our own rule pack (E-69; Semgrep's maintained rules can't be
used in a commercial SaaS). Snyk's free tier covers 5 projects and Team starts
at $25/month; its DAST, secrets and AI agent products are Enterprise-only.
Remaining gaps against industry-grade scanners, in priority order, are tracked
as E-70 to E-74 in `docs/NEXT-STEPS.md`: a site crawler (most checks still see
only the homepage), PR dependency checks, the sqlmap/xsser fixes, a measured
accuracy benchmark, and a cross-site findings view. Items 3, 5, 6 and 7 above
remain open.

The Sprint 17 section's claims about a specific 2026 attack campaign were
not re-verified in this refresh. Cite the primary sources directly before
reusing them in marketing.

---

## 11. Positioning conclusion

*Renumbered from §9 after Sprint 9-13 update.*

Hebrides Cyber's honest position is **the developer-and-agency-friendly
automated scanner for UK SMEs who have a compliance trigger (Cyber
Essentials, procurement) or a dev-hygiene habit (CI, GitHub) but no
security budget for a human pentest** — not a challenger to enterprise DAST,
not an MDR provider, and not (yet) a trust-apparatus-first buy for a
risk-averse enterprise buyer. The product's genuine structural advantages
(remediation ladder, diffing, CI-gate-on-new-findings, CE mapping) all serve
that exact buyer; the genuine gaps (plan enforcement, observability, trust
apparatus) are the right things to fix before trying to move upmarket, not
before trying to serve that buyer better.
