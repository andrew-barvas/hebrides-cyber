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

---

## 1. Method, as-of date, refresh procedure

**As of: 2026-08-23.** Competitor cells below carry their own verified-on
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
| **NCSC Web Check + Early Warning** | Free, UK government, credible. For a UK SME, the single most under-rated competitor — "the government already checks this" is a real objection. |
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
| **Hebrides Cyber** | 3 — compliance (CE mapping) + breach scare (score/badge) + dev hygiene (CI gate) + agency reporting (white-label) — internal, `docs/FUNCTIONALITY-MATRIX.md` — 2026-08-23 | 2 — passive suite + extended active-tool suite (scheduled only) + authenticated header/cookie recheck; no crawl-behind-login — internal — 2026-08-23 | 3 — explicit rule in `docs/SCANNER-CONVENTIONS.md` §4, baseline-diffing false-positive machinery in `httpProbe.ts` — internal — 2026-08-23 | 3 — `findingsDiff.ts` New/Fixed + `ScoreTrend.tsx` — internal — 2026-08-23 | 3 — generic → AI-tailored (`ai-fix.ts`) → ticket (`create-ticket.ts`) → merged PR (`generate-fix-pr.ts`, dependency bumps) — internal — 2026-08-23; **note**: no UI entry point for the PR step, see `docs/ENHANCEMENTS.md` E-15 | 3 — CI Action, REST API, webhooks, Slack, Teams, Jira, Linear — internal — 2026-08-23 | 3 — Cyber Essentials + OWASP Top 10 + CIS Controls v8 — internal — 2026-08-23 | 2 — multi-site + white-label; no reseller billing — internal — 2026-08-23; **note**: multi-site is client-gated only, `FUNCTIONALITY-MATRIX.md` §5 | 3 — £20/mo, per-account not per-seat, 1 free scan — `../marketing/03-pricing-page.md` — 2026-08-23 | 3 — one-click scan post-signup, domain-ownership verification required before results (real, not decorative) — internal — 2026-08-23 | 1 — no published methodology page beyond `/what-we-check`, no sample report gallery, no SOC 2/ISO, solo-operator — internal — 2026-08-23 | 1 — self-serve only, no human triage or SLA today — internal — 2026-08-23 |
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

**As of 2026-09-14**, all 20 enterprise competitor gaps identified in the
original competitive audit have been implemented. This is a significant
shift — when §4 was written (2026-08-23), most of these were aspirational.
Updated self-scoring for dimensions affected:

- **D6** stays 3 — now also includes ServiceNow, GitHub Issues, SIEM
  (syslog + webhook), expanded CI/CD SDK, and a GraphQL API endpoint
- **D7** upgraded from 3 → **3+** — now covers 7 frameworks (ISO 27001,
  PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2, DORA)
  with per-control pass/fail reporting, not just finding-level mapping
- **D8** upgraded from 2 → **3** — MSP portal with per-client health
  scoring, RBAC with 4-level role hierarchy, SCIM provisioning, org/workspace
  model, custom scan policies. Still no reseller billing, keeping at 3 not 4
- **D2** stays 2 — scan windows and custom policies add operational
  flexibility but don't change scan *depth* (still no crawl-behind-login)

### Enterprise feature inventory (for competitive positioning)

| Category | Features | Code |
|---|---|---|
| Identity | SSO/SAML, RBAC (4-level), SCIM 2.0, IP allowlisting | `ssoSaml.ts`, `rbac.ts`, `scimProvisioning.ts`, `ipAllowlist.ts` |
| Multi-tenancy | Org model, MSP portal, custom scan policies | `orgModel.ts`, `mspPortal.ts`, `customScanPolicies.ts` |
| Compliance | 7-framework reporting, SLA monitoring, 5-factor risk scoring | `complianceReport.ts`, `slaMonitoring.ts`, `riskScoring.ts` |
| Integrations | SIEM, CI/CD SDK, ServiceNow, GitHub Issues, GraphQL API | `siemIntegration.ts`, `cicdSdk.ts`, `ticketProviders.ts`, `graphqlApi.ts` |
| Scanning | GraphQL scanning, proof-of-exploit, scan windows, scheduled reports | `graphql.ts`, `scanWindows.ts`, `scheduledReports.ts` |

---

## 9. Anti-features — what NOT to build

*Renumbered from §8 after Sprint 9-13 update.*

Pairs with `docs/USER-GUIDE.md` §6 ("what this product deliberately does
not do"). Some competitors' features are deliberately not worth matching:

- **Full crawl-behind-login / IDOR testing** — real value, but turns this
  from an automated scanner into a manual-pentest-adjacent liability surface
  a solo operator can't safely support at scale (false positives on
  business logic are expensive to get wrong, and the legal/consent surface
  gets much larger).
- **Brute-forcing or destructive payloads** — several competitors' "deep
  scan" modes do this; explicitly ruled out here (`docs/USER-GUIDE.md` §6)
  because it risks actually breaking a customer's production site, which is
  a worse outcome than a missed finding.
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
| 5 | **AI/ML vulnerability prioritization** | Qualys TruRisk, Rapid7 InsightVM | ML-trained exploit-likelihood scoring vs `riskScoring.ts`'s rule-based approach. Requires training data from real scan results |
| 6 | **Dark web / threat intel monitoring** | Detectify, Intruder enterprise, Recorded Future | Credential leak monitoring beyond HIBP. High value but needs data partnerships |

### Low priority (enterprise-only, not worth building for SME segment)

| # | Gap | Who has it | Why NOT to build it |
|---|---|---|---|
| 7 | **IAST/RASP** (agent-based interactive testing) | Invicti, Acunetix, Contrast Security | Requires instrumenting the running application — enterprise deployment model incompatible with SME self-serve |
| 8 | **Mobile app security testing** | Probely, Invicti, NowSecure | APK/IPA analysis is a different product category entirely; would dilute focus |
| 9 | **Attack path analysis** | Qualys, XM Cyber, Pentera | Automated attack graph traversal — needs enterprise network complexity to be meaningful |
| 10 | **Autonomous pen testing** | Pentera, NodeZero, Horizon3.ai | AI-agent-driven pen testing. Frontier technology, 12-18 months from SME pricing. Watch space but don't build yet |

### Sprint 15 update (2026-09-14): table-stakes and differentiators closed

The following gaps were closed in Sprint 15 alongside the SBOM/EASM work:

| Item | Status | Notes |
|---|---|---|
| **SBOM generation** (CycloneDX 1.5) | ✅ done | `sbomExport.ts` + `GET /api/v1/scans/{id}/sbom` |
| **EASM discovery** | ✅ done | `easmDiscovery.ts` — crt.sh + DNS brute-force + HTTP probing → `asset_inventory` |
| **Scheduled report delivery** | ✅ done | Was 80% built; `send-scheduled-reports.ts` + hourly cron now sends due reports |
| **Scheduled reports dashboard UI** | ✅ done | `ScheduledReportsConfig` component on dashboard |
| **CVSS badges on findings** (E-55) | ✅ already done | Data flowed through; FindingCard already rendered badges |
| **CSV/JSON download** (E-53) | ✅ already done | Both UI button and API endpoint existed |
| **Score-trend sparklines** (E-52) | ✅ already done | `FleetOverview.tsx` MiniSparkline already rendered |
| **`/sbom` landing page** | ✅ done | SEO page for SBOM compliance searches |
| **`/agencies` landing page** | ✅ done | Conversion page for Agency tier |

Remaining high-priority gap: **CSPM** (E-32, Cloud Security Posture Management)
— sequenced into Sprint 16.

### Competitive positioning after Sprint 15

Hebrides Cyber now has **feature parity or superiority** versus SME-tier
competitors (Intruder, Probely, Beagle, Pentest-Tools) on every dimension
except trust apparatus (D11) and support model (D12) — both of which are
business maturity gaps, not code gaps. The product's enterprise feature set
(SCIM, MSP portal, RBAC, 7-framework compliance, SIEM, SLA monitoring)
exceeds what most SME-priced competitors offer at any tier. With SBOM
generation and EASM now live, the product also leads on regulatory readiness
(EU CRA) and attack surface visibility — both areas where most SME-priced
competitors offer nothing.

The remaining high-priority gap (CSPM) is sequenced into Sprint 16
(`docs/SPRINT-PLAN.md`).

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
