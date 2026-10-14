# Hebrides Cyber — independent platform review

**Date:** 2026-10-14 · **Reviewed at commit:** `8e485bd` (origin/master) ·
**Lenses:** security architect · SaaS product reviewer · cyber consultant · UX
specialist · technical author · product owner.

This is a deliberately critical review of Hebrides Cyber as a candidate successor
to the retired NCSC Web Check. It is written from the **source code** (the arbiter
is [`FUNCTIONALITY-MATRIX.md`](FUNCTIONALITY-MATRIX.md), which is maintained from
code not marketing), cross-checked against the live site and the project's own
strategy docs. It keeps this folder's standing rule: describe reality, including
what is broken or unwired. Visual companions: [`architecture.md`](architecture.md),
[`DATA-MODEL.md`](DATA-MODEL.md), [`diagrams/`](diagrams/README.md).

> **Methodology & caveats.** Findings are evidence-based with file paths. Several
> dashboard pages are client-rendered and were not visually walked for this pass;
> an in-browser accessibility (axe/pa11y) and UX walkthrough is a recommended
> follow-up (Phase 5). "Severity" on platform findings uses the usual
> critical/high/medium/low; product ratings use Excellent/Good/Adequate/Weak/Missing.

---

## Executive verdict

**Strong engineering, over-reaching commercial story, a handful of real security
defects to close.** The scanning engine and platform are genuinely good and ahead
of their stage: ~40 passive checks + ~27 real external-tool integrations, RLS
tenant isolation backed by a real-Postgres RLS test suite, a four-rung remediation
ladder, New/Fixed diffing, SLA + triage, 7-framework compliance mapping, SBOM,
in-house SAST rules, and KEV/EPSS/NVD/OSV enrichment — at 2–15× below competitor
entry prices. The discipline ("never report a finding you can't evidence", a
ratcheted coverage floor, a real RLS test suite) is better than most funded
startups.

The critical issues are specific and fixable:

| # | Headline risk | Type |
|---|---|---|
| 1 | **Cannot take payment** — `STRIPE_PRICE_*` unset; prod `/api/health` → `stripe:false` (E-07). | Existential (commercial) |
| 2 | **Grant applications over-claim deleted/unwired features** (SSO/SAML, RBAC, SCIM, MSP portal) to public funders. | Integrity / legal |
| 3 | **Cloud credentials stored plaintext** in a column named/documented `credentials_encrypted` (S-1). | High (security) |
| 4 | **SSRF guard bypasses** + unrestricted scanner-runner egress (A-1). | High (security) |
| 5 | **"Autonomous AI pen-test" tier is vaporware** (Strix/Cairn never run; `ai-pentest` profile unreachable). | High (over-claim) |
| 6 | **Risk score is a flat severity tally** that floors at 0, despite CVSS/EPSS/KEV enrichment. | Medium (credibility) |
| 7 | **No true multi-tenant/MSP mode, no sign-up page, no password reset.** | Medium (product) |
| 8 | **Documentation drift** is the mechanism by which over-claims propagate. | Medium (governance) |

**Readiness:** closer to "beta that can't bill" than "launch-ready." The single
highest-value *non-code* action is aligning external claims with the (excellent,
honest) internal reality.

---

## Phase 1 — Product discovery

### Feature inventory
Scanning engine (base passive + extended active tools), dashboard (overview/scans/
assets/findings/SLA/integrations), two-step-ownership scan workflow, reporting
(on-page + Executive PDF + CSV + compliance export + remediation pack), remediation
ladder, triage, scheduled/recurring scans, trends/diffs, API + keys + webhooks +
GitHub Action + CI templates, Slack/Teams/Jira/Linear/ServiceNow/GitHub Issues/
PagerDuty/Opsgenie, SIEM forwarding, white-label PDF, portfolio report, admin
panel (now incl. **real MRR/revenue/churn, usage-cap visibility, per-tool kill
switches, structured audit filtering, GDPR deletion-request queue, email
deliverability** — merged in `#44`–`#49`), CMS blog/newsletter + RSS, monitoring
(emerging-threat, attack-surface, lookalike-domain).

### Capability map & ratings

| Area | Rating |
|---|---|
| Passive web/TLS/DNS/email scanning | Excellent |
| Supply-chain / dependency / SBOM / SAST | Excellent |
| Threat-intel enrichment (KEV/EPSS/NVD/OSV) | Excellent |
| Remediation workflow (AI/ticket/PR/retest/triage/SLA) | Excellent |
| Reporting (exec PDF, compliance, trends, diff) | Good |
| Admin observability (post `#44`–`#49`) | Good |
| Cloud posture (storage, 3 clouds) | Good |
| Active DAST (ZAP/nuclei/sqlmap) | Good |
| Network scanning | Adequate |
| Auth journeys | Adequate |
| CMS | Adequate |
| Observability (prod error visibility) | Weak |
| Multi-tenancy / MSP / orgs | Weak |
| Dark-web / breach monitoring | Weak |
| Continuous EASM inventory | Weak |
| Offensive / AI-pentest tier | Missing (vaporware) |

### User journey map
Home → Services/Pricing/What-we-check → Contact **or** Login (magic-link/password +
MFA) → Dashboard → verify domain (DNS TXT / file) → run scan → report → remediate/
triage → subscribe **(blocked)**. Gaps: no sign-up page, no password reset,
subscribe dead-ends at Stripe 503, one-off audits are contact-only.

### Architecture assumptions (validated)
Single Next.js surface on Azure SWA (pages + API Functions); Supabase Postgres/Auth/
Storage with RLS; Postgres job queue drained by GitHub Actions runners (scans can't
run on SWA Functions — no shell/binaries); service-role key server-only. See
[`architecture.md`](architecture.md).

### Missing functionality vs the NCSC-replacement checklist

| Expected capability | Status |
|---|---|
| Attack Surface Management | Partial (per-scan `easmDiscovery`, no standalone pipeline) |
| Continuous monitoring | Yes |
| CVE enrichment NIST/NVD | Yes |
| Remediation tracking workflow | Yes |
| Security posture scoring | Weak (flat tally) |
| Supplier risk assessment | Partial (typosquat + script inventory) |
| External attack-surface inventory | Partial |
| Executive board reporting packs | Partial (exec + portfolio PDF; no board template) |
| PCI/GDPR/Cyber-Essentials reporting | Yes |
| Cyber Essentials self-assessment | Missing (mapping only) |
| Dark-web breach monitoring | Weak (HIBP domain only) |
| DNS takeover detection | Yes |
| Certificate Transparency monitoring | Yes |
| Website change detection | Partial (script/DNS/hostname, no page diff) |
| Email security monitoring | Yes, minus DMARC aggregate reports |
| Security-header monitoring | Yes |
| API security testing | Partial |
| AI-assisted remediation | Yes |
| Multi-tenant MSP mode | Missing |
| Customer portal for consultancies | Weak |
| Scheduled/recurring scans | Yes |
| Trend dashboards | Yes |
| Security benchmarking vs peers | Missing |

---

## Phase 2 — Functional audit

**Incomplete / stub (fix or stop advertising):**
- **Offensive tier** — `strix.ts`/`cairn.ts` wrap binaries that don't exist at
  pinned versions and have never run; `credentialSpray` unverified; `ai-pentest`
  profile unreachable (DB CHECK + UI exclude it).
- **Scheduled-report PDF** — API accepts `format:"pdf"` but the sender only emits
  CSV/JSON; content is a counts table; route not plan-gated server-side.
- **CMS SEO fields** — editor collects + public page renders `meta_description`/
  `og_image`, but neither `POST` nor `PATCH` persists them → **silently dropped**
  (`src/pages/api/admin/blog.ts`, `blog/[slug].ts`). Real bug.
- **Google OAuth** — `signInWithGoogle()` exists, no UI, provider disabled.
- **SIEM** — real and pipeline-wired but no UI, absent from the Integrations page.
- **Risk score** — flat `100 − Σ(weights)`, floors at 0 (`scoreFromFindings`).

**Duplicate / low-value / debt:** `generate-fix-pr` has no UI entry point (E-15);
nmap scans 13 ports but only 6 can emit a finding; `whatwaf` confidence hardcoded;
ZAP API key literal `changeme` in a workflow; nine enterprise "modules" were built
then deleted as unwired (healthy cleanup, but a build-ahead-of-need signal).

**Prioritised improvement backlog:** see the consolidated table at the end.

---

## Phase 3 — Vulnerability-scanner review

### Capability vs the field

| Area | Hebrides | NCSC Web Check (historic) | SME peers (Intruder/Astra/Beagle/Detectify) | Enterprise (Qualys/Tenable/Rapid7/Acunetix) |
|---|---|---|---|---|
| TLS/headers/DNS/email config | Strong (exceeds Web Check) | Core | Comparable | Comparable |
| Subdomain / CT discovery | Good (passive) | Partial | Good | Strong |
| Continuous EASM inventory | Partial | No | Detectify strong | Strong |
| Authenticated DAST / IDOR | Crawl + header/cookie; **no per-user IDOR** | No | Yes (paid) | Yes |
| Network / port / service ID | Adequate | No | Varies | Strong (agents) |
| Cloud posture (CSPM) | Storage only, 3 clouds | No | Varies | Strong (full IAM) |
| Dependency / SBOM / SAST | Strong | No | Varies | Strong |
| CVSS/EPSS/KEV enrichment | Strong data, **weak scoring** | No | Varies | Strong |
| Remediation (PR/ticket/AI) | Strong | No | Rare | Varies |
| Compliance reporting | Strong (7 frameworks) | No | Varies | Strong |
| IAST / RASP / agent-based | No (by design) | No | No | Yes |

**Coverage ratings:** Discovery Good · Web-app Good · Network Adequate · Cloud
Adequate/Good · Config (SPF/DKIM/DMARC/HSTS/TLS/cert) **Excellent** · Reporting
Good (scoring Weak).

### Materially-missing areas (justification · value · priority · approach)
- **CVSS-weighted risk score** — boards/enterprise expect defensible, comparable
  scores; floor-at-0 is indefensible. *P1.* Compute from weighted CVSS × EPSS × KEV
  with diminishing returns; keep severity (evidence) separate from score (risk).
- **Continuous EASM inventory** — NCSC's own EASM buyer's guide is the checklist
  ex-Web-Check users apply. *P2.* Decouple `easmDiscovery.ts` into its own schedule
  + asset dashboard + change feed.
- **DMARC aggregate-report processing (E-66)** — the one Mail Check function
  `dns.ts` doesn't replace. *P2.* Inbound RUA mailbox + parser + per-domain view.
- **CSPM depth (IAM/encryption)** — *P2–P3*, only after a consented cloud-credential
  flow and the S-1 encryption fix.
- **Peer benchmarking** — *P3*, anonymised cohort percentiles once ≥1,000 real scans.

---

## Phase 4 — CMS review

| Capability | Status |
|---|---|
| Page / blog / news management | Good (one `blog_posts` table, slug-prefixed) |
| Draft / publish / schedule | Good (draft/published/scheduled, hourly cron); no multi-stage approval |
| Categories / tags | Weak (tags only, no taxonomy) |
| SEO (meta/sitemap/OG/structured data) | Weak — sitemap/robots/OG present, but **meta_description & og_image silently dropped on save** |
| RSS / Atom | Good |
| Media library / image optimisation | Weak (single-image upload, no library) |
| Document management | Missing |
| Audit history | Weak (global log exists, but blog edits not audited) |
| Version history / rollback | Missing |
| Role-based editing / approval | Weak (admin-only) |

**CMS maturity score: 5 / 10.** Competent for an operator-run marketing blog with
auto-generated content; missing versioning, media library, taxonomy, SEO-field
persistence (a bug) and content-edit auditing expected of "enterprise-grade".

---

## Phase 5 — UI/UX review

Against **GOV.UK Design System / modern SaaS / WCAG 2.2 / cyber best practice:**
- **Visual & brand — Good.** Consistent custom dark-first "cyber" theme via
  CSS-variable tokens (documented light/dark contrast parity), shadcn-style
  primitives, PWA, mobile-responsive data tables.
- **GOV.UK alignment — Weak** (on that specific benchmark). It is explicitly *not*
  the GOV.UK Design System; a dark, neon, developer aesthetic is a mismatch with
  GOV.UK clarity-first conventions for a public-sector-adjacent "Web Check
  replacement." Fine for a dev/SaaS audience; a risk for public-sector trust.
- **Accessibility — Adequate but unverified.** WCAG-aware tokens, aria on
  primitives, labelled inputs — but no automated a11y check in CI (no axe/pa11y)
  and dark-by-default. **Recommend** an axe/pa11y pass + manual WCAG 2.2 AA audit.
- **Onboarding — Weak.** First-run checklist exists but "not yet verified against a
  real account"; **no sign-up page, no password reset**.
- **Scan setup — Good** (ownership proof is legitimate friction; needs crisp copy).
- **Report consumption — Strong** (exec PDF, trends, diff, triage, remediation pack).

**Quick wins:** sign-up + reset pages; axe in CI; fix CMS SEO save; surface SIEM in
UI; scan error messaging. **Strategic:** a GOV.UK-flavoured high-contrast
"public-sector" theme option; verified onboarding; sample-report gallery +
`/methodology`.

---

## Phase 6 — Platform security review

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| S-1 | **High** | Cloud credentials stored **plaintext** in a column named/documented `credentials_encrypted` | `sql/migrations/030`, `cloud-credentials.ts`, `cloudPosture.ts` |
| A-1 | **High** | SSRF guard bypasses (IPv6 `fe9/fea/feb`, IPv4-mapped v6, alt IP encodings, TOCTOU/rebinding, unvalidated derived/redirect fetches) + unrestricted runner egress | `src/lib/ownership.ts`; `docs/security.md` |
| S-2 | Medium | Session cookies, basic-auth passwords, tracker/SIEM/SSO tokens also plaintext (RLS-only) | migrations `013/014/033/036` |
| A-2 | Medium | Rate limiter **fails open** on Redis error; in-memory fallback is a no-op across instances | `src/lib/rateLimit.ts` |
| I-1 | Medium | Terraform doesn't match prod; IaC not source of truth; bare `apply` duplicates infra | `azure/terraform/main.tf` |
| I-4 | Medium | CI Actions pinned to mutable tags, not SHAs — the product flags exactly this on customers (zizmor) | all `.github/workflows/*.yml` |
| D-1 | Low | `scans` INSERT allowed from anon client; business rules enforced only in API layer (worker re-validates) | `sql/migrations/001` |
| — | Low | CSP `'unsafe-inline'` (no nonce); Dockerfile floating `node:20-slim`; no self-dependency CVE scan; MIT licence on commercial SaaS; (now addressed:) **root `SECURITY.md` added by this pass** | various |

**Strengths:** MFA (TOTP, AAL2 step-up); real RLS + real-Postgres RLS test suite;
two historic privilege-escalation holes (self-grant `is_admin`; self-set Agency
plan) found and fixed (`017`/`024`); sensitive tables service-role-write-only;
DOMPurify on all markdown (own stored-XSS once found + fixed); signature-verified
Stripe webhook; hashed API keys + per-key IP allowlist; GDPR retention/erasure;
strong CSP/HSTS/COOP/COEP in the load-bearing layer.

**Top three to fix before production:** S-1 (encrypt cloud creds + rename column
honestly), A-1 (SSRF + egress allow-listing), I-4 (SHA-pin CI Actions).

---

## Commercial & viability

- **Pre-revenue and blocked** (E-07). Zero validated demand; two internally
  inconsistent revenue models (£30/mo avg vs £568 ARPU), both "conservative" guesses.
- **Over-claims** to public funders and in marketing ("Same depth. Same standards"
  vs £10k enterprise testing; unsourced "43% of UK attacks target SMEs"; an
  AI-campaign statistic the docs admit was "not re-verified") are the biggest
  *non-code* risk. The internal docs are, by contrast, exceptionally candid.
- **Solo founder** → structural ceilings (no 24/7, no SLA/MDR, self-serve support,
  no SOC 2/ISO/CREST), correctly acknowledged internally.
- **Market:** real timely opening (Web Check/Mail Check retired 31 Mar 2026); large
  price advantage; consolidating field (Probely→Snyk, Intruder→sales-led); a local
  CREST competitor (same town) that can't be beaten head-to-head — the
  differentiated SME/compliance lane is the right call.
- **Legal:** manual pen-tests sold without confirmed PI insurance; ToS not
  solicitor-reviewed; active tools run on scheduled scans under domain-ownership
  proof the ToS itself says "does not constitute legal authorisation."

---

## Consolidated prioritised backlog

| ID | Priority | Item |
|---|---|---|
| P0-1 | **P0** | Set `STRIPE_PRICE_*`; verify end-to-end paid signup for all tiers (unblocks the business) |
| P0-2 | **P0** | Align external claims with reality: stop citing deleted features to funders; drop "same depth, same standards"; source or cut stats |
| P0-3 | **P0** | Encrypt `cloud_credentials` (KMS/envelope) + rename column; fix SSRF bypasses + add scanner-runner egress allow-listing |
| P1-1 | P1 | Replace flat score with CVSS/EPSS/KEV-weighted model (keep severity evidence separate) |
| P1-2 | P1 | Add sign-up page + password reset; surface SIEM in Integrations UI |
| P1-3 | P1 | Persist CMS SEO fields; implement the real scheduled-report PDF |
| P1-4 | P1 | Enable Sentry DSN; add `scans.error_detail`; add request correlation IDs; SHA-pin CI Actions |
| P2-1 | P2 | DMARC aggregate-report processing (E-66); continuous standalone EASM pipeline |
| P2-2 | P2 | Decide the offensive tier: wire a real agent or remove the claim and `ai-pentest` profile |
| P2-3 | P2 | True MSP/org multi-tenancy if agency/consultancy is a genuine target segment |
| P3-1 | P3 | Peer benchmarking; Cyber Essentials self-assessment questionnaire; board-pack report template; media library + CMS versioning |

---

## Scorecard summary

| Dimension | Verdict |
|---|---|
| Scanner breadth & depth | **Strong** (passive excellent; active good; no authenticated IDOR) |
| Evidence discipline / FP posture | **Excellent** |
| Reporting & remediation | **Strong** (scoring model weak) |
| Platform security | **Good** with 2 High findings to close |
| Tenant isolation (RLS) | **Strong, tested** |
| CMS maturity | **5 / 10** |
| UI/UX | **Good** build; **Weak** on GOV.UK alignment, verified a11y, onboarding completeness |
| Documentation (engineering) | **Excellent** prose; diagrams added by this pass |
| Commercial readiness | **Weak** (cannot bill; unvalidated demand; over-claims) |
| Overall | **Promising, honest-at-core product that is a few P0 fixes and a claims-cleanup away from being genuinely sellable.** |
