# Competitor matrix

A side-by-side of Hebrides Cyber against the products that win the same buying
decision. It sits beside `COMPETITIVE-ANALYSIS.md`, which holds the scored
rubric (§4), the advantages and disadvantages, and what not to build. This file
answers a different question: **what does each side actually ship, dimension by
dimension, and which gaps could we close ourselves?**

**As of: 2026-10-30.**

## The rule this file follows

`COMPETITIVE-ANALYSIS.md` §1 says a competitor price or limitation must never
be asserted without a source and a date on the specific cell. That rule applies
here too, so this file is split by how much can be proven:

- **Hebrides Cyber** is checked against the code. Every claim in the second
  table names the file that shows it. This is the part that can go stale, so
  re-check it when a feature ships.
- **Competitors** appear only as their own positioning (a headline strength, as
  the vendor describes it). These are not verified and carry no date. No price,
  no limitation and no "they lack X" is stated for any competitor, because none
  has been checked against their current pages. The refresh procedure in
  `COMPETITIVE-ANALYSIS.md` §1 is how a competitor cell earns a place here.

## Who is compared

Vendor positioning only; unverified, no source date yet.

| Product | Category | Headline strength, as positioned | Deployment |
|---|---|---|---|
| Intruder.io | SME vulnerability management | continuous attack-surface monitoring | SaaS |
| Probely | Developer-first web and API scanning | API scanning from an OpenAPI spec, CI plugins | SaaS |
| Detectify | External attack surface and web scanning | continuous attack-surface monitoring, researcher-sourced signatures | SaaS |
| Pentest-Tools.com | Toolkit of on-demand scanners | many tools, including free ones; white-label reports | SaaS |
| Beagle Security | Automated web and API testing | AI-assisted testing, report templates | SaaS |
| Astra Security | Scanning plus managed penetration testing | human-verified findings | SaaS and managed service |
| Invicti / Acunetix | Enterprise web application scanning | proof-based scanning | SaaS and on-premises |
| Rapid7 InsightAppSec | Enterprise web application scanning | integration with the wider Rapid7 platform | SaaS |
| Qualys WAS | Enterprise web application scanning | integration with the wider Qualys platform | SaaS and appliance |
| Snyk | Developer security: dependencies, code, IaC, containers | reachability analysis, fix pull requests, IDE plugins | SaaS |
| Burp Suite Enterprise | Enterprise web application scanning | the Burp engine; customer-run scanning agents | customer-run |
| OWASP ZAP | Open-source scanner | free; automation framework | self-hosted |

## Hebrides Cyber, dimension by dimension

Checked against the code on 2026-10-30. Paths are relative to `hebridescyber-app/`.

| Dimension | What ships | Evidence |
|---|---|---|
| Primary focus | Web scanning for UK SMEs and agencies, with the supply chain (dependencies, code, infrastructure-as-code, GitHub workflows) in the same product | `docs/FUNCTIONALITY-MATRIX.md`, `docs/SCANNER-INVENTORY.md` |
| Scan types | A passive base suite on every scan; safe-active tools chosen by scan profile; authenticated scanning with a saved cookie or Basic credential, or a recorded form login; API checks (OpenAPI and Postman import, GraphQL); dependency, code, IaC and workflow scanning of a connected repo; an offensive profile for Tier A only, gated by plan and a per-target authorization | `src/lib/scanProfiles.ts`, `src/lib/scanExecution.ts`, `src/lib/offensiveAuthorization.ts` |
| Proof of exploit | Reflected and DOM-based XSS, open redirect, CORS and exposed-file findings are re-checked and marked "confirmed exploitable"; the report shows attack chains | `src/lib/scanners/proofOfExploit.ts`, `xssConfirm.ts`, `src/lib/attackPathAnalysis.ts` |
| Compliance mapping | Cyber Essentials, OWASP Top 10, CIS Controls v8, ISO 27001, PCI DSS, NIS2 and DORA; SOC 2 and HIPAA derived by crosswalk. Worded as an automated indicator, never a certification | `src/lib/scanners/compliance.ts` |
| CI gate | Fails a build only on new, untriaged findings at or above a threshold. A POSIX script for any CI system, templates for five, and a packaged GitHub Action | `public/ci/hebrides-scan.sh`, `action/index.js`, `src/app/docs/ci/page.tsx` |
| Remediation | Fix text on every finding; an AI-tailored fix (needs Azure OpenAI configured); pull requests that bump vulnerable dependencies and add missing security headers; tickets in Jira, Linear, ServiceNow or GitHub; a remediation pack; retest | `src/lib/scanners/remediationText.ts`, `src/lib/aiRemediation.ts`, `src/pages/api/generate-fix-pr.ts`, `src/lib/configFixes.ts`, `src/lib/ticketLinks.ts` |
| Integrations | Email, Slack, Teams, webhooks; SIEM export by webhook or syslog in JSON, CEF or LEEF; Jira, Linear, ServiceNow, GitHub issues; PagerDuty and Opsgenie; uptime monitoring; a public API | `src/pages/api/account/` (`siem-integration.ts`, `ticket-integration.ts`, `oncall-integration.ts`, `uptime-integration.ts`) |
| Attack surface | Certificate-log (crt.sh) and Subfinder discovery on every scan; a certificate-log sweep every 6 hours; alerts for subdomain takeover, lookalike domains, DNS changes and new hostnames; DNS brute-force on Tier A only. New-hostname alerts sent from the sweep itself are in review at the time of writing | `src/lib/easmPipeline.ts`, `src/lib/attackSurfaceMonitor.ts`, `src/lib/scanners/takeover.ts`, `src/lib/lookalikeDomainMonitor.ts`, `.github/workflows/easm-discovery.yml` |
| Deployment | SaaS on Azure Static Web Apps; scans run on GitHub Actions workers that claim jobs from a Postgres queue. No customer-run or on-premises scanner | `docs/ARCHITECTURE-NOTES.md` |
| Pricing model | One free scan, then paid plans (Basic, Pro, Agency, Tier A) with a cap on monitored sites per plan. Prices are on the pricing page, not here | `src/lib/freeTier.ts`, `src/lib/planAccess.ts`, `sql/migrations/018_monitored_targets_plan_cap.sql` |
| Reporting | Executive PDF (white-label), compliance report, remediation pack, CycloneDX SBOM with VEX, CSV and JSON export, an Agency portfolio PDF, scheduled reports. No SARIF yet | `src/lib/executiveReport.ts`, `src/lib/sbomExport.ts`, `src/pages/api/v1/scans/[id]/export.ts`, `src/lib/portfolioReport.ts` |
| Scale model | A Postgres job queue with `SKIP LOCKED` claims; 3 worker shards, each stopping at 15 jobs or 25 minutes per run; a daily scheduled enqueue. Recent runs take about 6 minutes; not measured under load | `.github/workflows/scheduled-scans.yml`, `src/scripts/run-queued-scan-jobs.ts` |
| Platform security | Row-level security on every table; customer credentials encrypted at rest with AES-256-GCM; service-role isolation; an audit log; two-factor sign-in. **No SOC 2, ISO 27001 or Cyber Essentials certification yet.** Open hardening items are tracked in `OWNER-TODO.md` | `src/lib/credentialEncryption.ts`, `docs/security.md`, `docs/OWNER-TODO.md` |
| Best-fit buyer | UK SMEs, agencies and MSPs, and teams that need Cyber Essentials evidence | `marketing/`, `src/app/agencies/` |

Also shipping, and easy to miss: DMARC report ingestion, a Cyber Essentials
self-assessment, scan windows, public score badges, a partner portal, finding
triage with SLAs, and a cross-site findings view.

## Capabilities competitors position that we do not have

These are the gaps a small team could close with its own version. The effort is
a rough development estimate, not a quote.

| # | Capability | Positioned by | What we would build | Effort | Status |
|---|---|---|---|---|---|
| 1 | Instant public check, no signup | free tools from several scanner vendors, and the retiring NCSC Web Check | Paste a domain, get a grade, from passive checks only (TLS, headers from one request, mail-authentication DNS, certificate-log subdomains). A scan today needs domain verification. | 3–5 days | Approved 2026-10-30 |
| 2 | SARIF export | several scanner and code-security vendors | `?format=sarif` on the existing export route, plus an upload step in the CI templates so findings appear in GitHub's Security tab. GitHub needs code scanning enabled on the repository (a paid feature on private repositories). | 1–2 days | Approved 2026-10-30 |
| 3 | Customer-defined checks | scanners with extension ecosystems (ZAP, Burp, nuclei) | Let Agency and Tier A accounts add their own nuclei templates, run only against their verified targets. Templates must be restricted to the target's own host, with code and headless modes disabled. | about 1 week | Approved 2026-10-30 |
| 4 | Analyst review of a finding | Astra | A "request an analyst review" action on a finding, routed to the operator as a paid add-on. Little engineering; it monetises existing consultancy. | 1–2 days | Not started |
| 5 | Reachability on dependency findings | Snyk | Tag each vulnerable-package finding with whether production code imports the package. Evidence only; never changes severity. | about 1 week | Not started |
| 6 | Local command line and pre-commit hook | Snyk, ZAP | A `hebrides` command for secrets, lockfile changes and code checks before a push, built on the dependency-diff API and CI script that exist. | 2–3 days for the command line; weeks for an IDE plugin | Not started |
| 7 | Customer-run scanner agent for internal applications | Burp Suite Enterprise, Invicti, Qualys | A worker container customers run inside their network, outbound HTTPS only. Needs an agent-facing claim and submit API with per-agent tokens (today's workers hold database credentials), and results treated as untrusted. Also answers the fixed-scanner-IP request enterprise buyers make. | 2–3 weeks | Plan once a buyer asks |

Also planned: a cloud-posture wrapper (Prowler) for AWS, Azure and GCP; a
two-session access-control test with TOTP support for authenticated scans; and
queue-wait monitoring.

**Not worth building:** an interactive-testing agent inside the customer's
application (needs a runtime agent per language); researcher-sourced signature
programmes (a community, not a feature); a proprietary scan engine (we wrap ZAP
and nuclei, so effort is better spent on depth); appliance or on-premises
packaging (until a deal needs it).

## Filling in the competitor cells

When a competitor cell is worth having (a pricing decision, a sales conversation,
a funding application), verify it properly before writing it down:

1. Load the vendor's current pricing and feature pages; note the date.
2. Record the cell as level or statement, the evidence line, the source URL and
   the verified-on date, in `COMPETITIVE-ANALYSIS.md` §4 using its format.
3. Leave a cell unverified rather than filling it from memory.

The dimensions in the table above are the ones to verify first, in this order:
pricing model, attack-surface coverage, proof of exploit, CI gate, integrations.
