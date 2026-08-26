# Consultancy Services & Market Pricing Catalogue

**This is consultancy service-line market intel — manual pen tests, IR
retainers, compliance advisory, MDR — not a SaaS product comparison.** For
how Hebrides Cyber the *product* compares against other automated
scanners (Intruder.io, Probely, Astra, etc.), see
`hebridescyber-app/docs/COMPETITIVE-ANALYSIS.md` instead — different
question, different answer, not duplicated here.

Reference catalogue of services UK/global SME-focused security consultancies
and MSSPs commonly offer, with typical packaging, pricing, and tooling —
for comparing against and prioritising Hebrides Cyber's consultancy-side
offerings (`marketing/08-business-plan.md`; the engineering-side roadmap
lives at `hebridescyber-app/docs/ROADMAP.md`, its history at
`hebridescyber-app/docs/decisions/ENGINEERING-LOG-2026-08.md` — the old
`PRODUCTION-ROADMAP.md` this originally pointed at was deleted as
misleading early in the product's life).

## 1. Core offensive & assurance services (high demand, high margin)

| Service | What competitors offer | Packaging / Pricing | Tools & tech | How Hebrides Cyber can differentiate |
|---|---|---|---|---|
| Web application penetration testing | Manual OWASP Top 10 + API testing, authenticated tests, business logic checks, exploit verification | Fixed-price: small site £300–£800; medium SaaS £800–£3k; enterprise higher | Burp Suite, ZAP, custom scripts, Playwright for automation | Fast "Express" scans (24–48h) + deeper manual audits; developer-friendly PR templates and remediation code |
| API / Mobile app testing | API fuzzing, auth flows, token handling, mobile client reverse engineering | Add-on to web app tests or separate packages | Postman, Burp, Frida (mobile), Objection | API contract checks, automated CI hooks to run tests on PRs |
| Infrastructure / Cloud security review | IAM review, storage permissions, network rules, logging, misconfigurations | Per-cloud or per-environment; small reviews £200–£1k | AWS/Azure/GCP consoles, ScoutSuite, Prowler, manual checks | Specialise in Supabase/Vercel/Azure stacks; RLS audits + automated remediation scripts |
| CI/CD & supply-chain security | Pipeline secrets, artifact signing, dependency provenance, SCA | Workshops + audits; one-off £200–£1k | GitHub Actions, Snyk, Dependabot, Sigstore | Pipeline hardening templates, GitHub Action policies, automated PRs to fix deps |
| Internal network / infrastructure pentest | On-prem or cloud network tests, lateral movement, AD assessments | Higher cost; often onsite/VPN | Cobalt Strike (enterprise), BloodHound, Nmap | Lightweight remote network checks for small businesses; partner with local engineers for onsite work |

These are the bread-and-butter services clients expect; they command higher
one-off fees and are a gateway to recurring work.

## 2. Continuous & managed services (recurring revenue)

| Service | What competitors offer | Pricing model | Tools & tech | How to productise |
|---|---|---|---|---|
| Vulnerability scanning & management (SaaS) | Automated scans, dependency monitoring, ticketing, SLA alerts | Subscription £20–£200+/mo | Snyk, Dependabot, Nessus, Qualys, custom scanners | Security Score product: tiered Basic/Pro/Agency, Slack alerts, remediation PRs |
| Managed Detection & Response (MDR) | 24/7 monitoring, threat hunting, incident response | Monthly retainer, higher price point | EDR agents (CrowdStrike), SIEM (Elastic, Splunk), SOAR | Lightweight monitoring + incident on-call add-on; partner with an EDR vendor as reseller |
| Managed backups & recovery | Backup verification, restore drills, ransomware readiness | Monthly fee per server/site | Veeam, Azure Backup, custom scripts | Simple website & DB backup + restore tests for local businesses |
| Patch & maintenance service | Regular dependency and OS patching | Monthly retainer or per-incident | Automation scripts, Dependabot, Ansible | "Patch day" service with automated PRs and optional apply-for-client |
| Security-as-a-Service for churches/charities | Low-cost recurring packages for non-profits | Discounted monthly plans | Same tools, simplified reporting | Vertical package: sermon indexing, donation security checks, GDPR help |

Recurring revenue stabilises cashflow and increases LTV; competitors bundle
automated scanning with human review.

## 3. Compliance, governance & advisory (trust & upsell)

- GDPR readiness & data protection audits — gap analysis, DPIAs, policy templates.
- Cyber Essentials / Cyber Essentials Plus preparation — documentation, technical checks, pre-audit remediation (strong UK/local market fit).
- PCI DSS readiness — for e-commerce clients.
- Security policy & incident response planning — tabletop exercises, runbooks, playbooks.
- Pen test attestation & compliance reporting — formal reports for procurement or insurers.

Positioning: package "Compliance Starter" bundles (e.g. Cyber Essentials + 1
year Security Score) to win local SMEs and tourism operators who need
procurement compliance.

## 4. Incident response, forensics & IR retainer (high trust, high margin)

- Incident response retainer — guaranteed response window, triage, containment, forensic analysis.
- Digital forensics — evidence collection, root cause analysis.
- Ransomware negotiation support — usually via partners.

Start with a simple retainer for local businesses (phone + 24–48h response)
and partner with a specialist for complex cases. Clear T&Cs and insurance
recommendations required — see professional indemnity insurance note in
`docs/security.md` / `PRODUCTION-ROADMAP.md` Stage 7.

## 5. Productised, developer-friendly add-ons (fast to deliver, high perceived value)

- Automated remediation PRs — GitHub PRs that fix headers, update deps, add HSTS/CSP snippets.
- Security Score badge / widget — embeddable trust badge for websites (with expiry and link to report).
- White-label PDF reports for agencies.
- Developer training & workshops — secure coding, 1-day CI/CD hardening sessions.
- SaaS integrations — Slack alerts, Jira ticket creation, GitHub issue/PR automation.

Pricing: small fixed fees for PRs; subscription tiers for badge and
integrations.

## 6. Niche & vertical services (differentiate locally)

- Tourism & hospitality security — booking systems, POS, Wi-Fi segmentation, GDPR for guest data.
- Church & charity digital security — donation platform security, sermon archives, volunteer account management.
- Crofters & small agricultural tech — IoT device hardening, simple telemetry security.
- Photography / creative businesses — watermarking, secure galleries, e-commerce checkout security.

Local Hebrides focus gives credibility; vertical packages convert better
than generic offerings.

## 7. Tools, integrations & automation competitors use

- SCA & dependency monitoring: Snyk, Dependabot, OSS Index.
- Dynamic scanning / pentest tooling: Burp Suite, OWASP ZAP, Nikto.
- Static analysis / IaC scanning: Checkov, tfsec, Semgrep.
- CI/CD & pipeline checks: GitHub Actions, GitLab CI, Azure DevOps.
- EDR / monitoring: CrowdStrike, SentinelOne, Elastic, Datadog.
- Ticketing & automation: Jira, GitHub Issues, Slack, PagerDuty.
- PDF/reporting: Puppeteer / Playwright for HTML→PDF (already the approach used in `src/functions/generate-report`).
- Cloud infra tools: ScoutSuite, Prowler, Cloud Custodian.

Start with a minimal set (Snyk/Dependabot + ZAP + Playwright) and add
integrations as revenue justifies.

## 8. Pricing models & commercial strategies competitors use

- One-off fixed price audits — clear scope, deliverables, retest window.
- Monthly subscriptions — tiered (Basic/Pro/Agency), automated scans + periodic manual review.
- Retainers — incident response or priority support.
- Per-asset pricing — per domain, per server, or per app.
- White-label / reseller — agencies resell reports under their brand.
- Workshops & training — day rates or per-attendee pricing.

Suggested Hebrides Cyber approach (matches `marketing/03-pricing-page.md`):
hybrid — clear one-offs to attract clients, plus a simple subscription
(Basic £20, Pro £35, Agency £75) and an optional IR retainer.

## 9. Differentiators to prioritise

1. Developer-first deliverables: remediation PRs, code snippets, CI templates.
2. Automation + human review: fast automated Security Score with optional manual follow-up.
3. Local trust + vertical focus: tourism, churches, local SMEs.
4. Productised add-ons: embeddable Security Score badge, white-label reports for agencies.
5. Affordable incident retainer with clear SLAs for local businesses.
6. Low-friction onboarding: one-click scans, clear proof-of-ownership flow, fast turnaround (24–72h) — the two-step `run-scan` flow in `src/functions/run-scan/index.ts` is the current stub of this.
7. Transparent pricing & sample reports on the site.

## 10-11. (removed — stale code claims)

*Both sections here referenced code that no longer exists — `checkDependencies()` in a `src/lib/scanners.ts` that was never the real module structure, `src/functions/run-scan`, "ownership verification is a token-echo stub" (it's real DNS/file verification now), and "vertical pages/white-label/Slack+Jira not built" (all shipped). For current, code-verified product capability, see `hebridescyber-app/docs/FUNCTIONALITY-MATRIX.md`; for what's actually still open, `hebridescyber-app/docs/ENHANCEMENTS.md`.*
## 12. Example packaged offerings for the site

- **Starter Security Score** — £20/mo or £30 one-off: automated scan,
  1-page report, email alert.
- **Site Audit** — £300: manual review + 8-page report + 1-hour
  remediation call.
- **SaaS Audit** — £1,500: full pen test, CI/CD review, cloud permissions
  review.
- **Pro Monitoring** — £35/mo: weekly scans, dependency alerts, Slack
  notifications, quarterly manual review.
- **IR Retainer** — £150/mo + hourly incident fees: 48-hour response,
  triage, containment.

## Closing recommendation

Ship the Security Score product and a clear Site Audit offering first. Use
the Score as a lead magnet and conversion funnel into paid audits and
subscriptions. Prioritise developer-friendly outputs (PRs, CI templates)
and vertical packages for the Hebrides (tourism, churches, local trades).
Once there's recurring revenue and a few case studies, add white-label
agency features and a simple IR retainer.
