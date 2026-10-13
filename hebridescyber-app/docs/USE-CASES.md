# Use Cases

Six concrete scenarios showing how Hebrides Cyber serves different customer
types. Each references real product capabilities verified against
`docs/FUNCTIONALITY-MATRIX.md` — no aspirational features. For the
competitive framing behind these, see `docs/COMPETITIVE-ANALYSIS.md` §9/§11.

---

## 1. Tourism operator — B&B with a booking site

**Profile**: A small B&B on Lewis with a WordPress booking site, processing
card payments through a third-party widget. No technical staff; the owner's
nephew built the site. Annual revenue under £100k.

**Trigger**: A guest mentions their card was compromised after booking. The
owner googles "is my website secure" and finds Hebrides Cyber.

**What happens**:
1. Signs up, runs a free scan within minutes (D10=3, no setup call needed).
2. Scan discovers: exposed `.env` file with database credentials
   (`exposure.ts`), outdated WordPress plugins with known CVEs
   (`wpvdb.ts`), missing security headers (`headers.ts`), no HTTPS on the
   booking subdomain (`tls.ts`).
3. Each finding comes with plain-English remediation text
   (`remediationText.ts`) — "Delete the file at `/path/.env` and rotate
   your database password" rather than "CVE-2024-XXXXX."
4. The owner forwards the report to the nephew. The nephew fixes the issues
   using the four-rung remediation ladder (D5=3): reads the static advice,
   clicks "AI Fix" for WordPress-specific guidance, creates a Jira ticket
   for the hosting provider.
5. Upgrades to Basic (£20/mo) for weekly automated scans. Next week's scan
   shows the `.env` finding as "Fixed" in the New/Fixed diff (D4=3).

**Value delivered**: A non-technical business owner can understand and act
on security findings without hiring a consultant.

---

## 2. Local trades business — electrician with a WordPress site

**Profile**: An electrician in Stornoway whose web agency built a WordPress
site with a contact form and portfolio. The agency manages hosting but
doesn't proactively check security.

**Trigger**: The local council requires Cyber Essentials evidence for a
public-sector contract the electrician is bidding on.

**What happens**:
1. Runs a scan. The Cyber Essentials compliance tab
   (`complianceReport.ts`) shows exactly which CE controls pass and which
   fail, mapped from real scan findings — not a generic checklist.
2. Three CE controls fail: outdated server software, missing CSP header,
   and a jQuery library with a known XSS vulnerability.
3. The electrician creates tickets directly to the web agency's Linear
   board (`ticketIntegrations.ts`) — one click per finding, pre-filled
   with the remediation text.
4. Agency fixes the issues. Next scan shows all three as "Fixed." The
   compliance tab now shows a passing CE posture.
5. Exports the compliance report as evidence for the council tender.

**Value delivered**: Cyber Essentials readiness assessment at £20/mo instead
of £300-500 for a manual CE assessment, with ongoing monitoring.

---

## 3. SaaS startup — developer team shipping daily

**Profile**: A 5-person SaaS team in Edinburgh. They deploy to AWS via
GitHub Actions multiple times a day. Security is "we'll get to it."

**Trigger**: A prospective enterprise customer asks "do you have a security
scanning process?" during due diligence.

**What happens**:
1. Installs the Hebrides Cyber GitHub Action (`../action/`) in their CI
   pipeline. Takes 5 minutes — one YAML file, one API key.
2. The CI gate checks each PR against the previous scan's findings. A PR
   that introduces a new CSP downgrade or removes an HSTS header **fails
   the build** — but existing findings don't block merges (D4's
   new-findings-only gate, the key differentiator vs naive CI scanners).
3. Pro plan (£35/mo) gives daily scheduled scans of their staging
   environment. Findings flow to Slack (`scanAlerts.ts`) and Jira
   (`ticketIntegrations.ts`) alongside their normal sprint work.
4. Connects their GitHub repo for dependency scanning
   (`dependencyManifest.ts`), secret detection (`secretScan.ts`), and
   Docker base image EOL checks (`dockerBaseImage.ts`).
5. For the enterprise customer's due diligence: exports the 7-framework
   compliance report (`complianceReport.ts`) covering ISO 27001, OWASP
   Top 10, and CIS Controls v8 alongside the score trend over time.

**Value delivered**: Security-as-part-of-the-workflow, not
security-as-an-afterthought. The CI gate catches regressions before they
ship; the compliance report answers enterprise buyer questions.

---

## 4. Digital agency managing 10 client sites

**Profile**: A web agency in Glasgow managing WordPress, Shopify, and
custom sites for 10 SME clients. Monthly retainer includes "we keep your
site secure" but they've never had tooling to back that claim.

**What happens**:
1. Agency plan (£75/mo) with 15 monitored targets — all 10 client sites
   plus their own properties.
2. **Fleet overview** (`FleetOverview.tsx`) shows every client's score,
   last scan date, and open finding count in one dashboard — no clicking
   through 10 separate reports.
3. **Portfolio report** (`portfolioReport.ts`, Agency) rolls all 10
   client sites into one PDF — scores, open criticals, SLA breaches —
   for a single monthly client-facing summary.
4. **White-label PDF reports** (`generate-report.ts` with Agency branding)
   go to clients at monthly review meetings — the agency's logo, not
   Hebrides Cyber's.
5. **SLA monitoring** (`slaMonitoring.ts`) tracks remediation deadlines
   per severity — critical findings get 24h, high gets 72h. The agency
   can show clients they're meeting response commitments.
6. Each client site picks its own scan profile (`safe`/`full`/`api`/`cms`,
   `scanProfiles.ts`) — an e-commerce site runs the deeper profile, a
   brochure site the lighter one.
7. When a client's WordPress plugin has a CVE, the agency auto-creates a
   ticket and tracks it through to resolution with dedupe and auto-close
   (`ticketLinks.ts`, `ticketAutoClose.ts`).

**Value delivered**: Turns "we keep your site secure" from a vague promise
into a measurable, auditable service with per-client reporting.

---

## 5. Cyber Essentials preparation

**Profile**: Any UK SME that needs Cyber Essentials certification for a
contract, insurance requirement, or supply-chain obligation.

**What happens**:
1. Runs a scan. The multi-framework compliance report
   (`complianceReport.ts`) maps every finding to the specific CE control it
   violates — not a generic "you have 12 findings" but "CE control
   'Secure Configuration' fails because of these 3 specific issues."
2. Subscribes to Basic or Pro for ongoing monitoring. Scheduled reports
   (`scheduledReports.ts`) track CE compliance percentage weekly.
3. Findings are prioritised by severity (`scoreFromFindings`,
   `scanners/index.ts`), so the most urgent issues surface first.
4. As fixes land, the New/Fixed diff shows progress. The compliance
   percentage climbs from 62% to 94% over 4 weeks.
5. Before the formal CE assessment, exports the latest compliance report
   as evidence of ongoing security monitoring — assessors recognise
   automated scanning as supporting evidence.

**Value delivered**: A structured, evidence-based path to CE compliance
that costs £20-35/mo instead of relying solely on a one-off £300-500
assessment that provides a snapshot, not ongoing monitoring.

---

## 6. Island charity or church — free tier

**Profile**: A church in Point, Lewis, with a simple informational website
managed by a volunteer. No budget for security tooling. No technical
knowledge.

**What happens**:
1. Uses the free single scan — no credit card required.
2. Scan finds: mixed content (HTTP images on an HTTPS page), an
   auto-indexable `/backup/` directory, and a missing `X-Frame-Options`
   header allowing clickjacking.
3. The report explains each finding in plain English with a specific fix:
   "Ask your website volunteer to change `http://` to `https://` for
   these 3 images" rather than "Mixed Content violation."
4. The charity forwards the report to their web volunteer, who fixes the
   issues in an afternoon.
5. For qualifying Outer Hebrides organisations: a free annual re-scan
   (part of the local community benefit programme — see
   `marketing/12-hie-grant-application.md` §3).

**Value delivered**: A zero-cost security baseline for organisations that
would otherwise have no security visibility at all. Demonstrates
community benefit for grant funding narratives.
