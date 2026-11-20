# Phishing awareness: simulated phishing and staff training (design, 2026-11-19)

Status: **design only, nothing built.** Owner decisions are marked ⚑ and
listed together at the end, with the owner-only steps raised as OT-59 to
OT-61 in [`OWNER-TODO.md`](OWNER-TODO.md). Working name "Phishing awareness";
the product name is a decision (⚑ D1).

## 1. The idea in one paragraph

A customer runs a simulated phishing email to their own staff, with their
written authorisation. Anyone who clicks sees a short "here's what you
missed" lesson straight away, and staff can be assigned a short course. The
customer sees click and **reporting** rates over time, and gets evidence for
Cyber Essentials, insurance and supplier questionnaires. Large companies
take this for granted; small ones rarely have the tool, the know-how or the
budget.

## 2. Why it fits Hebrides Cyber

- **The gap is real for small firms.** Microsoft's built-in Attack
  Simulation Training needs Defender for Office 365 Plan 2 (or E5). Most
  small businesses are on Business Premium, which has Plan 1. Google
  Workspace has no built-in equivalent.
- **Buyers are asked for it.** Cyber insurance proposal forms and supplier
  questionnaires commonly ask whether staff get awareness training and
  phishing tests. The answers feed the evidence pack (next-10 task 7).
- **It is managed-service shaped.** "An engineer runs a quarterly test and
  explains the results" is exactly Lookout's model.
- **Much of the plumbing exists:** staff lists from the Microsoft 365 and
  Google Workspace connections (`m365Consent.ts`, `workspaceConsent.ts`),
  team roles and audit logging, report pages and PDFs (`lookoutReportPdf.ts`),
  scheduled jobs in GitHub Actions, and email sending (`email.ts`).
- **Competition exists**, including UK firms aimed at small businesses
  (usecure, CyberSmart, Bob's Business) and large platforms (KnowBe4,
  Hoxhunt). Our edge is the bundle: scanning, Lookout and awareness in one
  place, with one report.

## 3. Principles (what we will and won't do)

1. **Supportive, never punitive.** The National Cyber Security Centre (NCSC)
   advises against blaming people who click. A large ETH Zurich study
   (Lain, Kostiainen and Čapkun, IEEE S&P 2022) found that training shown
   after a failed simulation didn't make employees more resilient and may
   have made some more susceptible, while encouraging reporting worked well.
   So the headline measure is the **reporting rate**, clicks are secondary,
   and the product never names and shames.
2. **No credentials are ever captured.** A landing page may record *that* a
   form was submitted, never what was typed. No field value leaves the
   browser.
3. **Authorised in writing, per campaign.** Like Tier A's
   `offensive_scan_authorizations`, a campaign runs only with a current
   authorisation from the customer naming the domains, the recipients (or
   "all staff from the connection"), the sending window and the person
   authorising. Staff are told the programme exists (not when).
4. **No real-brand impersonation by default.** Templates are generic ("a
   shared document", "a parcel", "a password expiry") or styled as the
   customer's own internal mail. Imitating real brands (Microsoft, DHL, HMRC)
   is a legal question first (⚑ D4).
5. **Our own domains stay clean.** Simulations never send from
   hebridescyber.co.uk or the transactional email domain; they use dedicated
   sending domains (⚑ D3, OT-60).
6. **Marketing waits for the build** (OT-14), and never names the engine
   underneath (the same rule as the scanner tools).

## 4. How it works (customer's view)

1. **Set up (once):** connect Microsoft 365 or Google Workspace (already
   built) or upload a staff CSV. Add our sending domains and IPs to the
   allowlist we guide them through (Microsoft 365's *advanced delivery*
   policy for phishing simulations; the Gmail equivalent, exact steps to
   confirm). Sign the authorisation.
2. **Campaign:** pick a template and difficulty, choose recipients, set a
   window (we spread sends over it so it doesn't arrive all at once).
3. **During:** a click opens a short lesson explaining the clues in that
   email. A report (forwarding to our report address, later a button) shows
   a "well spotted" message.
4. **After:** a results page and a section in the Lookout report: delivered,
   reported, clicked, submitted, by department if known, and the trend
   against the last campaign. No individual league table for managers by
   default (⚑ D6).
5. **Training:** assign the course to everyone (recommended) and, optionally,
   a follow-up to anyone who clicked twice in a row (⚑ D5). Completion is
   tracked and reminders sent.

## 5. Phasing

| Phase | What | Who runs it | Size |
|---|---|---|---|
| **1. Managed pilot** | Admin-panel campaign builder, generic templates, landing lesson, click and report tracking, results in the Lookout report | Our engineer | ~2–3 weeks |
| **2. Self-serve (Pro and up)** | Customer-facing builder, staff from the M365/Workspace connection, scheduled recurring campaigns, course assignment and completion tracking, trend charts | Customer | ~3–4 weeks |
| **3. Reporting button** | Outlook add-in and Gmail add-on that report a message to us and the customer | Customer | ~2 weeks + store review |

Phase 1 can run for Lookout pilot customers (OT-45) before any self-serve
release, which de-risks deliverability and the legal wording.

## 6. Technical design

### 6.1 Engine: build small or run Gophish

- **Option A (recommended for phase 1): build a small sender in-app.** A
  campaign is a list of recipients, a template and a window; a scheduled job
  sends in batches. Tracking is one signed token per recipient per campaign
  in each link. It reuses our auth, audit, storage and reporting with no
  second admin UI to secure.
- **Option B: self-host Gophish** (open source, MIT licence) as the engine,
  driven over its API. Mature templates and tracking, but another service to
  run, patch and secure, and its data model doesn't match ours.

⚑ D2: confirm Option A.

### 6.2 Sending

- Dedicated sending domains (for example two or three neutral ones), with
  SPF, DKIM and DMARC set up properly, so allowlisting by domain and IP is
  possible.
- **The email provider must permit simulated phishing in its acceptable use
  policy.** Many transactional providers prohibit it; check Resend's terms,
  and if needed use a provider or plan that explicitly allows it (⚑ D3,
  OT-60).
- Spread sends across the window; cap per-minute rate; stop the campaign on
  a customer "pause" at any time.

### 6.3 Tracking without false positives

- **Clicks:** the link carries an HMAC-signed token
  (campaign id + recipient id). The landing page records a click only after a
  real page load in a browser (a small script posts back), because email
  security link scanners (Microsoft Safe Links, Google) open links
  automatically and would otherwise count as clicks. Requests from known
  scanner IP ranges, or within seconds of delivery with no script, are
  recorded as "scanned", not "clicked".
- **Opens:** not tracked. Tracking pixels are unreliable and add little.
- **Submitted:** the landing form, if shown, posts only a flag. Field values
  are discarded in the browser and never sent.
- **Reported:** phase 1 via a report address customers forward to (or a
  journal rule); phase 3 via the add-in.

### 6.4 Data model (sketch, phase 1)

All service-role only (RLS on, no policies), cascading from `auth.users`,
with RLS tests, like `finding_assignments` (078).

- `phishing_authorizations`: owner, authorised_by_name, authorised_by_email,
  domains[], scope (all staff from connection / listed), window, signed_at,
  expires_at, revoked_at.
- `phishing_campaigns`: owner, authorization_id, template_id, difficulty,
  window_start/end, status (draft / scheduled / sending / done / paused),
  created_by.
- `phishing_recipients`: campaign_id, email (stored only for the campaign's
  life plus retention), display name, department, token hash, sent_at,
  delivered status.
- `phishing_events`: recipient_id, type (scanned / clicked / submitted /
  reported), at, user agent class (not full string), no IP stored beyond what
  scanner filtering needs at request time.
- `training_assignments`: owner, recipient email, course id, assigned_at,
  completed_at, reminder count.
- Retention: events and recipient emails deleted after 12 months (⚑ D7),
  aggregates kept for trend lines. Added to `cleanup-retention.ts`.

### 6.5 Training content

- **The NCSC's free staff e-learning ("Top Tips for Staff")** is the obvious
  core course. Organisations can host it, but we must **check its licence
  and how completion can be tracked** before relying on it (⚑ D5, OT-61).
- Plus our own two-minute "what you missed" lesson per template, written in
  house (plain English, the clues in that specific email).
- Completion tracking for a hosted course needs a SCORM player or our own
  short quiz; phase 2 decides which.

### 6.6 Where it shows up

- Admin panel tab (phase 1) and a dashboard page (phase 2).
- A **Lookout report section** and PDF section: rates, trend, one or two
  plain recommendations.
- The **evidence pack** (task 7): "phishing simulation run on <date>,
  training completion <n>%".

## 7. Legal and data protection

- **We are a processor** for the employer's staff data. A data processing
  agreement and an update to the privacy policy and terms (⚑ D8, OT-59).
- **Lawful basis and transparency are the employer's**, but we should give
  them a short DPIA template and a staff notice template.
- **Solicitor and insurer sign-off before the first live campaign**, as with
  OT-13 for Exploit: this is a social-engineering service against a
  customer's staff, so professional indemnity cover must include it (OT-59).
- **Brand impersonation:** off by default; legal advice if ever wanted (⚑ D4).

## 8. Pricing (to decide)

Competitors are roughly £1–3 per user per month. Options (⚑ D9):

- included in Lookout tiers (quarterly managed campaign), or
- a per-user add-on for Pro and above (self-serve), or
- both: managed in Lookout, self-serve as an add-on.

## 9. Owner decisions (⚑)

| # | Decision | Recommendation |
|---|---|---|
| D1 | Product name | Decide with marketing; avoid "phish" in the name customers' staff see |
| D2 | Engine: in-app sender or self-hosted Gophish | In-app sender (A) |
| D3 | Sending domains and an email provider whose terms allow simulations (OT-60) | Two neutral domains, a provider that explicitly allows it |
| D4 | Real-brand impersonation in templates | Off; generic and internal-style templates only |
| D5 | Training: NCSC course (licence to check, OT-61) plus our lessons; required follow-up for repeat clickers? | Course for everyone; optional follow-up after two clicks in a row, framed as support |
| D6 | Individual results visible to managers? | Aggregates by default; per-person only for the account owner, with a warning |
| D7 | Retention of recipient emails and events | 12 months |
| D8 | DPA, privacy policy and terms wording (OT-59) | Solicitor drafts with OT-13/OT-35 |
| D9 | Pricing and packaging | Quarterly campaign in Lookout; self-serve add-on later |

## 10. Not in scope

- Smishing (SMS) and voice phishing.
- Collecting or testing real passwords, ever.
- Targeting anyone other than the authorising customer's own staff.
