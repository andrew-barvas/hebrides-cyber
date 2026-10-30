# Product ideas

Stable-ID (`P-nn`) list of **new products**: something a new buyer could
pay for, or a new line of revenue. Nothing here is built unless an entry
says so, and nothing here is committed or dated.

**How this differs from [`ENHANCEMENTS.md`](ENHANCEMENTS.md).** That file
owns *features of the product we already sell* (`E-nn`). This file owns
*whether a new product is worth building at all*. When a `P-nn` is
greenlit, its build work is written up as new `E-nn` items there, and the
`P-nn` entry lists their IDs under **Build items**. Never restate an
`E-nn` here; link it by ID. What exists today is decided by
[`FUNCTIONALITY-MATRIX.md`](FUNCTIONALITY-MATRIX.md), not by either file.

**IDs.** Never renumber. A dropped idea is marked `DROPPED` with the
reason, and its number is retired.

**Status values.** `idea` → `testing` (its first test is running) →
`greenlit` (has `E-nn` build items) → `shipped`, or `DROPPED`.

**Fields.** Every entry answers the same questions, so ideas can be
compared:
- **Who pays**: the buyer and a price *hypothesis* (current plans: Basic
  £20/mo, Pro £35/mo, Agency £75/mo, Tier A by quote).
- **Problem**: what goes wrong for them today.
- **What we reuse**: existing modules and `E-nn` items.
- **What's new**: the work that doesn't exist yet.
- **Effort**: S (days), M (2–4 weeks), L (1–3 months), with the
  `ENHANCEMENTS.md` category (code / money/time / solo-blocked).
- **First test**: the cheapest way to learn if anyone wants it, before
  building.
- **Kill criteria**: measurable, with a pilot size or a date. If one is
  hit, mark it `DROPPED`.

Growth and promotion (social media, local press) are not products. They
live in
[`../../marketing/11-social-media-and-local-press-playbook.md`](../../marketing/11-social-media-and-local-press-playbook.md).

---

## P-01 — Kit Watch: alerts for the office kit a website scan can't see

**Status: idea.**
**The product**: the owner lists what they run, in plain English: router,
firewall or VPN box, storage box (NAS), CCTV, printers, Windows version,
WordPress plugins, booking/till/accounting software. They pick each item
from a catalogue (or later, photograph its label). We alert only when an
item has a flaw criminals are actively exploiting, or has reached end of
life. Each alert says what to do in plain English. We never say "you're
safe"; we say "no known actively exploited issues".
**Who pays**: Basic and up, as a retention feature, or a £5–10/mo add-on.
Possibly a standalone tier for businesses whose website isn't worth
scanning. Hypothesis to test.
**Problem**: the devices that dominate CISA's actively-exploited (KEV)
list (edge/VPN appliances, NAS boxes) sit in the office, where our
scanner never looks. npm audit and our dependency scanning only help
people with code repositories.
**Why it sells**: Cyber Essentials' "Security update management" control
requires high and critical updates within 14 days and no unsupported
software. "We watch your kit and keep the evidence you patched on time"
is a reason to buy.
**What we reuse**:
- E-68 matching: `src/lib/emergingThreats.ts` (`buildCveTechRanges`,
  `matchHost` over `TechObservation`s from `scanners/techInventory.ts`),
  the `emerging_threat_alerts` ledger, and the 6-hourly job
  (`src/scripts/check-emerging-threats.ts`). A declared item becomes one
  more `TechObservation`.
- `src/lib/scanners/endOfLife.ts` (endoflife.date) for end-of-life alerts.
- `emergingThreatSteps` in `scanners/remediationText.ts`, plus email,
  `slack.ts` and `msTeams.ts` delivery.
- `src/lib/cyberEssentialsReadiness.ts` and `/dashboard/cyber-essentials`
  for the patch-evidence view.
**What's new**: the catalogue (friendly name → CPE vendor/product), an
owner-declared inventory table with RLS, the "I've updated it" evidence
trail, and the plain-English alert copy.
**Effort**: M. **Category**: code. The catalogue is the real work.
**Risks**: catalogue-to-CPE mapping is messy; NVD analysis lags (E-68
already treats that as "pending"); and the wording must never imply
"safe".
**First test**: ask 10 pilot customers to list their kit in a form. Map
it to CPEs by hand and send one month of alerts manually.
**Kill criteria**: drop it if fewer than 5 of 10 pilots list 3+ items, or
if under 70% of what they list maps to a CPE without hand-editing.

## P-02 — Email account check (Microsoft 365 / Google Workspace)

**Status: idea.**
**The product**: a read-only connection to the customer's Microsoft 365 or
Google Workspace tenant. It checks: is MFA enforced, is legacy sign-in
allowed, are there external mail-forwarding rules, how many admins are
there, is DKIM signing on. It alerts when any of these change for the
worse.
**Who pays**: Pro and up, or an add-on. Business email compromise and
invoice fraud are the losses small businesses actually report.
**What we reuse**: the email-security DNS checks (`scanners/dns.ts`),
DMARC aggregate reports (E-66, `dmarcAggregate.ts`), lookalike-domain
monitoring (E-65). The cloud-credentials pattern from E-32
(`CloudCredentialsConfig`, `scanners/cloudPosture.ts`), with tokens
sealed per CLAUDE.md rule 20 (`secretMigration.ts`).
**What's new**: a Microsoft Graph app (publisher verification, admin
consent), a Google Workspace equivalent, and the posture checks
themselves.
**Effort**: L. **Category**: money/time. Microsoft's app verification
and, for some Google scopes, a third-party security assessment take
calendar time and may cost money.
**First test**: run the checks by hand for 5 pilot tenants (screen-share
with the admin) and see whether the findings change anything.
**Kill criteria**: drop it if under half the pilots will grant admin
consent, or if Google's assessment cost is above one year of expected
add-on revenue (then build Microsoft only).

## P-03 — Supplier fraud check

**Status: idea.**
**The product**: the customer lists their suppliers' and clients'
domains. Using public records only (DNS, certificate transparency,
domain registration data), we alert when a supplier's domain can be
spoofed (no DMARC enforcement), or when a lookalike of that supplier's
domain is registered. That's how fake-invoice emails get sent.
**Who pays**: Pro/Agency add-on. Accountants, trades and anyone who pays
supplier invoices by bank transfer.
**What we reuse**: `scanners/dns.ts` email checks and
`lookalikeDomainMonitor.ts` (E-65), both passive.
**What's new**: a supplier list per account, scheduling, and alert copy.
Only passive public lookups are allowed, because the customer doesn't
own these domains and every active check needs verified ownership.
Results stay private to the customer and are stated as facts, never as
a published "score" of the supplier.
**Effort**: S–M. **Category**: code.
**First test**: offer it to the first 10 Pro customers as a beta toggle.
**Kill criteria**: drop it if fewer than 3 of 10 add 5+ suppliers within
a month.

## P-04 — Cyber insurance readiness pack

**Status: idea.**
**The product**: insurers' proposal forms ask about MFA, backups,
patching and external exposure. We generate an evidence pack from scan
results, plus Kit Watch (P-01) and the email check (P-02) once they
exist. Brokers then become a sales channel.
**Who pays**: the business (one-off fee at renewal time), or a broker
(referral or wholesale).
**What we reuse**: the compliance mapping (`scanners/compliance.ts`),
Cyber Essentials readiness, and PDF reports (`generate-report.ts`, the
portfolio report).
**What's new**: question mapping for 2–3 insurers' forms, the pack
layout, and broker terms.
**Effort**: S to build, but the partnership is the work. **Category**:
solo-blocked.
**First test**: show a mocked pack to 3 local brokers.
**Kill criteria**: drop it if none of 3 brokers agrees to a pilot.

## P-05 — Client workspaces for agencies and IT support firms

**Status: idea.**
**The product**: a version of Agency aimed at web agencies and IT
support firms (MSPs). Sites are grouped by client. Each client gets a
branded report and, optionally, their own read-only login. The agency's
home screen ranks clients by "what got worse since last week".
Wholesale pricing per client.
**Who pays**: agencies and MSPs, per client per month. One agency
customer brings 10–50 sites.
**What we reuse**: the fleet view (E-27, `FleetOverview`), the partner
portal (E-39), the portfolio report, white-label branding
(`BrandingSection`), team roles (E-45), SSO for the top plan (E-76).
**What's new**: a client entity between account and site, client-level
reports and logins, and wholesale billing.
**Effort**: M. **Category**: code (billing changes touch Stripe).
**Prerequisite**: plan checks in the UI must go through
`planAccess.ts`. The Tier A fix that did this (PR #110, branch
`claude/frosty-golick-eeca03`) was closed unmerged, so dashboard pages
still compare plan names directly.
**First test**: interview 5 agencies about how they report security to
clients today, and what they'd pay per client.
**Kill criteria**: drop it if fewer than 2 of 5 say they'd switch their
client reporting to it.

---

## Emerging-threat intake

New threats are the best source of product ideas, as long as each one
gets the same four questions. Review once a month, using what the blog
pipeline (`newsletter.ts`'s `fetchRecentHighSeverityCves`) and the E-68
alert job pulled in. Also review after any incident in the UK press.

1. **Does it hit UK small businesses?** What do they run that's
   affected? If nothing, log it as "none" and stop.
2. **Can we already see it?** Is there a scanner check, or does E-68
   match it? If yes, the only action is content (blog, newsletter,
   social post).
3. **If not, what's missing?**
   - A check on the website → a new `E-nn` in `ENHANCEMENTS.md`,
     following `SCANNER-CONVENTIONS.md`.
   - A new data source → a new `E-nn`.
   - Something outside a website scan (office kit, email tenant,
     suppliers, staff) → evidence for an existing `P-nn`, or a new one.
4. **Write it down** in the log below, even when the answer is "none".
   The log shows which products real threats keep pointing at.

### Intake log

| Date | Threat or event | Who it hits | Covered today? | Outcome |
|---|---|---|---|---|
| 2026-03-31 | NCSC Web Check / Mail Check retired | UK organisations that used the free service | Yes | E-61 landing page (done) |
| ongoing | Edge/VPN appliances and NAS boxes keep appearing in CISA KEV | Any business with a firewall, VPN or NAS | No: office kit isn't scanned | Evidence for P-01 |
| 2025-10-14 | Windows 10 end of support | Small offices still on Windows 10 | No | Evidence for P-01 (end-of-life alerts) |
| ongoing | Business email compromise and invoice fraud | Anyone paying invoices by bank transfer | Partly: DMARC and lookalike checks on the customer's own domain | Evidence for P-02 and P-03 |
