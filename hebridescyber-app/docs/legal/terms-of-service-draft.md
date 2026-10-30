# Terms of Service — SUPERSEDED, now live at src/app/terms/page.tsx

> **Published 27 August 2026 per explicit owner instruction, ahead of
> solicitor review.** The live page (`src/app/terms/page.tsx`, linked from
> the footer and `/pricing`) resolved every `[PLACEHOLDER]` below by
> either omitting the unconfirmed fact entirely (company registration
> number, VAT treatment, professional-indemnity-insurance status — none of
> these are stated on the live page, rather than guessed) or using
> standard, defensible boilerplate (§8's liability cap, §12's Scotland
> governing-law choice) rather than leaving visible placeholder text on a
> production legal page. **This still isn't a substitute for solicitor
> review** — §4 (authorisation/indemnification) and §8 (liability cap
> sizing) in particular should still get a real legal read before this is
> relied on in a dispute. Kept here for that review and for the original
> reasoning; the live page is the current, actual terms.

**Why this exists now**: the live site takes Stripe Checkout payments and
the product fires real attack payloads (sqlmap, commix, dalfox, nuclei)
at customer-specified third-party infrastructure, with no contract,
liability cap, or acceptable-use policy in place today. That combination
is the highest-priority legal gap identified in the readiness audit.

---

## Terms of Service

**Last updated: [PLACEHOLDER — date of actual publication]**

### 1. Who we are and acceptance of these terms

Hebrides Cyber ("we", "us", "our") is based in the Isle of Lewis,
Scotland, UK. `[PLACEHOLDER: registered company name/number if
incorporated, and VAT registration status — see README.md's operational
checklist, both still unconfirmed as of this draft]`.

By creating an account, purchasing a subscription, or engaging us for a
one-off audit or pen-test, you ("Customer", "you") agree to these Terms.
If you don't agree, don't use the service.

### 2. The service

We provide:
- **Automated Security Score subscriptions** (Basic/Pro/Agency) — scheduled
  automated scanning, a scored report, and remediation guidance, per the
  plan tier described on `/pricing`.
- **One-off audits** (Small Website Audit / Standard Web App Audit / Full
  SaaS Audit) — a mix of automated scanning and, at the higher tiers,
  manual testing, delivered as a written report.
- **Manual penetration-test engagements and other add-ons** priced per
  engagement.

The service identifies **indicators** of security weakness. It is not a
guarantee that a target system is secure, free of vulnerabilities, or
compliant with any particular standard — see §7 (Disclaimers).

### 3. Accounts

You must provide accurate registration information and keep your
credentials confidential. You're responsible for activity under your
account. Notify us immediately at `[PLACEHOLDER: contact email]` if you
suspect unauthorised access.

### 4. Authorisation to scan — read this before submitting a target

**This is the most important clause in this document for a product that
fires real attack payloads at infrastructure you specify.**

By submitting any URL, domain, or system for scanning — automated or
manual — you represent and warrant that:

- you own the target, or
- you have explicit, current authorisation from the owner to conduct
  security testing against it, including active/intrusive testing
  (port scanning, vulnerability probing, SQL injection testing, XSS
  testing, and the other techniques the extended scan tier and manual
  engagements use).

We verify domain ownership via DNS/file-based proof before running
scheduled or on-demand automated scans (see `docs/security.md`), but this
verification does not itself constitute legal authorisation to test, and
manual/one-off engagements may rely on your representation alone.

**You agree to indemnify and hold us harmless** from any claim, loss, or
liability arising from your submission of a target you were not
authorised to test. We reserve the right to suspend or terminate your
account and refuse service if we reasonably believe a submitted target
was not authorised.

### 5. Acceptable use

You will not:
- use the service to test a target you're not authorised to test (§4);
- use the service to develop or launch attacks against third parties
  outside the scope of a specific, authorised engagement;
- attempt to circumvent rate limits, plan restrictions, or access
  another customer's data;
- resell or provide the service to a third party outside a specifically
  contracted white-label/agency arrangement (Agency plan).

We may suspend accounts that violate this section without refund.

### 6. Fees, billing, and cancellation

- Monthly subscription plans are billed via Stripe on a recurring basis
  at the price shown on `/pricing` at signup. You can cancel at any time
  via the billing portal; cancellation takes effect at the end of the
  current billing period, no partial refund for the remainder.
- One-off audits are invoiced 50% upfront, remainder on delivery, per
  `/pricing`.
- Prices are `[PLACEHOLDER: confirm VAT treatment — inclusive/exclusive,
  and registration status]`.
- We may change prices for future billing periods with notice; changes
  don't apply retroactively to a period already paid for.

### 7. Disclaimers

The service is provided "as is." Automated and manual security testing
can never guarantee the discovery of every vulnerability, and a clean or
high-scoring report is not a certification that a target is secure. We
make no warranty, express or implied, of merchantability, fitness for a
particular purpose, or that the service will be uninterrupted or
error-free.

Cyber Essentials / compliance-framework references in reports are
described as automated indicators only, never as a certification —
matching the wording already used in the product itself
(`src/lib/scanners/compliance.ts`).

### 8. Limitation of liability

`[PLACEHOLDER — standard SaaS shape for a solicitor to size correctly for
this business: liability for direct losses capped at fees paid by the
Customer in the 12 months preceding the claim; no liability for indirect,
consequential, or lost-profit damages; carve-outs typically excluded from
the cap are death/personal injury caused by negligence, fraud, and
anything that can't be excluded by law.]`

Manual pen-test/incident-response engagements priced on `/pricing`
(£300/£800/£1,800 and quoted IR retainers) should not be sold without
professional indemnity insurance in place — `[PLACEHOLDER: confirm
current status, README.md's operational checklist has this unticked as
of this draft]`.

### 9. Intellectual property

Scan reports and findings we generate for you are yours to use for your
own security purposes. We retain ownership of our underlying tooling,
scanner logic, and report templates. You grant us a licence to process
the target/scan data you submit solely to provide the service.

### 10. Termination

Either party may terminate a subscription per §6. We may terminate or
suspend access immediately for a breach of §4 or §5, or if required by
law.

### 11. Data protection

Personal data is handled per our [Privacy Policy](/privacy) — retention
periods, data-subject rights, and processor list live there, not
duplicated here. `[Note: docs/security.md's Data Retention section flags
that the retention periods /privacy promises aren't yet implemented in
code — docs/ENHANCEMENTS.md E-10 — worth having the solicitor confirm
these Terms shouldn't reference retention promises that aren't real yet.]`

### 12. Governing law

These Terms are governed by the law of Scotland. `[PLACEHOLDER: confirm
jurisdiction/dispute-resolution clause with a solicitor — this is a
default assumption based on the business's location, not a researched
choice.]`

### 13. Changes to these Terms

We may update these Terms; material changes will be communicated to
registered users by email, matching the pattern already used for the
Privacy Policy.

### 14. Contact

Hebrides Cyber, Isle of Lewis, Scotland, UK — hello@hebridescyber.co.uk
(matching `/privacy`'s `CONTACT_EMAIL` constant; used as-is on the live page).

---

## Still open (checklist for whoever takes this to a solicitor)

- [x] Live page created (`src/app/terms/page.tsx`), linked from the footer
      and `/pricing`'s subscribe section — `docs/ROADMAP.md` BETA-B1's
      *publication* half is done.
- [ ] Solicitor review of the live page, focused especially on §4
      (authorisation/indemnification — the clause doing the most work for
      a product that fires real attack payloads) and §8 (liability cap
      sizing) — BETA-B1's *review* half is still open.
- [ ] If the business becomes VAT-registered or incorporates formally,
      add that to the live page (currently omitted rather than guessed).
- [ ] Manual pen-test engagements (£300/£800/£1,800 on `/pricing`) are
      still being sold without confirmed professional indemnity insurance
      — README.md's operational checklist has this unticked. The live
      Terms page doesn't reference insurance status either way; this is
      a business-readiness gap independent of the Terms page itself.
