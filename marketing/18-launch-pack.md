# Launch pack: company, Lookout, Exploit (2026-11-20)

Everything needed to go from "built" to "selling", in order. The owner-only
steps are tracked as OT items in `hebridescyber-app/docs/OWNER-TODO.md`; this
file explains how to do them and holds the ready-to-send texts. Nothing here
is legal, tax or insurance advice: it is a checklist and drafts for the
professionals to confirm.

## 0. Done on 2026-11-20

- Email works end to end: Resend verified for `hebridescyber.co.uk` (EU),
  `RESEND_API_KEY` in Azure and GitHub, a live enquiry delivered (OT-02).
  `hello@` is an alias of `admin@`.
- `lookout.hebridescyber.co.uk` and `exploit.hebridescyber.co.uk` forward
  (301, GoDaddy) to `www.hebridescyber.co.uk/lookout` and `/exploit`. HTTPS on
  the forwards follows when GoDaddy issues the certificate (a few hours).
  Azure's Free plan allows two custom domains (www and the bare domain), so
  serving the products on their own hostnames needs the Standard plan (about
  $9 a month): do that at paid launch.
- Supabase's custom SMTP (Resend) is filled in and waiting for the owner to
  paste a dedicated Resend key and save (OT-57).
- "Hebrides Cyber" has no match at Companies House (checked 2026-11-20).

## 1. Register the company

Why now: liability protection for a business that sends test traffic to
customers' systems, grant eligibility (HIE and others expect a company),
buyer trust, and contracts and insurance in the company's name rather than
yours. See `10-formalisation-and-funding-roadmap.md` §2 for the background.

1. **Speak to an accountant first (30 minutes).** Confirm: limited company
   rather than sole trader, how to pay yourself (salary and dividends), VAT
   timing, and whether they file your accounts. Online fixed-fee accountants
   for solo founders are common and usually include formation.
2. **Verify your identity with Companies House.** Directors now verify
   identity through GOV.UK One Login before or during incorporation. Do this
   first: it can take a little while.
3. **Incorporate online** at gov.uk/limited-company-formation:
   - Name: **Hebrides Cyber Ltd**.
   - Type: private company limited by shares, model articles.
   - SIC codes: 62020 (IT consultancy) and 62012 (business software
     development).
   - Shares: for example 100 ordinary £1 shares, all held by you.
   - Registered office: an accountant's or a virtual-office address keeps
     your home address off the public register. A registered email address is
     also required.
   - Fee: check the current fee on GOV.UK; online is cheapest. Usually done
     within a day.
4. **HMRC:** register for Corporation Tax within three months of starting to
   trade (the company's UTR arrives by post). Set up PAYE only if you pay
   yourself a salary through payroll.
5. **Business bank account** in the company's name (most UK banks onboard a
   new limited company online in a day or two).
6. **ICO data protection fee:** the company processes customer personal data,
   so register with the ICO and pay the annual fee (the small-business tier;
   check the current amount on ico.org.uk).
7. **VAT:** registration is compulsory only above the threshold (check the
   current figure on GOV.UK). Voluntary registration lets you reclaim VAT on
   costs but adds 20% to prices for customers who can't reclaim it. Decide
   with the accountant and fix whether £149 and £299 are VAT-inclusive.
8. **Insurance in the company's name** (see §4 for the email): professional
   indemnity, cyber, and public liability.
9. **Move accounts to the company:** Stripe (business details and bank),
   GoDaddy, Microsoft 365, Resend, Azure, Supabase, GitHub billing.
10. **Assign the IP:** the code, brand and domain were created by you
    personally. A short assignment deed from you to the company puts them in
    the company's name (grant bodies and any future investor will ask). Add
    it to the solicitor instruction in §3.
11. **Update the website** (a session can do this once you have the details):
    company name, number and registered office in the footer, terms and
    privacy policy, as UK disclosure rules require on business websites.

## 2. Lookout: what's left to sell it

Fastest route (this week, by invoice): pilot with 3–5 customers on the
engagement letter in §6, invoice them yourself, set them to Pro (Essentials)
or Agency (Assured) by hand in the admin Customers tab, and write their
reports in Admin → Lookout reports. Log hours per report; stop and rethink if
a quarterly report takes over four hours or fewer than two of five prospects
would pay £149 a month (OT-45).

For self-serve checkout:

| Step | Item | Who |
|---|---|---|
| 1 | **Name (OT-33).** Search search-trademark.service.gov.uk for "Lookout" in classes 9 and 42. Lookout, Inc. holds a US LOOKOUT mark in those classes, so a UK or international mark is likely. If so, pick another name (Beacon, Harbour Watch) and search that. | You |
| 2 | **Tier limits (OT-42).** Approve or change: Essentials 4 analyst hours a quarter, 3 domains and 5 IPs, Pro features; Assured 9 hours, 10 domains and 16 IPs, Agency features; two new customers a month in the pilot. Quarterly £399 / £799, annual £1,490 / £2,990. | You |
| 3 | **Traffic disclosure (OT-43).** Keep or drop the five fake-login rate-limit check for Lookout. | You |
| 4 | **Solicitor (OT-35).** The brief in §3. | You |
| 5 | **Stripe (OT-34).** Products and six recurring GBP prices, test mode then live; price IDs into Azure as `STRIPE_PRICE_LOOKOUT_{ESSENTIALS,ASSURED}_{MONTHLY,QUARTERLY,ANNUAL}`. | You (IDs can be pasted to a session) |
| 6 | **Code.** Draft #199 rebased, checkout cards mounted, Lookout sites locked to the Lookout scan profile, admin Lookout tab takes an email. | In progress in its own session |
| 7 | **Merge and launch** once 1–5 are done. | Session, on your go-ahead |

## 3. Solicitor brief (Lookout and Exploit together)

Send this with the attachments listed. It also covers the IP assignment from
§1 and, optionally, phishing awareness (OT-59).

> **Subject: Hebrides Cyber Ltd — terms, customer contracts and IP assignment for two security services**
>
> Hello,
>
> I run Hebrides Cyber, a UK cyber security business serving small and
> medium-sized businesses (business customers only, no consumers). I'm
> incorporating Hebrides Cyber Ltd and would like a fixed quote for the work
> below.
>
> **What we do today.** An online service that runs automated, passive and
> non-intrusive security checks of websites and domains a customer has
> proved they control, with reports and fix guidance. Our current website
> terms are attached.
>
> **Service 1: managed exposure review (working name "Lookout").** A
> recurring subscription (monthly, quarterly or annual) in which an engineer
> reviews a customer's internet-facing estate each quarter and writes a
> report. It sends active but non-exploitative traffic to the customer's
> verified systems (page and file requests, connections to common ports, TLS
> tests, and a small number of sign-in attempts with made-up details to test
> rate limiting). It includes a capped number of analyst hours per quarter.
> The customer acknowledges each report as read; acknowledging is not
> acceptance of risk.
>
> **Service 2: authorised penetration testing (working name "Exploit").** A
> fixed-scope, time-boxed engagement, booked and scoped by a person, never
> bought online. It sends real, authorised attack traffic to systems the
> customer owns and has listed in a signed scope, within an agreed window,
> to confirm in a controlled, non-destructive way whether weaknesses are
> exploitable. The customer can stop it at any time. Evidence is bounded and
> redacted. Each retest needs a new authorisation.
>
> **What I need:**
>
> 1. **Website terms of service** updated for both services (draft wording
>    for the Lookout sections is attached), including subscription renewal,
>    cancellation and fair-use analyst hours, and the authorisation-to-scan
>    clause.
> 2. **A Lookout customer agreement** or order form: scope of the review,
>    the traffic disclosure, fair-use hours, report acknowledgement wording,
>    liability cap, and what happens if the customer's systems react badly
>    (for example, a lockout alert from the sign-in test).
> 3. **An Exploit engagement contract**, with:
>    - a written authorisation that satisfies the Computer Misuse Act 1990
>      (who may authorise, their authority over each in-scope system, and
>      what happens if they turn out not to have it);
>    - a scope schedule (enumerated in-scope hosts and an out-of-scope
>      list), testing windows and authorised contacts;
>    - rules of engagement (non-destructive testing, rate limits, an
>      immediate stop right, an incident and notification clause);
>    - third-party hosting: the customer's responsibility to hold any
>      permission their hosting or cloud provider requires;
>    - limitation of liability and indemnities appropriate to testing, and
>      alignment with my professional indemnity cover;
>    - confidentiality, evidence handling and retention, and report
>      ownership;
>    - retests as new authorisations.
> 4. **A data processing agreement** for both services (we act as processor
>    for customers' data, UK GDPR), and a privacy policy review.
> 5. **An IP assignment deed** transferring the software, brand and domain
>    from me personally to Hebrides Cyber Ltd.
> 6. *(Optional)* advice on a future simulated-phishing service for
>    customers' staff: the processor terms and employer authorisation
>    (design attached).
>
> **Attachments:** current terms (`/terms`) and privacy policy (`/privacy`);
> the draft Lookout terms sections 2 and 6; the Lookout service description
> and traffic disclosure; the Exploit plan summary (governance and
> authorisation workflow); optionally the phishing-awareness design.
>
> Could you let me know your fee and timescale? Lookout is the priority;
> Exploit can follow.
>
> Thanks,
> [Your name], Hebrides Cyber

**Attachments to gather** (a session can export any of these as PDFs):
`/terms` and `/privacy` from the live site; terms §2 and §6 from draft #199;
`marketing/17-lookout-managed-exposure-review.md` (including "What Lookout
sends to your systems"); `hebridescyber-app/docs/EXPLOIT-PRODUCT-PLAN.md`
"Product concept", "Governance and authorisation workflow" and "Legal,
insurance and safety gate"; optionally
`hebridescyber-app/docs/PHISHING-AWARENESS-DESIGN.md`.

## 4. Insurer email

> **Subject: Cover for Hebrides Cyber Ltd — cyber security services**
>
> Hello,
>
> I'm incorporating Hebrides Cyber Ltd, a UK cyber security business for
> small and medium-sized businesses. Please confirm in writing what cover you
> can offer, and at what cost, for:
>
> 1. Automated security checks of customers' websites (online subscription).
> 2. A managed exposure review: an engineer reviews a customer's
>    internet-facing systems each quarter and writes advisory reports. Active
>    but non-exploitative test traffic to the customer's own verified systems.
> 3. Authorised penetration testing: fixed-scope engagements, under a signed
>    contract and written authorisation, sending real but non-destructive
>    attack traffic to systems the customer owns.
>
> I need professional indemnity (including for advice and for any disruption
> testing causes), cyber cover for my own systems and customer data, and
> public liability. Please say whether item 3 is covered or excluded, and any
> conditions (contract terms, accreditations, limits) that apply.
>
> Expected turnover in year one: [figure]. Number of staff: 1.
>
> Thanks,
> [Your name]

## 5. Exploit: what's needed before it can launch

| Item | Who | Status |
|---|---|---|
| Go / no-go on the product (OT-51) | You | Open |
| Insurance covering contracted testing (OT-13, OT-55) | You | §4 email |
| Solicitor: engagement contract, authorisation, terms (OT-13) | You | §3 brief |
| Booked by hand only, never online checkout (OT-52) | You | Recommended: yes |
| Autonomous agents out of version 1 (OT-53) | You | Recommended: out |
| Pricing after a manual pilot (OT-54) | You | After the pilot |
| Engine weeks 8–9 rebased; engagement and scope record; gate-side scope check; customer status page with a stop button | Session | In progress |
| Public launch: link the page, remove noindex and the "not yet available" banner | Session | Only after all of the above |

## 6. Lookout pilot engagement letter (template)

> **Hebrides Cyber Ltd — Managed exposure review: pilot agreement**
>
> **Customer:** [organisation], [address]. **Contact:** [name, role, email].
>
> **Service.** Each quarter, a Hebrides Cyber engineer reviews the
> internet-facing systems listed below and sends you a written report: what
> we found, what matters most, who should fix it, and how. You can see your
> findings in your Hebrides Cyber dashboard at any time.
>
> **In scope:** [domains] [IP addresses]. You confirm you own or control
> these and are authorised to ask us to check them. We verify each domain
> before checking it.
>
> **What our checks send to your systems:** ordinary page and file requests,
> connections to common network ports, TLS tests, and up to five sign-in
> attempts with made-up details to check rate limiting. We never exploit a
> weakness, send attack payloads, or try real passwords. This is not a
> penetration test.
>
> **Plan and price:** [Essentials £149 / Assured £299] a month, invoiced
> quarterly in advance, [+ VAT if applicable]. Includes up to [4 / 9] analyst
> hours per quarter.
>
> **Term:** an initial [three]-month pilot, then quarter to quarter. Either
> side may end it with [30] days' written notice.
>
> **Reports:** marking a report as read records that you've seen it; it isn't
> acceptance of any risk in it.
>
> **Liability:** [as agreed with the solicitor]. **Data:** we process your
> data under our privacy policy and [data processing terms].
>
> Signed for the customer: ______ Name/role: ______ Date: ______
>
> Signed for Hebrides Cyber Ltd: ______ Date: ______

Until the solicitor has reviewed this (OT-35), use it only for friendly pilot
customers, and keep the liability line conservative.

## 7. Pilot prospect email (template)

> **Subject: A quarterly look at your website's security — free first report**
>
> Hi [name],
>
> I run Hebrides Cyber. I'm taking on a handful of local businesses for a
> pilot of a new service: each quarter I review what [organisation] has
> exposed on the internet (websites, email security, certificates, anything
> that shouldn't be public) and send you a short report with the few things
> worth fixing, in plain English.
>
> For pilot customers the first report is free, then it's £149 a month,
> invoiced quarterly, cancel any time. It's checks only: nothing that could
> disrupt your systems.
>
> Would a 15-minute call next week be useful?
>
> [Your name], Hebrides Cyber — www.hebridescyber.co.uk
