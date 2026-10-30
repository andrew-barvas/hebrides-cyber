# Lookout by Hebrides Cyber: Managed Exposure Review (copy draft)
`hebridescyber.co.uk`

**Status: DRAFT, not for publication.** The product is not built yet, and the name is not trademark-checked (plan Q6). Design and decisions: `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md`.

**Publishing rule (OT-14):** every claim below must match a built, tested feature on the day it goes live. Items marked **[VERIFY]** depend on work that is not done yet. Cut or reword them if they are not true at launch.

---

## Landing section (for `src/app/page.tsx` or `src/app/services/page.tsx`)

**Overline:** `$ lookout.watch()`

**Headline:** Know what the internet can see of your business. Before someone else looks.

**Subhead:** Lookout is a managed exposure review for UK small businesses. We keep watch on your websites, domains and open services, and a real engineer tells you, in plain English, what matters and what to fix first.

**Primary CTA:** Start Lookout
**Secondary CTA:** See what's in a report

**Small print under the buttons:** Not a penetration test. We look, we report, we help you fix. We never attack or exploit anything.

---

## Pitch paragraph (about 75 words)

Most small businesses have more of their company visible online than they realise: old subdomains, forgotten test sites, open services, out-of-date software. Lookout finds them, checks them for known weaknesses, and sends you a short report written for the person who runs the business, not just the person who runs the servers. Each period you get a clear list of what to fix first, and we re-check once you have fixed it.

---

## Features list

- **A full picture of what's exposed.** We map the websites, subdomains and open services connected to your domains. **[VERIFY: subdomain and port discovery on the `exposure` profile]**
- **Checks for known weaknesses.** Out-of-date software, risky settings, weak encryption and exposed admin pages, checked with established, non-intrusive scanning. **[VERIFY: tool list at launch; do not name OpenVAS or Nikto until their CI tests pass]**
- **Fixes in plain English.** Every finding says what it means for your business and what to do about it, ranked by how urgent it is.
- **Evidence for insurers and customers.** Reports are mapped to Cyber Essentials and other standards, so you can answer security questionnaires without guessing. **[VERIFY: wording must say "mapped to", never "certifies"]**
- **A report you can show the board.** One page of business-level risk, then the detail behind it.
- **Review call with a named engineer.** Go through the report with someone who can answer questions. Call count depends on your plan.
- **We re-check your fixes.** Fix something, and we confirm it is closed. **[VERIFY: Assured plan only]**
- **Safe by design.** Scans run only on domains you have proved you own. No exploits, no password guessing, no attempts to break in.

---

## Plans

| | **Essentials** | **Assured** |
|---|---|---|
| Monthly | £149 / month | £299 / month |
| Quarterly | £399 / quarter | £799 / quarter |
| Annual | £1,490 / year | £2,990 / year |
| Continuous automated scanning | Yes | Yes |
| Analyst-written report | Quarterly | Monthly |
| Review call | 30 minutes, quarterly | Two calls per quarter |
| Re-check of fixes | | Yes |
| Questionnaire help (Cyber Essentials, insurance) | | Yes |

**Optional extras:** Cyber Essentials readiness pack · insurance evidence pack · extra IP range · board summary · CI/CD hardening workshop (£300).

Prices are proposals from the plan and are subject to the owner's final sign-off. VAT treatment to be confirmed.

**Fair-use note (also needed in the terms):** Each plan includes a fixed amount of engineer time. Larger estates are quoted separately.

---

## Why choose us

**Local and accountable**
You get a named engineer from the Isle of Lewis, not a ticket queue. We answer to the businesses we live and work alongside.

**Engineers who explain**
We are software engineers. We write reports for the owner first and the IT person second, so you can act on them the same day.

**No disruption, no exploitation**
We look at what is visible from the outside. We never try to break in, we never run attack code against your systems, and we only scan domains you have verified.

**Clear, fixed pricing**
One monthly, quarterly or annual price for each plan. No surprise call-out fees for what is included.

---

## FAQ (for the page)

**Is this a penetration test?**
No. Lookout is a regular, defensive review of what is exposed and misconfigured. It does not try to exploit anything. If you need a hands-on penetration test, we offer that separately.

**Will scanning slow down or break my website?**
The checks are designed to be non-intrusive and rate-limited, and they only run against domains you have verified. We agree scan windows with you at the start. **[VERIFY: scan-window setting exists]**

**Do you watch my systems around the clock?**
No. Lookout is scheduled scanning plus engineer review, not a 24/7 monitoring or incident-response service. If something serious turns up, we tell you promptly, and we can quote separately for incident support.

**What do I need to give you?**
Your domains, a contact for alerts, and confirmation that you own or are authorised to test what we scan.

**Does it make me Cyber Essentials certified?**
No. It helps you prepare and gives you evidence. Certification is done by an accredited body.

---

## Notes for whoever builds the page

- Match existing patterns: `Service` entry (`name, icon, desc, includes[], meta?, tag?`) in `src/app/services/page.tsx`, section markup from `src/app/page.tsx`. Use theme tokens (`text-cybertext`), never `text-white`.
- `Card` renders `body` with `dangerouslySetInnerHTML`: escape ampersands as `&amp;`.
- Use the canonical host `https://www.hebridescyber.co.uk` in any absolute URL.
- Cap onboarding per month and show "limited places" only if it is true.
- Add the product to the terms (`src/app/terms/page.tsx` §2). Wording needs the solicitor (OT-13).

## Claims checklist before publishing

- [ ] `exposure` profile exists and is scheduled for Lookout customers
- [ ] No tool in the profile sends injection or exploit payloads (profile unit test)
- [ ] Reports include ATT&CK/CWE/business-impact fields, or the copy stops mentioning them
- [ ] Re-check of fixes works end to end (Assured)
- [ ] Stripe prices exist and checkout works for all six prices
- [ ] Terms updated and approved
- [ ] Name cleared (trademark and domain)
- [ ] No mention of 24/7, SOC, SLAs or certification
