# Lookout by Hebrides Cyber: Managed Exposure Review (copy draft)
`www.hebridescyber.co.uk`

**Status: DRAFT, not for publication.** The product is not built yet, and the name is not trademark-checked (OT-33). Design and decisions: `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md` ("Lookout service design"). Rewritten 2026-10-31.

**Publishing rule (OT-14):** every claim below must match a built, tested feature on the day it goes live. Items marked **[VERIFY]** depend on work that is not merged yet. Cut or reword them if they are not true at launch.

**Wording rules for this page:**
- Name no tools. Describe what is checked and what it tells the customer.
- Never name OpenVAS or Nikto until their integration tests pass in CI.
- No commands, settings or how-to detail about the checks.
- Prefer "check", "review", "testing" and "assessment" to "scan", "probe", "run", "attack" and "payload". Accuracy wins: the page must still say plainly that the checks send active traffic to the customer's systems ("What Lookout sends to your systems" below). "MITRE ATT&CK" is a proper name and stays as written.
- No 24/7, SOC, SLA or certification claims.

---

## Landing section (for `src/app/services/page.tsx`, optionally `src/app/page.tsx`)

**Overline:** `$ lookout.watch()`

**Headline:** Know what the internet can see of your business, and what to fix first.

**Subhead:** Lookout is a managed exposure review for UK small businesses. We check your websites, domains and internet-facing services every day, and a named engineer tells you, in plain English, what matters and what to do about it.

**Primary CTA:** Start Lookout
**Secondary CTA:** See what's in a report

**Small print under the buttons:** Not a penetration test. We test what is visible from the internet for known weaknesses and risky settings, and we never try to break in.

---

## Pitch paragraph (about 80 words)

Most small businesses have more online than they realise: old subdomains, forgotten test sites, open services and out-of-date software. Lookout finds them, checks them every day for known weaknesses and risky settings, and an engineer turns the results into a short report written for the person in charge of the business, not just the person who looks after the servers. You get a clear list of what to fix first, a call to talk it through, and confirmation once each fix has worked.

---

## Features list

- **A clear picture of what's exposed.** We map the websites, subdomains and internet-facing services connected to your verified domains, and tell you when something new appears. **[VERIFY: PR #144 merged; Lookout targets use the `exposure` profile]**
- **Checks for known weaknesses and risky settings.** Out-of-date and unsupported software, weak encryption, missing security settings, exposed admin pages and files that should not be public.
- **Email and domain protection.** Whether your domain can be used to send spoofed email, and whether your domain registration and certificates are about to lapse.
- **What your documents give away.** Names, email addresses, internal system names and photo locations hidden in files on your website. **[VERIFY: only once the metadata check is part of the `exposure` profile; cut until then]**
- **Fixes in plain English.** Every finding says what it means for your business, how to fix it and roughly how long it takes, ranked by urgency.
- **Evidence for insurers and customers.** Findings are mapped to Cyber Essentials, ISO 27001 and other standards, and to MITRE ATT&CK, so you can answer security questionnaires with something to show. **[VERIFY: ATT&CK mapping ships with PR #144; always "mapped to", never "certifies" or "compliant"]**
- **A named engineer, not a ticket queue.** A review call each quarter (two on Assured) with the person who wrote your report.
- **Confirmation that fixes worked.** Tell us when something is fixed and we confirm it from the next scheduled check.

---

## What Lookout sends to your systems

Lookout is an active assessment, not passive observation. To find what an outsider could find, our checks connect to your systems from the internet, much as a visitor or an outsider's automated tools would. Specifically, they:

- load pages from your websites, follow links on them (up to 50 pages, respecting your robots.txt) and read the files those pages link to
- request a fixed list of well-known file locations, such as old backups and configuration files, to see whether any are public
- connect to common network ports on your addresses to see which services answer, and identify the software behind them
- check for known misconfigurations and exposed admin pages
- submit your login page five times with made-up details, to check that it slows down repeated attempts

They do **not**:

- try to exploit a weakness, inject test code or commands into your forms or URLs, or guess passwords
- try to log in with real or default credentials, or go beyond what is reachable from the internet
- check anything you have not proved you own or are authorised to have tested

We agree a time window for the checks with you, and you may see our requests in your logs or your hosting provider's alerts. Tell your IT supplier before you start. **[VERIFY: list matches the `exposure` profile and base suite at launch; update when ZAP passive mode (PR #152) or the metadata check is added, or if the login check is switched off for Lookout (OT-43)]**

---

## Plans

| | **Essentials** | **Assured** |
|---|---|---|
| Monthly | £149 / month | £299 / month |
| Quarterly | £399 / quarter | £799 / quarter |
| Annual | £1,490 / year | £2,990 / year |
| Daily automated checks | Yes | Yes |
| Engineer-written report | Quarterly | Monthly |
| Review call | 30 minutes, quarterly | Two per quarter |
| Fix confirmation | At the next report | Within the month |
| Help with Cyber Essentials and insurance questionnaires | | Yes |
| "What to log" guidance for your IT supplier | | On request **[VERIFY: build step 8]** |
| Included estate | Up to 3 domains and 5 IP addresses **[VERIFY: OT-42]** | Up to 10 domains and 16 IP addresses **[VERIFY: OT-42]** |

**Optional extras (quoted):** Cyber Essentials readiness pack · insurance evidence pack · extra domains or IP addresses · board summary · CI/CD hardening workshop (£300).

Each plan includes a fixed amount of engineer time; larger estates are quoted separately. Not a penetration test. VAT treatment to be confirmed (OT-33). **[VERIFY: prices signed off and Stripe checkout live for all six prices (OT-34)]**

---

## Why choose us

**Local and accountable**
You get a named engineer from the Isle of Lewis, not a ticket queue. We answer to the businesses we live and work alongside.

**Engineers who explain**
We are software engineers. We write reports for the owner first and the IT person second, so you can act on them the same day.

**Thorough, never exploitative**
We test what is visible from the internet and tell you exactly what our checks send. We never try to break in, and we only check domains you have verified.

**Clear, fixed pricing**
One monthly, quarterly or annual price per plan. No surprise call-out fees for anything included.

---

## FAQ (for the page)

**Is this a penetration test?**
No. A penetration test tries to break in. Lookout is a regular, defensive review of what is exposed and misconfigured, and it never tries to exploit anything. If you need a hands-on penetration test for a contract or regulator, ask us and we will point you to the right option.

**Will the checks slow down or break my website?**
They are designed to be light: ordinary page requests, a fixed list of file and port checks, and no test code sent to your forms. They only cover domains you have verified, inside a time window we agree with you. **[VERIFY: per-check request rate limit is documented before claiming "rate-limited"; check windows exist (migration 031)]**

**Will it show up in my logs?**
Yes. Our checks are real traffic, so your website logs, firewall or hosting provider may record them, and your login page will see five attempts with made-up details. We tell you when the first checks start.

**Do you watch my systems around the clock?**
No. Lookout is daily automated checking plus engineer review, not 24/7 monitoring or incident response. If we see something serious, we email your nominated contact, normally within one working day. That is a best-effort notice, not a guaranteed response time.

**What do I need to give you?**
Your domains and public IP addresses, a contact for urgent findings, and confirmation that you own them or are authorised to have them tested. You verify each domain with a DNS record or a file on your site before anything is checked.

**Does it make me Cyber Essentials certified?**
No. It helps you prepare and gives you evidence. Certification is done by an accredited certification body.

---

## Notes for whoever builds the page

- Match existing patterns: `Service` entry (`name, icon, desc, includes[], meta?, tag?`) in `src/app/services/page.tsx`, section markup from `src/app/page.tsx`. Use theme tokens (`text-cybertext`), never `text-white`.
- `Card` renders `body` with `dangerouslySetInnerHTML`: escape ampersands as `&amp;` (note "MITRE ATT&amp;CK").
- Use the canonical host `https://www.hebridescyber.co.uk` in any absolute URL.
- Show "limited places" only while the onboarding cap (OT-42) is real.
- Add the product to the terms (`src/app/terms/page.tsx` §2), with the solicitor's wording (OT-35, OT-13).
- Keep "What Lookout sends to your systems" on the page. It is the accuracy counterweight to "never exploitative" and must not be cut for length.

## Claims checklist before publishing

- [ ] PR #144 merged: `exposure` profile exists and Lookout targets are scheduled on it
- [ ] No component in the profile sends injection or exploit test input (profile unit test)
- [ ] "What Lookout sends to your systems" matches the profile and base suite on launch day (ZAP passive mode, metadata check, login check)
- [ ] Reports include the ATT&CK and CWE fields, or the copy stops mentioning ATT&CK
- [ ] Metadata feature cut unless `metadataLeak` is in the `exposure` profile
- [ ] Fix confirmation works from the scheduled check (both plans)
- [ ] Stripe prices exist and checkout works for all six prices (OT-34)
- [ ] Tier limits approved (OT-42); traffic disclosure approved (OT-43)
- [ ] Terms updated and approved (OT-35)
- [ ] Name cleared: trade mark and domain (OT-33)
- [ ] No mention of OpenVAS, Nikto or any other tool by name
- [ ] No mention of 24/7, SOC, SLAs or certification
