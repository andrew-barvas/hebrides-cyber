# 16 — NCSC Web Check / Mail Check replacement campaign

**Status:** drafts, ready for the owner to send or post. Nothing here has been sent.
**Why now:** the NCSC retired its free Web Check and Mail Check services on 31 March 2026 and points organisations to commercial External Attack Surface Management (EASM) products instead. Small UK organisations that relied on them now have nothing, and many don't know it yet.
**Landing pages (live once merged):** `/web-check-alternative` (row-by-row coverage map, including the parts we only partly cover), `/cyber-essentials` (readiness scan), blog post `ncsc-web-check-mail-check-retired-what-to-do` (seed `sql/seed/002_ncsc_web_check_retirement_post.sql`, run it in the Supabase SQL editor).

## Rules for every piece

- **Never imply NCSC endorsement.** Say "the NCSC retired…", never "NCSC-approved", "official replacement" or "recommended by the NCSC". Use the NCSC name only to state the fact of the retirement, and link their notice.
- **Only claim what `/web-check-alternative` claims.** Two honest gaps: no continuous discovery of unknown assets yet, and DMARC aggregate reports are not received yet. Don't say "full replacement".
- **No invented numbers.** No "thousands of breaches", no made-up customer counts. "Thousands of organisations used Web Check" is fine only if we can cite it; otherwise say "many".
- Prices: free first scan; monitoring from £20/month (Basic). Paid sign-up needs the Stripe price IDs set first (owner action E-07). Until then, point CTAs at the free scan and `/contact`.
- UTM-tag every link: `?utm_source=<channel>&utm_medium=<type>&utm_campaign=ncsc-replacement`.

## 1. Email sequence (to existing contacts, newsletter subscribers, enquiry list)

Send only to people who opted in. Three emails, one week apart.

**Email 1. Subject:** The NCSC's free Web Check has gone. Here's what it was checking

> Hi {first name},
>
> On 31 March the NCSC retired Web Check and Mail Check, its free services for spotting website and email-security problems. If your organisation used them, those checks have stopped.
>
> What they were looking for still matters: expired or weak certificates, missing security headers, out-of-date software, exposed files, and email settings that let anyone send phishing in your name.
>
> We've put together a plain-English page showing what each retired check covered and how to keep it running: {link /web-check-alternative}
>
> You can run one free scan of a domain you own, with no card needed.
>
> {signature}

**Email 2. Subject:** Can someone send email pretending to be you? A two-minute check

> Mail Check's main job was answering one question: can your domain be spoofed? Here's how to check yourself.
>
> Look up the DMARC record at _dmarc.{yourdomain}. If it's missing, or says p=none, fake email from your domain still gets delivered.
>
> Our free scan checks SPF, DKIM, DMARC, MTA-STS and TLS-RPT and tells you exactly what to change: {link /dashboard}
>
> More on what replaced Web Check and Mail Check: {link /blog/ncsc-web-check-mail-check-retired-what-to-do}

**Email 3. Subject:** Getting ready for Cyber Essentials?

> If Cyber Essentials is on your list this year, the parts an assessor can see from outside (your website, your exposed services, your out-of-date software) are the ones a scan finds fastest.
>
> Our readiness scan maps every finding to the five Cyber Essentials controls, and is clear about what a scan can't see: {link /cyber-essentials}
>
> It's an indicator to help you fix things before you apply, not a certification.

## 2. LinkedIn posts (owner's profile, then the company page)

**Post A (the news):**

> The NCSC retired Web Check and Mail Check on 31 March 2026.
>
> For many small organisations, charities and councils, those were the only external security checks they had. The NCSC now points people to commercial attack-surface tools, and has published a buyer's guide.
>
> If you used either service, three things to do this week:
> 1. Register for the NCSC's Early Warning service. It's still free and still running.
> 2. Check your DMARC record. p=none means spoofed email still gets delivered.
> 3. Put something back in place that keeps checking your website and email settings.
>
> I've mapped what each retired check covered, and what we do and don't replace: {link}
>
> #CyberSecurity #NCSC #SmallBusiness #Scotland

**Post B (the founder angle):** after 15+ years building secure systems for large defence and public-sector programmes, why I'm building affordable checks for small UK organisations. End with the Web Check alternative link. Owner to write in their own voice; keep employer names to what the owner is comfortable stating publicly.

**Post C (practical):** a screenshot of a sample report's email-security section (from `/sample-reports`, never a real customer's), captioned "This is what Mail Check used to tell you."

## 3. Search ads (Google Ads, small UK-only budget)

**Ad group: NCSC replacement.** Keywords (phrase match): "ncsc web check", "web check replacement", "ncsc mail check alternative", "mail check retired", "free website security check uk", "dmarc check uk".
Negative keywords: "jobs", "careers", "login", "ncsc careers".

- Headlines (≤30 chars): `Web Check Has Been Retired` · `Free Website Security Scan` · `Check Your DMARC & SPF` · `UK-Based, From £20/Month`
- Descriptions (≤90 chars): `The NCSC retired Web Check and Mail Check. Keep checking your site and email.` · `One free scan, no card. Plain-English fixes for every finding.`
- Final URL: `/web-check-alternative?utm_source=google&utm_medium=cpc&utm_campaign=ncsc-replacement`

**Ad group: Cyber Essentials readiness.** Keywords: "cyber essentials readiness", "cyber essentials scan", "cyber essentials check website". Final URL `/cyber-essentials`. Don't use "certification" in the ad text: we don't certify.

## 4. Agency outreach (web agencies, IT support firms, MSPs)

Agencies looked after Web Check for many of their clients. Use the existing cold-outreach rules in `07-cold-outreach-emails.md`, at most 20 a week, personalised.

**Subject:** Replacing Web Check for your clients

> Hi {name},
>
> Since the NCSC retired Web Check and Mail Check in March, agencies that relied on them have lost a free way to keep an eye on client sites.
>
> Hebrides Cyber's Agency plan scans up to 15 client sites on a schedule. It produces white-label PDF reports and shows one list of open findings across every site, with bulk triage. It runs from CI too, with templates for GitHub, GitLab, Bitbucket, Azure DevOps and Jenkins.
>
> Would it be useful if I scanned one of your client sites (with their permission) so you can see the report?
>
> {signature}

Landing page: `/agencies`.

## 5. Measuring it

- Free scans started with `utm_campaign=ncsc-replacement` (sign-ups and first scans by source).
- Visits to `/web-check-alternative` and `/cyber-essentials`, and conversion to a first scan.
- Review after four weeks: keep the channels that produced first scans, drop the rest.
