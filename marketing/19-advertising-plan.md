# Advertising and social launch plan (2026-11-20)

Builds on `06-marketing-plan.md` (positioning, channels), `15-launch-campaign.md`
(8-week plan, budget) and `11-social-media-and-local-press-playbook.md`
(platforms, pillars). Where this file differs, it wins: it reflects what has
changed since (Lookout pilots, Exploit kept back, the free check on the
homepage, the weekly fix email, the public security badge, and no Stornoway or
Isle of Lewis in public copy). The bios in `11-…` §3 are superseded by §3 here.

## 1. Rules for every post and ad

1. **Every claim matches a built feature** (OT-14). No 24/7, SOC, SLA,
   certification or "penetration testing" claims.
2. **Exploit is not advertised at all** until OT-13 (insurance and solicitor)
   and OT-51 (go decision). The `exploit.` address forwards to a hidden page;
   don't share it.
3. **Never name offensive tools or describe attack techniques** in posts, ads
   or bios. `11-…` pillar 5 names attacker tooling: drop the names and keep the
   point ("AI-driven attacks are hitting small businesses for a few dollars a
   target; here's what we check").
4. **Location:** "based in Scotland, serving the UK". No Stornoway or Isle of
   Lewis.
5. **Advertising law:** claims must be provable (ASA CAP Code). Cold email to
   limited companies and LLPs is allowed with a clear opt-out; sole traders
   and partnerships need prior consent (PECR). The outreach templates already
   carry an opt-out line.
6. **Examples:** use synthetic findings, labelled as examples, until a
   customer agrees in writing to be featured.

## 2. What to advertise, and when

| Product | Now | Later |
|---|---|---|
| **Scanner** (main) | Yes. Lead with the **free website check** on the homepage: a result in seconds, no sign-up. Then the weekly "one thing to fix" email, Cyber Essentials mapping and fix guides. | Case studies once customers agree. |
| **Lookout** | Direct outreach to 5 pilot prospects only (launch pack §7). No public ads until the name is cleared (OT-33) and checkout is live. | Ads and posts once OT-33/34/35 are done. |
| **Exploit** | Nothing. | After OT-13 and OT-51. |
| **Phishing awareness** | Nothing (design only). | After it's built and OT-59 is done. |

## 3. Accounts to create (about an hour in total)

Use **admin@hebridescyber.co.uk** for every account, with MFA on and the
passwords in a password manager. Reserve the handle everywhere even where you
won't post yet.

| Account | Priority | Handle / name | Notes |
|---|---|---|---|
| **LinkedIn company page** | 1 | Hebrides Cyber | Needs a personal LinkedIn account to create. Add the logo, banner and About text below. |
| **Your LinkedIn profile** | 1 | (you) | Headline below; set Hebrides Cyber as your current role so the page shows staff. |
| **Google Business Profile** | 1 | Hebrides Cyber | Choose "service-area business" and hide the address. Free, shows in Google search and Maps, collects reviews. |
| **X** | 2 | `@hebridescyber` | For short technical posts and news commentary. |
| **YouTube** | 3 | `@hebridescyber` | Reserve now; 2-minute product demos later. |
| **Facebook page** | 3 | Hebrides Cyber | Reserve; low priority for the UK-wide B2B buyer. |
| **Bluesky** | optional | `hebridescyber.co.uk` | Can use the domain itself as the handle (a DNS TXT record). |

**Brand assets (done):** in `hebridescyber-app/public/brand/social/`: the
profile picture `profile-400x400.png` (fits inside a circle crop), the LinkedIn
company cover `linkedin-company-1128x191.png`, your LinkedIn banner
`linkedin-personal-1584x396.png`, the X header `x-header-1500x500.png`, the
YouTube banner `youtube-banner-2560x1440.png` and the link preview
`share-1200x630.png` (now shown whenever a page of the site is shared). To
change the copy, edit and re-run `src/scripts/render-social-images.ts`.

**Bios, ready to paste:**

- **LinkedIn tagline:** Website and email security checks for UK small
  businesses, with clear fixes.
- **LinkedIn About:** Hebrides Cyber checks your website, domains and email
  setup for security problems and tells you, in plain English, what to fix
  first and how. Scans run automatically, map to Cyber Essentials, and track
  what's new and what you've fixed. Try a free check, no sign-up:
  www.hebridescyber.co.uk. Based in Scotland, serving the UK.
- **Your headline:** Founder, Hebrides Cyber | 15+ years secure software and
  cloud delivery (defence and Scottish public sector) | Practical security for
  UK small businesses
- **X bio:** Security checks for UK small businesses' websites and email, with
  plain-English fixes. Free check, no sign-up 👉 hebridescyber.co.uk
- **Google Business description:** Hebrides Cyber helps UK small businesses
  find and fix security problems in their website, domain and email setup.
  Automated checks, Cyber Essentials mapping and clear, prioritised fixes. Free
  website check on our site.

## 4. Three messages to repeat

1. **"Find out in 30 seconds."** The free check: type your website, get a
   result, no sign-up.
2. **"One thing to fix this week."** No 40-page report: we tell you the one
   thing that matters most, and how, every Monday.
3. **"Ready for Cyber Essentials and your insurer."** Findings mapped to the
   controls they ask about.

## 5. Funnel and tracking

- **Path:** post or ad → free check → result page → sign up → paid plan.
- **UTM tags on every link:** `?utm_source=linkedin&utm_medium=social&utm_campaign=launch`
  (sources: linkedin, x, google, gbp, email, outreach; campaigns: launch,
  cyber-essentials, weekly-fix). Analytics only runs after cookie consent.
- **Track weekly (a spreadsheet is fine):** free checks run, sign-ups, paid
  conversions, cost per sign-up for ads, and pilot replies.
- **Targets for the first 8 weeks:** 300 free checks, 40 sign-ups, 5 paying
  customers, 3 Lookout pilots.

## 6. Six-week launch calendar

Week 0 overlaps company registration (launch pack §1); nothing paid until the
company and its bank account exist.

| Week | Do |
|---|---|
| **0: prepare** | Create the accounts in §3 and add the assets and bios. Write the first 10 posts (§8). Book the accountant. Make sure the pricing page and checkout work (a test purchase in Stripe test mode). |
| **1: soft launch** | Personal LinkedIn post: why you built it, a link to the free check. Message 20 people you know (former colleagues, local businesses) asking them to try the check and reply with feedback. Send the 5 Lookout pilot emails. |
| **2: content** | 3 posts a week on LinkedIn (§8), daily short posts on X. Claim the Google Business Profile and ask your first three users for reviews. |
| **3: outreach** | Cyber Essentials-triggered outreach: 20 a week to limited companies that need CE (bidding for public contracts, suppliers to larger firms), using `07-cold-outreach-emails.md` with the opt-out line. Approach 5 web agencies about reselling (Agency plan). |
| **4: paid test** | Google Ads search test (§7). Share one anonymised before/after example. |
| **5–6: review** | Keep what converts, drop what doesn't. If a pilot customer agrees, publish the first case study. |

**Ongoing cadence:** LinkedIn 3 posts a week; X most days; one blog post a
week (the daily blog and weekly newsletter already generate drafts: review
before publishing); Google Business update every two weeks.

## 7. Paid advertising

Start with **Google search ads**, where people are already looking. Skip
LinkedIn and Meta ads until there's organic signal; LinkedIn clicks are
expensive and Meta's audience rarely buys this.

- **Budget:** £300 over 4 weeks (about £10 a day), UK only, weekdays.
- **Keywords (phrase match):** "cyber essentials check", "website security
  check", "check my website security", "website vulnerability scan uk",
  "dmarc check", "ssl certificate checker", "small business cyber security".
- **Negative keywords:** jobs, course, training, free download, certification
  body, careers, salary.
- **Landing page:** the homepage with the free check; for Cyber Essentials
  terms, `/cyber-essentials`.
- **Ad text example:** "Free Website Security Check | Results in 30 Seconds" /
  "Plain-English fixes, mapped to Cyber Essentials. No sign-up needed."
- **Stop rule:** if cost per sign-up is above £30 after £150 spent, pause and
  rethink keywords or landing page.

## 8. First ten posts (LinkedIn first; shorten for X)

1. **Why I built Hebrides Cyber:** small businesses get the same attacks as
   big ones, without a security team. Link to the free check.
2. **"Try it on your own site":** a screenshot of a free check result
   (synthetic, labelled), what each line means.
3. **The email setup most small businesses get wrong:** what SPF, DKIM and
   DMARC are in one sentence each, and how to check yours.
4. **Certificates expire:** what happens when they do, how to never be caught
   out.
5. **"One thing to fix this week":** why one action beats a 40-page report.
6. **Cyber Essentials in plain English:** the five controls, and which ones a
   website scan can evidence.
7. **AI-driven attacks on small businesses:** the cost per target has fallen
   to a few dollars, so everyone's a target. What basic checks catch. (No tool
   names.)
8. **Your website platform matters:** fixes differ on WordPress, Shopify, Wix
   and Squarespace; we tailor them.
9. **Behind the scenes:** how we avoid false alarms (a failed lookup is never
   reported as "all clear").
10. **Ask:** "Run the free check and tell me the one thing it found. I'll reply
    with how to fix it."

## 9. AI help: what to use it for

Use AI tools (Claude, ChatGPT, or Grok on X) to draft posts, rewrite for each
platform and suggest replies. Read every post before it goes out, never
auto-post, never let AI invent statistics or customer stories, and keep the
rules in §1. Grok inside X is fine for drafting there; it doesn't change how X
ranks your posts.

## 10. Decisions for you

| # | Decision | Recommendation |
|---|---|---|
| A1 | Keep any Hebrides-local outreach (Facebook groups, local press) now that public copy says "Scotland"? | Drop it from launch; UK-wide B2B first |
| A2 | Lead message | The free check |
| A3 | Ads budget for the first month | £300 Google search only |
| A4 | Which email address the accounts use | admin@ with MFA |
| A5 | When to publish a case study | After the first customer agrees in writing |
