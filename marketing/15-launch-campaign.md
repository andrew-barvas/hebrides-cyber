# Launch Campaign — 8-Week Plan

Practical, executable campaign plan for a solo founder. Sequenced so
earlier weeks build the foundation for later weeks' outreach. Assumes
social media accounts are registered (see
`marketing/11-social-media-and-local-press-playbook.md` §8) and the
product is live with a real domain.

Companion to `marketing/06-marketing-plan.md` (channel priorities/KPIs)
and `marketing/11-social-media-and-local-press-playbook.md` (platform
setup, bio copy, content pillars, first 10 posts).

---

## Week 1-2: Foundation

**Goal**: establish online presence and publish the first content.

### Actions

| Day | What | Platform | Time |
|---|---|---|---|
| 1 | Register @hebridescyber on LinkedIn, Facebook, X | All | 30 min |
| 1 | Paste bio copy, upload profile/banner images | All | 15 min |
| 1 | Post 1: Founder story | LinkedIn | 10 min |
| 2 | Join 3-5 local Facebook groups (Lewis/Hebrides business groups) | Facebook | 15 min |
| 3 | Post 2: Why affordable security matters | LinkedIn | 10 min |
| 4 | Introduce yourself in local Facebook groups (personal, not salesy) | Facebook | 15 min |
| 5 | Post 3: Product announcement | LinkedIn | 10 min |
| 7 | Post 4: Local community free scan offer | Facebook | 10 min |
| 8 | Post 5: Cyber Essentials explainer | LinkedIn | 10 min |
| 10 | Post 6: "This week in cyber" (from daily blog content) | X/Twitter | 10 min |

**Time commitment**: ~2.5 hours total across 2 weeks.

### Milestone check

- [ ] 3 platforms live with consistent branding
- [ ] 6 posts published
- [ ] At least 1 local Facebook group joined and introduced

---

## Week 3-4: Local Outreach

**Goal**: direct contact with local businesses and local press.

### Actions

| What | How | Time |
|---|---|---|
| Free scan offer in local Facebook groups | Post offering free scans for any local business — personal, helpful tone | 15 min |
| Cold outreach to 20 local businesses | Use templates from `marketing/07-cold-outreach-emails.md`, adapted for local context. Source businesses from: Comhairle business directory, Business Gateway Outer Hebrides, tourism board, local Google Maps results for "Lewis businesses with websites" | 2-3 hours |
| Press release to Stornoway Gazette | Adapt template from `marketing/11-social-media-and-local-press-playbook.md` §7. Hook: "Stornoway man launches cybersecurity business offering free scans to local businesses" | 30 min |
| Press release to West Highland Free Press | Same release, adapted if needed | 15 min |
| Email Business Gateway Scotland adviser | Request a meeting to discuss the business, mentioning the HIE grant application | 15 min |
| Publish first blog post | "5 Things Every Small Business Website Gets Wrong About Security" — write using Claude/ChatGPT for a draft, then edit for voice and accuracy | 1-2 hours |
| Continue social posting | Posts 7-10 from the playbook | 40 min |

**Time commitment**: ~5-6 hours total across 2 weeks.

### Milestone check

- [ ] 20 cold outreach emails sent
- [ ] At least 2 press contacts reached
- [ ] Business Gateway meeting requested
- [ ] First blog post published
- [ ] At least 3 local businesses have received their free scan

---

## Week 5-6: Content Engine

**Goal**: build shareable, technical content that demonstrates expertise.

### Actions

| What | How | Time |
|---|---|---|
| LinkedIn article: remediation PR walkthrough | Show the four-rung remediation ladder with a real (anonymised) example. The before/after diff is the best demo asset this product has | 1-2 hours |
| Screen recording demo | 2-minute Loom or similar showing: sign up → run scan → read report → see findings with fix instructions. No editing needed — raw is more authentic | 30 min |
| Cyber Essentials mapping explainer | "What CE actually checks vs what we check" — a comparison table showing how Hebrides Cyber's automated checks map to each of the 5 CE themes | 1 hour |
| Repurpose daily blog into social content | Pick 1 daily blog post per week, turn it into a LinkedIn post with commentary. Use AI to draft variations for X/Twitter | 30 min/week |
| Cross-post to X/Twitter | 3x/week, adapted from LinkedIn content + daily blog highlights. Use #cybersecurity #infosec #CyberEssentials | 15 min/post |

**Time commitment**: ~4-5 hours total across 2 weeks.

### Milestone check

- [ ] Screen recording demo published (linked from social profiles + website)
- [ ] At least 1 LinkedIn article with 10+ engagements
- [ ] Consistent 5x/week posting cadence across platforms

---

## Week 7-8: Conversion Push

**Goal**: turn awareness into paying customers.

### Actions

| What | How | Time |
|---|---|---|
| Google Ads test campaign | £200 budget on "cyber essentials scan UK small business," "website security check UK," "affordable pen test UK." Use Google Ads Smart Campaign for simplicity | 1 hour setup, then monitor |
| First case study | Even if self-scan of a consenting local business. Structure: "What we found → What it meant → What we fixed → Current score." Get permission to name the business if possible | 2 hours |
| Follow up with free-scan recipients | Email every business that received a free scan: "Here's what we found — upgrade to Basic (£15/month with your local discount) for weekly monitoring" | 1-2 hours |
| Submit HIE grant application | Use `marketing/12-hie-grant-application.md` as the base. Adapt to the specific application form if required | 2-3 hours |
| BBC Alba / BBC Radio nan Gaidheal pitch | "Local man launches cybersecurity business from Stornoway" — the Gaelic-language angle is genuinely newsworthy for these outlets specifically | 30 min |

**Time commitment**: ~7-8 hours total across 2 weeks.

### Milestone check

- [ ] Google Ads running with at least 100 impressions
- [ ] 1 case study published
- [ ] All free-scan recipients followed up
- [ ] HIE grant application submitted
- [ ] At least 1 paying customer

---

## AI Content Generation Tools

### What to use AI for

| Task | Tool | How |
|---|---|---|
| Blog post drafts | Claude or ChatGPT | Provide the topic + key points + daily blog data as context. Always edit for voice, accuracy, and UK English |
| Social media post variations | Claude or ChatGPT | Provide one master post, ask for 3 platform-adapted versions (LinkedIn/Facebook/X) |
| Email subject line A/B testing | Claude or ChatGPT | Provide the email body, ask for 5 subject line options |
| Press release drafts | Claude or ChatGPT | Provide the news hook + key facts, edit the output heavily for local tone |
| Social media graphics | Canva AI | Use brand colours from `marketing/02-branding.md` (atlantic #0B1D3A, neon #39FFC0, white text) |
| "This week in cyber" posts | Daily blog pipeline | Repurpose `generate-daily-blog.ts` output into social posts — the data is already sourced from real CVE/KEV/news feeds |

### What NOT to use AI for

- **Testimonials** — must be real quotes from real customers
- **Case studies** — must be factual, based on real scans with permission
- **Technical claims** — must be code-verified per the project's own
  evidence discipline (`docs/SCANNER-CONVENTIONS.md`)
- **Grant applications** — AI can draft, but every figure and claim must
  be verified by the founder before submission

---

## Sustainable Posting Cadence (Post-Launch)

For a solo founder, this is the maximum sustainable cadence without
content quality dropping:

| Platform | Frequency | Best time | Content type |
|---|---|---|---|
| LinkedIn | 2x/week | Tuesday + Thursday, 8-9am | Professional: product features, compliance, founder story, case studies |
| Facebook | 1x/week + ad-hoc in local groups | Wednesday, 10am | Local: community offers, workshop announcements, local business stories |
| X/Twitter | 3x/week | Mon/Wed/Fri, 12pm | Technical: "this week in cyber," dev tips, CI gate showcase, before/after diffs |

**Content pipeline** (weekly rhythm):
1. Monday: scan daily blog posts from the past week, pick 1 to expand
2. Tuesday: publish LinkedIn post (10 min to write, using AI for draft)
3. Wednesday: publish Facebook post (5 min, adapted from LinkedIn)
4. Thursday: publish second LinkedIn post
5. Friday: batch-create 2-3 X/Twitter posts for the following week

**Monthly**: 1 evergreen piece (remediation walkthrough, compliance guide,
or local case study) — 2-3 hours.

**Quarterly**: refresh competitive analysis, update grant narrative if
needed, review posting analytics and adjust.

---

## Budget Summary

| Item | Amount | Period |
|---|---|---|
| Google Ads test | £200 | One-off (week 7-8) |
| Canva Pro (optional) | £100/year | Annual |
| Loom (free tier) | £0 | — |
| Total domain registrations | £50-100 | One-off |
| **Total launch campaign cost** | **~£350-400** | 8 weeks |

Everything else (social media posting, cold outreach, press releases,
blog posts) is time, not money. The campaign is designed for a solo
founder with no marketing budget beyond the Google Ads test.
