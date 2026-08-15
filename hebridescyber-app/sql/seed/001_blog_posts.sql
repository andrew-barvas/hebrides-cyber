-- Seed data for the /blog section (public_posts table: sql/migrations/001_init.sql).
--
-- Run this in the Supabase SQL editor AFTER 001_init.sql. Idempotent —
-- ON CONFLICT (slug) DO NOTHING means it's safe to re-run.
--
-- Mix of real, sourced recent incidents (each cites where the facts came
-- from — verify independently before repeating these claims anywhere
-- formal, journalism moves fast and figures get revised) and evergreen
-- educational posts tied to this product's own features. Dates are spaced
-- weekly (Mondays) to look like a real posting cadence up to today
-- (2026-08-15) — going forward, generate-newsletter (src/lib/newsletter.ts)
-- takes over and writes real ones grounded in this app's own scan data.

insert into public.blog_posts (slug, title, excerpt, body_markdown, published_at) values

('hyundai-turkiye-ransomware-recruitment-data',
 'CRPx0 Ransomware Hits Hyundai Turkey: Why Recruitment Data Is a Bigger Target Than You Think',
 'A late-July 2026 attack on Hyundai Motor Türkiye''s recruitment systems shows why HR and hiring data deserves the same protection as financial records.',
$md$## What happened

On 31 July 2026, the ransomware group CRPx0 claimed an attack on Hyundai Motor Türkiye, publishing roughly 1.5GB of stolen data on its leak site. Unlike a typical customer-data breach, what CRPx0 took was HR and recruitment material: candidate assessment results, proctored exam data, and executive assessment reports. The group listed Tox and Session messenger IDs for ransom negotiation — a deliberate choice to avoid centralised infrastructure that could be seized.

This isn't Hyundai's first brush with ransomware. Its European division was hit by Black Basta in 2024, and Hyundai AutoEver America disclosed a breach affecting millions of customer records in 2025. Three incidents in three years at the same corporate group suggests the problem isn't one bad afternoon — it's a pattern.

## Why this matters if you're not a car manufacturer

Recruitment and HR platforms are consistently under-scrutinised compared to finance or customer databases, even though they hold exactly the kind of sensitive personal data — assessments, background checks, salary expectations — that's valuable to attackers and painful to have leaked. If your business uses a third-party applicant tracking system, an HR SaaS tool, or even a shared drive for CVs and interview notes, it's worth asking the same questions you'd ask about your customer database: who has access, is it backed up separately, and would you know if someone exported it all at once?

## What to actually do

- Audit who has access to your recruitment/HR tools — ex-employees and old integrations are the usual culprits.
- Don't assume a "small" HR dataset isn't worth protecting — assessment and interview data is personal data under GDPR regardless of size.
- If you use a third-party HR platform, ask about their own security posture — you're trusting them with your candidates' data.

Repeat incidents at the same organisation are a reminder that a one-off audit isn't enough — [continuous monitoring](/pricing) catches drift that a single point-in-time check misses.

*Sources: [GBHackers](https://gbhackers.com/crpx0-ransomware-claims-hyundai-turkey-breach/), [CyberPress](https://cyberpress.org/crpx0-ransomware-claims-hyundai-turkey-breach/)*
$md$,
 '2026-08-10T08:00:00Z'),

('uk-ransomware-2026-sme-stats',
 '323 UK Firms Hit by Ransomware in a Year — More Than Half Were SMEs',
 'City of London Police data shows small and medium businesses now bear the brunt of UK ransomware attacks, with average losses up 50% year on year.',
$md$## The numbers

City of London Police reported that 323 organisations disclosed ransomware attacks in the UK between April 2025 and March 2026 — more than 26 successful attacks every month. Over half of those reports (175) came from small and medium enterprises. Average reported financial losses reached around £270,000, a 50% increase on the previous year, and police believe the real figure is higher because businesses under-report losses.

Manufacturing was hit hardest (42 reports), followed by scientific and technical services (21) and education (19).

## Why attackers prefer small businesses

It's counterintuitive, but a well-defended large enterprise is often a worse target than a small firm with an unpatched firewall. Ransomware operators aren't chasing headlines — they're chasing the path of least resistance. SMEs are more likely to lack a dedicated incident response capability, run unpatched edge devices, and pay out quickly because downtime is existential rather than merely expensive.

## What actually reduces risk

Police and industry guidance converge on the same short list:

1. **Backups that are tested and kept offline** — a backup you've never restored from isn't a backup, it's a hope.
2. **Patch management** — most ransomware entry points are known vulnerabilities in software that hasn't been updated, not novel zero-days.
3. **Access controls** — MFA everywhere, least-privilege accounts, no shared admin logins.
4. **Follow NCSC guidance** — the UK's National Cyber Security Centre publishes free, small-business-specific advice.

If you don't currently have anything watching for the second point — outdated dependencies and missing patches — a [Security Score scan](/dashboard) covers exactly that ground automatically.

*Sources: [City of London Police](https://www.cityoflondon.police.uk/news/city-of-london/news/2026/june/dont-pay-the-ransom-warning-to-organisations-to-protect-themselves-from-ransomware-attacks-as-more-than-320-businesses-affected-last-year), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/over-300-uk-firms-hit-ransomware/)*
$md$,
 '2026-08-03T08:00:00Z'),

('klue-supply-chain-breach-third-party-risk',
 'One Leaked Credential From 2022, ~200 Companies Breached: The Klue Supply-Chain Lesson',
 'Market research vendor Klue was breached using a credential issued for a 2022 pilot — and the fallout hit customers including HackerOne, LastPass, and Jamf.',
$md$## What happened

Market research provider Klue was compromised by an extortion group tracked as "Icarus," which broke in using a credential Klue had issued back in 2022 for a limited product pilot — and apparently never revoked. The fallout spread to roughly 200 of Klue's customers, several of them cybersecurity companies you'd expect to know better, including Jamf, HackerOne, and LastPass.

## The uncomfortable lesson

The specific detail that matters here isn't the attacker's name — it's that the point of failure was a four-year-old credential from a pilot program nobody remembered to clean up. This is one of the most common ways breaches actually happen: not a sophisticated zero-day, but a forgotten API key, a test account with real permissions, or a contractor's access that was never revoked.

It's also a supply-chain story. None of Klue's affected customers did anything wrong themselves — they trusted a vendor, and the vendor's housekeeping failure became their incident to manage.

## What to check in your own business

- **Inventory every third-party integration and API key** your business has ever issued — most companies genuinely don't have a complete list.
- **Set expiry dates on pilot/trial credentials** by default, so "temporary" access doesn't quietly become permanent.
- **Ask vendors about credential lifecycle policy** before handing them data — "do you rotate and expire unused access?" is a fair question to ask any supplier.
- **Least privilege** — a credential issued for a limited pilot should never have had the scope to cause a 200-company incident.

A [CI/CD and secrets management review](/services) is specifically designed to catch exactly this class of problem before it becomes a headline.

*Sources: roundup reporting via [TechCrunch](https://techcrunch.com/2026/07/07/the-worst-hacks-and-breaches-of-2026-so-far/) and [TechRepublic](https://www.techrepublic.com/article/news-biggest-data-breaches-2026-ranked-impact/)*
$md$,
 '2026-07-27T08:00:00Z'),

('conduent-healthcare-breach-vendor-liability',
 '62.2 Million Records: The Conduent Breach and Why "We''re Just a Vendor" Isn''t a Defence',
 'Conduent''s breach became the third-largest in US healthcare history after its confirmed victim count nearly tripled — a reminder that vendors carry the same breach obligations as the businesses they serve.',
$md$## What happened

Conduent Business Services, which provides back-office processing, billing, and document handling for health plans, government agencies, and large employers, discovered on 13 January 2025 that attackers had been inside its network since the previous October. The SafePay ransomware group claimed responsibility for stealing multiple terabytes of data.

The scale kept growing. As of February 2026, state regulators had confirmed around 25 million affected individuals. By mid-2026, the US Department of Health and Human Services' Office for Civil Rights confirmed the real number: 62,224,658 people — making it the third-largest healthcare data breach ever recorded, behind only the 2024 Change Healthcare breach (192.7 million records) and the 2015 Anthem breach (78.8 million).

Conduent's direct breach-response costs hit $25 million in Q1 2025 alone, with a further $16 million anticipated through Q1 2026.

## Why this matters even if you're not a healthcare giant

Conduent isn't a healthcare provider itself — it's a *business associate*, a vendor that processes data on behalf of the organisations that actually hold the customer relationship. Under both US HIPAA rules and UK/EU GDPR's equivalent "data processor" obligations, that distinction doesn't reduce liability. If your business handles data on behalf of another company — payment processing, booking systems, appointment scheduling, printing and mailing — you carry real breach-notification and security obligations even though you're not the brand the end customer thinks they're dealing with.

## What smaller processors and subcontractors should check

- Do you actually know what data-processing obligations are in your contracts with the businesses you work for?
- Do you have cyber insurance, and does it cover incident response costs at a scale that matters to your business?
- Would you detect an intrusion in under three months? Conduent's attackers had roughly that long before discovery.

*Sources: [Paubox](https://www.paubox.com/blog/conduent-breach-hits-62m-ranking-third-largest-in-us-healthcare-history), [HIPAA Journal](https://www.hipaajournal.com/conduent-business-solutions-data-breach/)*
$md$,
 '2026-07-20T08:00:00Z'),

('charter-communications-breach-42-million',
 'Charter Communications: Tens of Millions of Records Stolen and Published — What Extortion-Only Attacks Mean for You',
 'No ransomware, no encryption — just theft and a public leak site. Charter''s May 2026 breach shows attackers increasingly skip encryption entirely.',
$md$## What happened

In May 2026, an extortion group stole data from Charter Communications — reporting put the stolen records at over 42 million and the number of affected individuals at close to 5 million — and published it on a leak site rather than deploying ransomware to encrypt Charter's systems.

## The shift worth noticing

Classic ransomware follows a familiar shape: encrypt the victim's files, demand payment for the decryption key, and backups are your main defence. A growing number of attacks now skip the encryption step entirely. The attacker copies the data and threatens to publish it unless paid — "extortion-only." Your backups don't help here, because nothing was ever locked; the threat is exposure, not downtime.

## What actually reduces exposure to this specific threat

- **Data minimisation.** The single most effective defence against a leak is not holding data you don't need. Old customer records, historic form submissions, and abandoned databases are pure liability with no upside.
- **Encryption at rest.** If data is stolen but unreadable without a key attackers don't have, the leak threat loses most of its teeth.
- **Export/access logging.** A sudden bulk export of a customer table is detectable *if* something is watching for it — most small business setups don't log this at all.
- **Know what you'd say.** Extortion-only incidents move fast once the leak site goes up; having a basic incident response plan (who do you tell, in what order, by when) matters more than people expect.

*Source: roundup reporting via [TechCrunch](https://techcrunch.com/2026/07/07/the-worst-hacks-and-breaches-of-2026-so-far/)*
$md$,
 '2026-07-13T08:00:00Z'),

('mfa-best-value-security-upgrade',
 'Multi-Factor Authentication: The Best Free Security Upgrade for a Small Business',
 'Stolen and reused passwords power a huge share of the account breaches in this list. A free authenticator app closes that door in about five minutes.',
$md$## Why passwords alone aren't enough

Look back through the incidents above and a theme emerges: stolen credentials, reused logins, and compromised employee accounts show up again and again as the way attackers get in. Passwords get reused across sites, phished, or simply guessed — and once an attacker has one, a bare password is no obstacle at all.

Multi-factor authentication (MFA) adds a second check — usually a time-based code from an authenticator app — so a stolen password alone isn't enough to log in. It's one of the highest-value security changes a small business can make, and unlike most of the advice in this newsletter, it's free and takes about five minutes to set up.

## A few things worth knowing

- **App-based codes (TOTP) beat SMS.** Text-message codes can be intercepted via SIM-swapping; an authenticator app (Google Authenticator, Authy, 1Password, etc.) doesn't have that weakness.
- **MFA isn't a silver bullet.** Sophisticated phishing kits can relay both your password and your MFA code in real time ("adversary-in-the-middle" attacks). It's a very high bar for most attackers, but not an absolute one — hardware security keys or passkeys are the next step up if you need stronger protection for high-value accounts.
- **Turn it on everywhere it matters first**: email (the master key to almost every password reset), your domain registrar, your hosting/cloud provider, and any financial accounts.

If you're a Hebrides Cyber customer, you can enable TOTP two-factor on your own account right now from [Account → Security](/account/security) — it's built on Supabase's standard MFA implementation, no extra app required beyond an authenticator.

$md$,
 '2026-07-06T08:00:00Z'),

('security-headers-five-minute-fix',
 'Five HTTP Headers Every Small Business Website Should Set (And None of Them Cost Anything)',
 'Missing security headers are the single most common finding in our Security Score scans. Here''s what each one does and how to add them.',
$md$## The most common finding we see

Across Security Score scans, missing HTTP security headers are consistently the top finding — more common than outdated libraries, weak TLS, or anything else. The good news: they cost nothing, take minutes to add, and meaningfully reduce several common attack classes.

## The five headers

**Strict-Transport-Security (HSTS)** — tells browsers to always use HTTPS for your domain, even if someone types `http://`. Prevents downgrade attacks on public wifi.

**Content-Security-Policy (CSP)** — restricts which sources a page is allowed to load scripts/styles/images from. The single strongest defence against cross-site scripting, though it takes the most tuning to get right without breaking your own site.

**X-Frame-Options** — stops your site being loaded inside an `<iframe>` on someone else's page, which blocks "clickjacking" attacks that trick users into clicking something disguised as your UI.

**X-Content-Type-Options** — set to `nosniff`, this stops browsers guessing (and misinterpreting) file types in a way attackers can exploit.

**Referrer-Policy** — controls how much of your URL gets leaked to other sites when a user clicks a link away from you, which matters more than people expect if any of your URLs contain sensitive query parameters.

## If you're running Next.js

```js
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Content-Security-Policy", value: "default-src 'self'" },
        ],
      },
    ];
  },
};
```

Adjust the CSP `default-src` to actually match what your site loads — a too-strict policy silently breaks pages rather than erroring loudly, so test after changing it.

Not sure which of these your own site is missing? [Run a free Security Score scan](/dashboard) and it'll tell you in about a minute.
$md$,
 '2026-06-29T08:00:00Z')

on conflict (slug) do nothing;
