-- One evergreen post for people searching for a replacement for the NCSC's
-- retired Web Check and Mail Check services. Same table and rules as
-- 001_blog_posts.sql: run it in the Supabase SQL editor; idempotent
-- (ON CONFLICT (slug) DO NOTHING).
--
-- Facts are limited to what /web-check-alternative already states and cites
-- (the NCSC's retirement notice and EASM buyer's guide). Re-check them against
-- those two NCSC pages before re-using this text anywhere else.

insert into public.blog_posts (slug, title, excerpt, body, published_at, status) values

('ncsc-web-check-mail-check-retired-what-to-do',
 'NCSC Web Check and Mail Check Have Been Retired: What UK Organisations Should Do Now',
 'The NCSC switched off its free Web Check and Mail Check services on 31 March 2026. Here is what they checked, what you can do yourself for free, and how to choose a replacement.',
$md$## What happened

On 31 March 2026 the National Cyber Security Centre retired **Web Check** and **Mail Check**, the free services that thousands of UK public bodies, charities and small businesses used to spot website misconfigurations and email-spoofing risks. The NCSC's reasoning is that the commercial External Attack Surface Management (EASM) market has matured, and it only runs services the market can't. It has published an [EASM buyer's guide](https://www.ncsc.gov.uk/guidance/external-attack-surface-management-buyers-guide) to help organisations pick a replacement ([retirement notice](https://www.ncsc.gov.uk/blog-post/retiring-mail-check-web-check)).

The NCSC's free **Early Warning** service continues. It does something different: it tells you about malicious activity and known vulnerabilities on your IP addresses. If you aren't signed up, do that first. It's free and it's still running.

## What you lost

**Web Check** looked at your website from the outside:

- TLS/HTTPS configuration and certificate problems
- missing HTTP security headers
- DNS configuration issues
- out-of-date software with known vulnerabilities
- exposed files and services that shouldn't be public

**Mail Check** looked at whether your domain could be used to send convincing fake email:

- SPF, DKIM and DMARC records, and whether DMARC actually enforces anything
- whether mail between servers is encrypted (MTA-STS and TLS-RPT)
- DMARC aggregate reports, which show who is sending email as your domain

Nothing here stopped mattering on 31 March. Attackers still look for exactly these things, and a domain without an enforcing DMARC policy can still be spoofed in a phishing email to your customers.

## What you can check yourself today, for free

1. **Your certificate.** Click the padlock in your browser. Check the expiry date, and that it's issued to your exact domain.
2. **Your DMARC record.** Look up the TXT record at `_dmarc.yourdomain.co.uk`. If it says `p=none`, spoofed email is reported but still delivered. Plan to move to `p=quarantine`, then `p=reject`, once your own sending services all pass.
3. **Your domain's renewal date.** An expired domain takes your website and email down together. Turn on auto-renew and registrar transfer lock.
4. **Early Warning.** Make sure you are registered for the NCSC's service.

These are worth doing, but they are a one-off snapshot. What made Web Check and Mail Check useful was that they kept looking.

## Choosing a replacement

Start with the NCSC's buyer's guide. Whatever you choose, ask these questions:

- **Does it cover both halves?** Website configuration *and* email security, not just one.
- **Does it keep looking?** Scheduled rescans, with alerts when something new appears, not just a one-off report.
- **Does it prove its findings?** A tool that reports a problem on every site that answers every URL with its homepage will bury the real issues in noise. Ask how false positives are handled.
- **Does it tell you how to fix things?** In plain English, for the technology you actually run.
- **Is it honest about what it doesn't cover?** No external scan can see inside your office network or check your laptops' patch levels.
- **Does the price fit?** Some EASM products are priced for enterprises. A small organisation shouldn't need an enterprise contract to replace a free government service.

## How Hebrides Cyber fits

We built Hebrides Cyber for exactly this gap. Our [Web Check alternative page](/web-check-alternative) maps each retired check to what we do, row by row, including the parts we only partly cover. We check the subdomains visible in public certificate logs, but we don't yet run continuous discovery of unknown assets, and we don't yet receive DMARC aggregate reports.

Every finding is also mapped to the [Cyber Essentials](/cyber-essentials) control it affects, which helps if you are preparing to certify. You can run one free scan against a domain you own, with no card required.

*Hebrides Cyber is independent and is not affiliated with or endorsed by the NCSC.*
$md$,
 '2026-10-06 07:00:00+00',
 'published')

on conflict (slug) do nothing;
