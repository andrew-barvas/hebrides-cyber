# Security Score Report Template

Purpose: a concise, automated report giving a quick, actionable view of a site's security posture. Used as a free lead magnet (one-page) and as the core of the paid monthly product (expanded dashboard + history).

---

## One-Page Security Score (automated, free tier)

**Header**
- Company / Site: example.com
- Date: 2026-08-14
- Score: 72 / 100 (visual gauge)

**Executive Summary** (2–3 plain-English sentences)
A short summary of the highest risks and recommended next steps, written for a non-technical business owner.

**Top 5 Findings** (priority order)

1. **Critical** — Missing HTTP security headers (HSTS absent). Impact: session hijack. Fix: add HSTS header and secure cookies.
2. **High** — Outdated dependency `express` v4.16, known CVE. Fix: upgrade to latest LTS and run tests.
3. **Medium** — Weak password policy on admin panel. Fix: enforce 12+ char minimum, add MFA.
4. **Low** — TLS uses ECDHE with SHA-1 fallback. Fix: reconfigure cipher suite.
5. **Info** — No DMARC record found. Fix: add DMARC for email protection.

**Automated Checks Included**
- TLS/SSL configuration (certificate, ciphers)
- HTTP security headers (HSTS, CSP, X-Frame-Options)
- Dependency vulnerability scan (Snyk / OSS Index)
- Open ports & exposed services (basic)
- DNS & email auth (SPF/DKIM/DMARC)
- Basic OWASP checks (injection, XSS surface)
- RLS / DB access checks (if a Supabase or DB connection is provided)

**Risk Breakdown**
Critical: 1 | High: 2 | Medium: 3 | Low: 4

**Action Plan**
1. Patch critical dependency and re-scan.
2. Add HSTS and secure cookie flags; deploy to staging first.
3. Enforce MFA for admin accounts and roll out the new password policy.

**Technical Appendix**
- Headers tested: [list]
- TLS grade: A-
- Top vulnerable packages: [list with CVE IDs]
- Tools used: automated scanner, dependency DB, TLS tester

**CTA**
Need help fixing these issues? Book a remediation session or subscribe to monthly monitoring.

---

## Full Monthly Report (paid tier, expanded)

- Historical score trend (sparkline)
- Full vulnerability list with CVE links and exploitability rating
- PR templates and code snippets for fixes (ready to paste into a GitHub PR body)
- CI/CD checklist and pipeline hardening suggestions
- Optional scheduled retest and verification after fixes are applied

## TODO
- [ ] Build the actual scoring algorithm (weighted by severity, exploitability, exposure)
- [ ] Wire this template into `generate-report/index.ts` in the app repo
- [ ] Decide on report branding — PDF header/footer, client logo placement for white-label (Agency tier)
