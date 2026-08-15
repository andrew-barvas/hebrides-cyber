# Technical Architecture

## Goals
- Fast static marketing site + dynamic dashboard for Security Score and client portal.
- Simple, secure, low-maintenance hosting.
- Integrate automated scanners, AI summarisation, and subscription billing.

## Recommended Stack

- **Frontend:** Next.js (App Router), deployed to Azure Static Web Apps (or Vercel).
- **Auth & DB:** Supabase (Postgres + Auth + Storage).
- **Serverless functions:** Azure Functions for scanner orchestration, webhook handlers, and report generation.
- **Scanning & tooling:**
  - Dependency scanning: Snyk CLI or `npm audit` + OSS Index, run in a serverless/container job.
  - TLS & headers: SSL Labs API or an `ssllabs-scan` wrapper.
  - Basic web checks: custom Playwright scripts + OWASP ZAP for automated scans.
  - Optional: Nikto/Nmap in isolated containers for deeper checks.
- **AI summarisation:** Azure OpenAI (or OpenAI API) to generate executive summaries and remediation text.
- **CI/CD:** GitHub Actions for deployments and scheduled scans.
- **Payments:** Stripe (subscriptions + one-off invoices).
- **Monitoring & logs:** Azure Application Insights or Sentry for errors; scan logs stored in Supabase or Azure Blob.
- **PDF reports:** Playwright (or Puppeteer) to render HTML → PDF for downloadable reports.
- **Notifications:** Slack, Teams, Email (SendGrid or Postmark).
- **Secrets:** Azure Key Vault (production) or Supabase secrets (dev); never stored in the repo.

## Data Flow (high level)

1. User signs up → Supabase Auth.
2. User requests a Security Score → serverless job runs automated checks (dependency scan, TLS, headers, basic OWASP).
3. Results stored in Postgres; Azure OpenAI summarises findings.
4. PDF generated and emailed; dashboard updated.
5. If subscribed, scheduled scans run weekly/monthly; alerts sent on critical findings.

## Security & Compliance Notes

- Run scanners from ephemeral containers or isolated serverless environments — never against production infra directly from a shared always-on process.
- Rate-limit scanning to avoid being blocked by targets or causing unintended load.
- Require proof of ownership (DNS TXT or file upload) before running any intrusive scan.
- Store PII minimally; encrypt sensitive data at rest and in transit.
- Provide a signed NDA / consent agreement for every pen test engagement.

## Relationship to the `hebridescyber-app` repo scaffold

This architecture matches the scaffold already generated: Next.js app in `src/app`, Supabase client in `src/lib/supabaseClient.ts`, Azure Functions stubs in `src/functions/run-scan` and `src/functions/generate-report`, Postgres schema in `sql/migrations/001_init.sql`, and GitHub Actions in `.github/workflows/`. The scanner logic in `run-scan/index.ts` is currently stubbed and needs real implementations (see repo TODOs).
