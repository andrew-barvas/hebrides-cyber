# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev          # Start dev server (Next.js 16 + Turbopack, port 3000)
npm run build        # Production build
npm run lint         # ESLint
npx tsc --noEmit     # TypeScript check — build does NOT run tsc, always run this separately
npm test             # Playwright e2e (builds app + starts server automatically — slow, hermetic)
npm run scan:local   # Run a real scan against a URL and persist to Supabase (needs SCAN_OWNER_ID)
npm run seed:users   # Create demo accounts in Supabase (admin, basic/pro/agency/no-plan)
```

## Environment

Copy `.env.example` to `.env.local`. Minimum to boot locally:

```
NEXT_PUBLIC_SUPABASE_URL=https://<project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon-key>
```

Without those, the app boots but all auth/data calls fail. The Supabase client logs a warning and uses a placeholder rather than throwing.

## Architecture

### Two API layers — don't confuse them

**`src/pages/api/`** — Next.js API routes, run in the same process as the app. Used for browser-facing, low-latency operations: Stripe webhooks/checkout/portal, admin panel endpoints, contact form. These have access to `NEXT_PUBLIC_*` env vars alongside server-only vars.

**`src/functions/`** — Azure Functions (HTTP-triggered). Used for heavy compute: `run-scan` (the full scanner pipeline), `generate-report` (Playwright PDF), `generate-fix-pr`, `generate-newsletter`, `verify-ownership`. Called from the browser via `NEXT_PUBLIC_AZURE_FUNCTIONS_URL`. The Functions use `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (server-only) directly — never the anon key.

### Two routers in one Next.js app

- **App Router** (`src/app/`) — all pages and layouts
- **Pages Router** (`src/pages/api/`) — API routes only

### Supabase access pattern

| Context | Client | Key used |
|---------|--------|----------|
| Browser (dashboard, login) | `src/lib/supabaseClient.ts` | anon key — RLS enforced |
| API routes & Functions | `createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)` | service role — bypasses RLS |
| Admin API routes | service role for writes; anon client to verify the caller's JWT | both |

`SUPABASE_SERVICE_ROLE_KEY` must never appear in a `NEXT_PUBLIC_*` var or any client bundle.

### Scan flow (two-step proof of ownership)

1. Dashboard POSTs `{ targetUrl }` to `run-scan` → Function creates a `scans` row (status `pending`) and returns `{ scanId, proofToken }`.
2. Dashboard POSTs `{ scanId }` with `X-Scan-Token: <proofToken>` → Function verifies ownership, runs the scanner pipeline, writes to `scan_results`.

Scheduled scans (`scheduled-scans.yml`) follow the same two-call flow but authenticate via `X-Service-Token` instead of a user JWT.

Set `ALLOW_DEV_TOKEN_VERIFICATION=false` in production to require real DNS/file ownership verification (see `src/lib/ownership.ts`) rather than the echo-token shortcut.

### Scanner pipeline

`src/lib/scanners/` — individual check modules:
- `tls.ts` — certificate grade and expiry
- `headers.ts` — security header presence
- `dns.ts` — SPF, DMARC
- `exposure.ts` — sensitive paths (.env, .git, phpinfo, etc.)
- `fingerprint.ts` — technology detection (WordPress etc.)
- `ports.ts` — common open ports via Shodan InternetDB
- `recon.ts` — IP resolution, Shodan CVEs, crt.sh subdomain enumeration
- `webapp.ts` — robots.txt, HTTP OPTIONS, error disclosure, WordPress deep scan, CORS reflected-origin, JS library versions
- `playwright.ts` — headless browser checks (stub; Playwright not in package.json yet)
- `zap.ts` — OWASP ZAP active scan (stub; needs `ZAP_API_URL`)

`src/lib/scanners/index.ts` wires all modules into `runAllChecks()` and `summariseResults()`. When adding a new check, export its result type from the module, add it to `ScanResults` in index.ts, and add finding entries in `summariseResults()`.

### Theme system

Tailwind `darkMode: 'class'`. `ThemeScript` in `src/app/layout.tsx` adds `dark` to `<html>` on load unless `localStorage.getItem('hc-theme') === 'light'`. Default is dark (cyber theme).

**Cyber palette** (always use these, not raw hex):
- `bg-cyberbg` / `bg-cyberpanel` — page and card backgrounds
- `border-cyberborder` — borders on dark surfaces
- `text-neon` / `bg-neon` — primary accent (#39FFC0); `shadow-glowsm` / `shadow-glow` for neon glow effects
- `text-atlantic` / `bg-atlantic` — primary on light surfaces
- `text-seafoam` / `bg-seafoam` — secondary accent on light surfaces

The dashboard, admin, and all auth pages are always-dark (no `dark:` variants needed). Marketing pages that support both themes use `dark:` prefix.

### Database schema

Key tables (all in `sql/migrations/`):
- `users` — profile data keyed to `auth.users`; `is_admin` grants admin panel access
- `subscriptions` — plan, status, slack_webhook_url; kept in sync by Stripe webhooks
- `scans` + `scan_results` — scan records and findings/score; RLS-protected by owner
- `monitored_targets` — agency-tier sites for nightly scheduled scans
- `contact_enquiries` — contact form submissions; service-role only (no browser RLS policy)
- `verifications` — domain ownership tokens

RLS is enabled on all tables. The only code path that bypasses it is server-side code using the service role key.

### Rate limiting

`src/lib/rateLimit.ts` uses Upstash Redis (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`) for shared-state rate limiting across Function instances. Falls back to an in-memory `Map` in dev — not safe across instances; don't rely on it in production.

### Payments

Stripe webhooks at `src/pages/api/stripe/webhook.ts` update `subscriptions` on `checkout.session.completed`, `invoice.payment_failed`, and `customer.subscription.deleted`. Requires `STRIPE_WEBHOOK_SECRET` and the three `STRIPE_PRICE_*` env vars (see `.env.example`).

### E2E tests

Playwright config (`playwright.config.ts`) hardcodes `NEXT_PUBLIC_SUPABASE_URL=https://example-project.supabase.co` for all test runs — tests seed `localStorage` with `sb-example-project-auth-token` and mock `*.example-project.supabase.co` network requests. Never use real Supabase credentials in e2e tests; the hardcoded project ref must stay `example-project`.

### Deployment

Azure Static Web Apps hybrid mode (not pure static export). `staticwebapp.config.json` controls HTTP headers (CSP, HSTS, COOP, CORP, X-Frame-Options, etc.) and routing rules — Next.js `headers()` in `next.config.mjs` is not used since SWA handles it at the CDN layer.
