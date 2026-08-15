# Production Roadmap — Idea to Live Site

Current state: working local MVP (marketing pages, dashboard UI with a
functional "run a scan" form, Supabase schema, run-scan/generate-report
Functions, Stripe webhook that writes to `subscriptions`, dynamic
scheduled-scans workflow, and a Playwright e2e test suite). Nothing is
deployed. Scanner logic (`src/lib/scanners.ts`) and the ownership
verification flow are intentionally still stubs pending real
implementation — see `docs/security.md`.

This roadmap sequences the remaining work into stages. Each stage lists
what has to happen and roughly what depends on what. Hand this to a future
Cowork session (or work through it yourself) one stage at a time.

## Stage 0 — Local verification (partially blocked in this sandbox)

- [x] All files written and structurally verified (JSON valid, file tree
      matches spec).
- [ ] **You need to do this part yourself:** this sandbox has no internet
      access to npm's registry, so `npm install` could not be run here.
      On your own PC, in the connected folder:
      ```
      cd hebridescyber-app
      npm install
      npm run dev
      ```
      Re-run `npm install` any time `package.json` changes (new
      dependencies land there regularly as scaffold features get added) —
      a stale `node_modules` is the usual cause of "Cannot find module"
      errors like the `@tailwindcss/typography` one seen during review.
      Also run `npm audit` after installing; `next` is pinned to
      `^14.2.25` specifically to pull in the fix for the critical
      middleware auth-bypass CVE (GHSA-f82v-jwr5-mffw) — don't downgrade
      it below that floor.
      Then open http://localhost:3000 and click through Home, Services,
      Pricing, Contact, and Dashboard. Report back anything that breaks —
      it's untested beyond static review.

## Stage 1 — Real Supabase project

- [ ] Create a Supabase project (free tier).
- [ ] Run `sql/migrations/001_init.sql` in the SQL editor.
- [ ] Copy the project URL + anon key into `.env.local`.
- [ ] Sign up a test user via magic link and confirm the dashboard shows
      "no scans yet" instead of "sign in required."

## Stage 2 — Domain & branding

- [ ] Register hebridescyber.com.
- [ ] Produce a real logo from the concept in `marketing/02-branding.md`
      (commission one or generate with an AI image tool) — swap the
      placeholder text logo in `Header.tsx` for it.

## Stage 3 — Azure infrastructure

- [ ] Provision resources using either `azure/terraform/main.tf` or
      `azure/cli-scripts/provision.sh` (see `09-azure-provisioning-prompt.md`
      for a ready-to-use Claude prompt for this step).
- [ ] Apply for Azure OpenAI access if not already approved on the
      subscription — this has an approval delay, start it early.
- [ ] Store real secrets in Key Vault; wire Function app settings to
      reference them.

## Stage 4 — Payments

- [ ] Create Stripe account, add products/prices matching
      `src/app/pricing/page.tsx`.
- [ ] Wire the "Get started" buttons on the pricing page to Stripe
      Checkout.
- [ ] Test the webhook handler (`src/pages/api/stripe/webhook.ts`) against
      Stripe's test mode and CLI (`stripe listen --forward-to`).

## Stage 5 — Real scanning

- [ ] Replace the stubs in `src/functions/run-scan/index.ts` one at a time:
      dependency scan (Snyk/npm audit), TLS & header check (SSL Labs API),
      Playwright page load, OWASP ZAP baseline scan.
- [ ] Build the proof-of-ownership verification flow described in
      `docs/security.md` (DNS TXT or file upload) — do not let real scans
      run without it.
- [ ] Add rate limiting and concurrency controls to `run-scan`.
- [ ] Move heavy scanners into isolated containers (Azure Container
      Instances) per `docs/security.md`.

## Stage 6 — CI/CD & go-live

- [ ] Set all GitHub Secrets listed in `README.md`.
- [ ] Push to `main`, confirm `deploy.yml` succeeds.
- [ ] Point DNS at the Static Web App, verify managed SSL provisions.
- [ ] Replace the hardcoded target list in `scheduled-scans.yml` with a
      dynamic query against the `subscriptions` table.

## Stage 7 — Legal & operational

- [ ] Get professional indemnity insurance before selling pen test
      engagements.
- [ ] Draft NDA / MSA templates (see `docs/security.md` for the consent
      template starting point).
- [ ] Implement the 90-day data retention cleanup job.
- [ ] Confirm VAT/registration status before publishing prices live.

## Stage 8 — Launch marketing

- [ ] Work through `marketing/06-marketing-plan.md` and
      `marketing/07-cold-outreach-emails.md` — local outreach first
      (fastest feedback loop), then remote/content channels.
- [ ] Seed the homepage testimonials once the first 2–3 clients are done.

---

Suggested order if you want the fastest path to your *first paying
customer* rather than full completeness: Stage 1 → Stage 0 (verify
locally) → Stage 2 (domain) → Stage 3 (Azure) → Stage 6 (deploy what
exists, even with stub scanning disclosed as "beta") → Stage 7 (insurance
+ legal, required before real engagements) → Stage 5 (real scanning) →
Stage 4 (payments) → Stage 8 (marketing push).
