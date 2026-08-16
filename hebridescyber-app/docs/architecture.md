# Architecture

## Data Flow

1. A user signs up / signs in via Supabase Auth (magic link).
2. From the dashboard (`src/app/dashboard/page.tsx`), they submit a target
   URL. The client calls `run-scan` **twice**:
   a. First with just `{ targetUrl }` — the Function creates a `scans` row
      (status `pending`, owner = the authenticated user) directly with the
      service role key, generates a random `proof_token`, and returns it.
   b. Then with `{ scanId }` and an `X-Scan-Token` header set to that
      token — the Function checks the token matches (`verifyOwnership()`),
      then actually runs the scan.
3. Alternatively, `scheduled-scans.yml` triggers the same two-call flow on
   a cron, for every `{ owner, targetUrl }` pair returned by
   `src/scripts/fetch-scheduled-targets.ts` (active subscriptions joined
   against `monitored_targets`), authenticating as a trusted service via
   `X-Service-Token` instead of a user session.
4. `run-scan` runs the scanner steps (currently deterministic stubs — see
   `src/lib/scanners/`), and writes results + a 0-100 score to
   `scan_results` using the Supabase **service role** key (bypasses RLS).
5. `summariseResults()` (destined for a real Azure OpenAI call) generates
   a plain-English executive summary from the findings.
6. The dashboard (`src/app/dashboard/scans/[id]/page.tsx`) reads the result
   back through the user's normal (RLS-protected) Supabase session.
7. `generate-report` renders the result as HTML and converts it to PDF via
   Playwright — returned directly, or uploaded to Blob Storage and
   returned as a SAS URL if `AZURE_STORAGE_CONNECTION_STRING` is set.
8. Stripe webhooks (`src/pages/api/stripe/webhook.ts`) keep the
   `subscriptions` table in sync with billing state
   (`checkout.session.completed` → active, `invoice.payment_failed` →
   past_due, `customer.subscription.deleted` → cancelled).

## Security Considerations

- **RLS everywhere.** Every table holding user data has row-level security
  enabled; the only code path that bypasses it is server-side code using
  the service role key (the Functions, never the browser).
- **Service role key isolation.** `SUPABASE_SERVICE_ROLE_KEY` must only
  ever live in Azure Function app settings / Key Vault, never in
  `NEXT_PUBLIC_*` env vars or client bundles.
- **Proof of ownership.** `run-scan` should not run against arbitrary URLs
  without verifying the caller controls the target — see `docs/security.md`.
- **Isolation of scanners.** Dependency scans, ZAP, and headless browser
  page loads are all stubbed today; the production versions should run in
  ephemeral, network-restricted containers (Azure Container Instances),
  not inline in the Function process.
- **Secrets never in git.** `.env.example` documents required variables
  with no real values; production secrets belong in Azure Key Vault.

## Scaling Notes

- The Consumption-plan Function App scales automatically per-invocation,
  but heavy scanners (ZAP, Playwright) will need either a higher-tier plan
  or delegation to Azure Container Instances to avoid Function timeout
  limits (default 5–10 minutes depending on plan).
- `scheduled-scans.yml` fetches its target list dynamically (`fetch-targets`
  job runs `src/scripts/fetch-scheduled-targets.ts` against the
  `subscriptions`/`monitored_targets` tables), so it scales past a handful
  of manually-added clients without editing the workflow. It still runs
  every target through a plain GitHub Actions matrix, capped at
  `max-parallel: 3` — move to a real queue (below) once that cap becomes a
  bottleneck.
- As scan volume grows, consider a queue (Azure Storage Queues or Service
  Bus) between the trigger and the actual scan execution, so bursts of
  scheduled scans don't overwhelm the Function App or get rate-limited by
  target sites.
- PDF report generation via Playwright is CPU/memory heavy — if this
  becomes a bottleneck, move it to a dedicated container job rather than
  running it inline in a Function.
