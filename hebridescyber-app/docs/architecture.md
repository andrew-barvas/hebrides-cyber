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
3. Alternatively, `scheduled-scans.yml` runs on a cron through a queue
   instead of calling `run-scan` directly: `src/scripts/enqueue-scheduled-scans.ts`
   inserts one `scan_jobs` row (see `sql/migrations/008_scan_jobs.sql`) per
   verified target belonging to an active subscription, then a matrix of
   ephemeral worker shards each run `src/scripts/run-queued-scan-jobs.ts`,
   claiming jobs via the `claim_scan_job()` `SKIP LOCKED` RPC and executing
   them with `src/lib/scanExecution.ts`'s `executeScan()` — the same function
   `run-scan` itself calls, so scan behaviour is identical either way.
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

- The Consumption-plan Function App scales automatically per-invocation, but
  can't run heavy/real active-scanning tools (ZAP daemon, nmap, sqlmap,
  nuclei) at all — no shell access, no custom image, 5-10 min execution cap.
  `run-scan` never attempts them (`executeScan()`'s `runExtendedTools` option
  defaults off and only the queue worker passes it — see below).
- `scheduled-scans.yml` enqueues into `scan_jobs` (a Postgres table, no new
  infra — Supabase is already provisioned) and works it with a small,
  fixed-size matrix of GitHub Actions worker shards, each claiming jobs via
  `SELECT ... FOR UPDATE SKIP LOCKED`. This scales by adding shards to the
  matrix, not by widening a per-target curl matrix, and avoids Redis/BullMQ
  or a long-lived container — neither of which Azure Static Web Apps or
  Consumption-plan Functions can run anyway. Each worker run is bounded
  (`MAX_JOBS_PER_RUN` / `TIME_BUDGET_MS` in `run-queued-scan-jobs.ts`), so a
  backlog just rolls over to the next scheduled run rather than one Actions
  job running unbounded.
- The same queue's worker is also where the real nmap/nuclei/sqlmap/ZAP tool
  suite (`src/worker/tools/`) actually runs — a GitHub Actions runner can
  `apt-get install` binaries and start a ZAP daemon via `docker run`
  (`scheduled-scans.yml`'s `work` job does both), which neither Static Web
  Apps nor Consumption Functions can. The BullMQ+Redis worker this suite was
  originally built for was deleted; only the tool-invocation logic survived,
  ported into `executeScan()`.
- PDF report generation via Playwright is CPU/memory heavy — if this
  becomes a bottleneck, move it to a dedicated container job rather than
  running it inline in a Function.
