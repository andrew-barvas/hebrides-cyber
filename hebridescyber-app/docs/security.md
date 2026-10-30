# Security & Operational Guidance

## Proof of Ownership

Before running any scan against a target — even a "safe" automated one —
verify the requester actually controls it. Two accepted methods:

1. **DNS TXT record.** Ask the user to add a TXT record like
   `hebridescyber-verify=<random-token>` at their domain, then check it
   via a DNS lookup before allowing scans against that domain.
2. **File upload.** Ask the user to upload a file at
   `https://target.com/.well-known/hebridescyber-verify.txt` containing a
   token you generated, then fetch it and compare.

Sample verification token flow:

1. User requests verification for `target.com` → generate a random token,
   store it in a `verifications` table keyed to `(user_id, domain, token,
   verified_at)`.
2. User adds the DNS TXT record or uploads the file.
3. User clicks "Verify" → server looks up the TXT record / fetches the
   file and compares to the stored token.
4. On match, mark `verified_at = now()`. `run-scan` should refuse to run
   against any domain without a corresponding verified record.

**Current state:** this is now implemented for real. `src/lib/ownership.ts`
does an actual DNS TXT lookup (`node:dns/promises`) and an actual fetch of
`/.well-known/hebridescyber-verify.txt`, driven by
`POST /api/verify-ownership` (`action: "start"` issues a token +
instructions, `action: "check"` performs the lookup and marks the
`verifications` row verified). `/api/run-scan` checks that table first, via
`isDomainVerified()` — which also exempts admin accounts (`users.is_admin`)
from needing verification at all, same as it exempts them from the
free-tier scan cap.

A weaker fallback still exists alongside it, off by default: if no verified
row is found and `ALLOW_DEV_TOKEN_VERIFICATION=true` is set, `/api/run-scan`
accepts the `X-Scan-Token` echoed back from scan creation instead — this
only proves the caller is the authenticated account that requested the
scan, not that they control the target's DNS/hosting. **Only ever set this
for local dev.** On a real deployment, leave it unset (or `false`) so every
scan requires real verification.

## Consent for Intrusive Scans

Anything beyond passive checks (header/TLS inspection, dependency
manifest review) — in particular ZAP active scanning or anything that
sends attack payloads — must only run after:

- Explicit, written consent from the target's owner.
- A signed agreement covering scope, timing, and liability.

Suggested legal consent template (have a solicitor review before use):

> "[Client] authorises Hebrides Cyber to perform security testing against
> [target_url] between [start date] and [end date], limited to [scope].
> Hebrides Cyber will not attempt to exfiltrate data, disrupt service
> availability, or test systems outside the agreed scope. [Client]
> confirms it has the authority to grant this permission."

## Isolation of Heavy Scanners

**Done, via ephemeral GitHub Actions runners rather than Azure Container
Instances** (ACA/ACI were considered and rejected — see
`docs/decisions/ENGINEERING-LOG-2026-08.md`'s "17 Aug" note — since GitHub Actions already
gives fresh, destroyed-after-each-run compute for free, and installing
real tools per run avoids maintaining a second infra surface). ZAP, nmap,
nuclei, and (in the opt-in `api` profile) sqlmap and commix only ever run inside
`.github/workflows/scheduled-scans.yml`'s `work` job
(`runExtendedTools: true` on `executeScan()`), never inline in an
interactive request:

- Each job's tools are installed fresh into that run's disposable runner
  VM and torn down when the job ends — no state or binaries persist
  between runs or across customers.
- Each job is bounded (`MAX_JOBS_PER_RUN`/`TIME_BUDGET_MS` in
  `src/scripts/run-queued-scan-jobs.ts`), so a hung scan can't run forever
  or starve the rest of the queue.
- **Not yet done:** strict egress rules limiting outbound traffic to only
  the specific target being scanned. GitHub-hosted runners have general
  internet egress by default — revisit if that becomes a real concern
  (e.g. via self-hosted runners with a locked-down network policy).

## AI triage data flow

With `AI_TRIAGE=1`, `aiTriage.ts` sends to the Azure OpenAI deployment the finding's title, check id,
severity, truncated detail and metadata hints, plus the replay request and up to 16 KB of the
response it captured from the customer's own site. It never sends credentials, cookies (request
cookies are not allowed and `Set-Cookie` is redacted), stored secrets or the target host. The model's
output is schema-checked and can only annotate a finding. Replay requests are constrained by
`replayProbe.ts` (read-only, same site, budgeted). Use a UK/EU-region deployment and reflect this in
the privacy notice before enabling it for customers. Off by default; `DISABLE_AI_TRIAGE=1` forces it
off.

## Uptime monitoring data flow (UptimeRobot, bring your own account)

A Pro-or-above customer can paste their own UptimeRobot API key. It is checked once against `api.uptimerobot.com`, then stored encrypted (`credentialEncryption.ts`) in `uptime_integrations`, a table with **no client policy at all**: the browser can never read it back, and `GET /api/uptime/status` returns monitor rows and sync times only. The key is only ever sent to `api.uptimerobot.com` (a pagination link pointing anywhere else is refused). Sent to UptimeRobot: the key, and for each monitor the customer's own verified site URL and a name (`Hebrides: <host>`). Received: monitor id, status and how long it has been in it. Monitors can only be created for domains the customer has verified. Disconnecting deletes the key and our monitor records but not the monitors in the customer's UptimeRobot account. Rows cascade-delete with the account. UptimeRobot's terms bar reselling or white-labelling its monitoring, which is why there is no shared Hebrides account.

## Secrets Handling

- Set production secrets (Supabase service role key, Stripe secret key,
  Azure OpenAI key, `GITHUB_PAT`, storage connection strings) as **Static
  Web App application settings** — `az staticwebapp appsettings set` or the
  Portal. Never paste raw values into `.env.local`, Terraform files, or
  GitHub Actions YAML (the `SUPABASE_*` GitHub Secrets used directly inside
  CI jobs — see `README.md` — are the intentional exception).
- `.env.example` in this repo lists required variable names only — no
  real values are ever committed.
- Rotate the Supabase service role key and Stripe keys periodically and
  immediately if a leak is suspected.

## Data Retention

**Status: implemented (2026-09-05, `docs/ENHANCEMENTS.md` E-10).** The
account owner confirmed automating against the already-published `/privacy`
figures rather than changing policy first:

- Scan results (raw findings, `scan_results` rows): **12 months**, then
  automatic purge — `src/scripts/cleanup-retention.ts`, run nightly by
  `.github/workflows/data-retention-cleanup.yml` (git root).
- PDF reports (Azure Blob Storage, `reports` container): **90 days**, then
  deletion — same script, skipped (not failed) when
  `AZURE_STORAGE_CONNECTION_STRING` is unset.
- Contact enquiries: **12 months**, then deletion — same script.
- Customer-initiated erasure (GDPR "right to erasure", `/privacy` §7's
  30-day response commitment): `/account`'s "danger zone" section calls
  `src/pages/api/account/request-deletion.ts`, which logs to `audit_logs`
  and emails the account owner. The actual deletion is a separate,
  human-run step — `src/scripts/erase-user-data.ts` (dry-run by default,
  `--confirm` to execute) — deleting a whole account is irreversible and
  deliberately not self-service.

**Deliberately still not automated**: account/subscription deletion on
subscription cancellation (no reliable "account closure" event exists to
anchor a timer to — see `erase-user-data.ts`'s header) and server-log
retention (an Azure infra setting, not application data — configure
separately in Azure Log Analytics).

## Rate Limiting & Concurrency

- `run-scan` uses `src/lib/rateLimit.ts` — a real, shared-state limiter via
  Upstash Redis's REST API (`UPSTASH_REDIS_REST_URL`/`TOKEN`, 10
  requests/hour per caller) when those are set. **Without them it falls
  back to an in-memory bucket that resets on instance recycling and
  doesn't share state across concurrently-running instances — set the
  Upstash env vars before relying on this in production.**
- Separately, free-tier accounts (no active subscription) are capped at
  **one scan, ever** (`src/lib/freeTier.ts`'s `isFreeTierExhausted`) —
  admins exempt. This bounds worst-case cost exposure from a single free
  account independently of the hourly rate limit.
- A burst of scheduled scans can't overwhelm anything Function-App-shaped
  anymore: `.github/workflows/scheduled-scans.yml` runs through a
  Postgres-backed queue (`sql/migrations/008_scan_jobs.sql`), worked by a
  fixed, bounded set of GitHub Actions shards (`src/scripts/run-queued-scan-jobs.ts`,
  itself capped per run by `MAX_JOBS_PER_RUN`/`TIME_BUDGET_MS`) rather than
  one HTTP call per target — see `docs/decisions/ENGINEERING-LOG-2026-08.md` §4.
