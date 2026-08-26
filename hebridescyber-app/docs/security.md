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
nuclei, sqlmap, XSSer, and commix only ever run inside
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

## Secrets Handling

- Set production secrets (Supabase service role key, Stripe secret key,
  Azure OpenAI key, `GITHUB_PAT`, storage connection strings) as **Static
  Web App application settings** — `az staticwebapp appsettings set` or the
  Portal. Never paste raw values into `.env.local`, Terraform files, or
  GitHub Actions YAML (the `DIGEST_SERVICE_TOKEN`/`SUPABASE_*` GitHub
  Secrets used directly inside CI jobs — see `README.md` — are the
  intentional exception).
- `.env.example` in this repo lists required variable names only — no
  real values are ever committed.
- Rotate the Supabase service role key and Stripe keys periodically and
  immediately if a leak is suspected.

## Data Retention

**Neither of the following is implemented in code.** This is a live gap,
not a future nice-to-have — tracked as `docs/ENHANCEMENTS.md` E-10 and
`docs/ROADMAP.md` BETA-3/BETA-B2. No scheduled cleanup job, lifecycle rule,
or deletion API exists anywhere in this repo; nothing has ever actually
been deleted by either promise below.

**This section previously stated a 90-day figure for scan results that
contradicted `/privacy`'s published 12-month figure** — an internal
inconsistency on top of the missing implementation. `/privacy` is the
customer-facing legal document and is the one that matters if the two ever
disagree again; this section now just repeats it rather than maintaining a
second, driftable copy of the same numbers:

- Scan results (raw findings, `scan_results` rows): promised **12 months**
  on `/privacy`, then automatic purge.
- PDF reports (Azure Blob Storage): promised **90 days**, then deletion.
- Contact enquiries: promised **12 months**, then deletion.

**Before implementing the cleanup job**, confirm these figures are still
the intended policy (they were never verified against any actual legal or
business requirement, just chosen when `/privacy` was written) — don't
build automation around them without that check. Once confirmed:

- A scheduled cleanup job (matching the `daily-blog.yml`/`weekly-newsletter.yml`
  pattern — a script run directly by GitHub Actions against Supabase, no
  HTTP hop) that deletes `scan_results` rows and Blob Storage PDFs past
  their respective windows.
- A deletion API / dashboard action so a customer can request *early*
  deletion (the GDPR "right to erasure" case `/privacy` §7 already commits
  to a 30-day response on, with no code path behind that commitment yet).

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
