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
`/.well-known/hebridescyber-verify.txt`, driven by the
`verify-ownership` Function (`action: "start"` issues a token + instructions,
`action: "check"` performs the lookup and marks the `verifications` row
verified). `run-scan` checks that table first.

A weaker fallback still exists alongside it: if no verified row is found,
and `ALLOW_DEV_TOKEN_VERIFICATION` is `true` (the default), `run-scan`
accepts the `X-Scan-Token` echoed back from scan creation instead — this
only proves the caller is the authenticated account that requested the
scan, not that they control the target's DNS/hosting. It exists so the
dashboard's quick self-service flow works without every user completing
DNS/file verification first. **Set `ALLOW_DEV_TOKEN_VERIFICATION=false`**
once you want every scan to require real verification.

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

Run ZAP, dependency scanners, and headless browser sessions in **ephemeral
containers** (Azure Container Instances or similar), not inline in a
long-lived process:

- Strict egress rules — only allow outbound traffic to the specific target
  being scanned, nothing else.
- Destroy the container after each scan; never reuse across customers.
- Set hard timeouts and resource limits so a hung scan can't run forever
  or starve other work.

## Secrets Handling

- Use **Azure Key Vault** for all production secrets (Supabase service
  role key, Stripe secret key, Azure OpenAI key, storage connection
  strings). Reference them from Function app settings via Key Vault
  references — never paste raw values into `local.settings.json`,
  Terraform files, or GitHub Actions YAML.
- `.env.example` in this repo lists required variable names only — no
  real values are ever committed.
- Rotate the Supabase service role key and Stripe keys periodically and
  immediately if a leak is suspected.

## Data Retention

- Default retention for scan artifacts (raw results, PDF reports): **90
  days**, after which they should be deleted automatically.
- **TODO:** implement a scheduled cleanup job (e.g. a nightly Azure
  Function or Supabase cron job) that deletes `scan_results` rows and any
  stored PDFs older than 90 days.
- Provide a deletion API / dashboard action so users can request early
  deletion of their data (relevant for GDPR "right to erasure" requests).

## Rate Limiting & Concurrency

- `run-scan` has an **in-memory token bucket** (`rateLimitBuckets` in
  `src/functions/run-scan/index.ts`, 10 requests/hour per caller by
  default) — this is only there so the shape of the check exists. It
  resets whenever the Function instance recycles and doesn't share state
  across concurrently-running instances, so it must NOT be relied on as
  the real control before the endpoint is exposed publicly. Replace with
  Azure Cache for Redis or a Supabase table + row locking, and consider
  tiering the limit by subscription plan (free vs. paid).
- Cap concurrent scans per customer and globally, so a burst of scheduled
  scans (see `scheduled-scans.yml`) can't overwhelm the Function App or
  get target sites to block your IP range.
- Consider a queue between scan requests and execution once volume grows
  past what direct HTTP-triggered Functions can handle smoothly.
