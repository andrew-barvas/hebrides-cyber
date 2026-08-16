# Hebrides Cyber REST API (v1)

Trigger scans and read results from CI, scripts, and integrations.

## Authentication

Every request needs an API key:

```
Authorization: Bearer hc_live_xxxxxxxxxxxxxxxxxxxxxxxx
```

Create one in the dashboard. The key is shown **once** — it's stored only as a
SHA-256 hash and cannot be recovered, so save it to your secret store
immediately. Lost keys are revoked and replaced, not recovered.

Keys can't create or revoke other keys. That's deliberate: a leaked CI secret
should not be able to mint permanent replacements that survive revoking the
original. Key management requires a logged-in session.

## Scanning requires a verified domain

The API only scans domains already verified for your account. There's no
interactive challenge step available to a CI runner, and an API key must not be
able to point the scanner at a host its owner hasn't proven they control.
Verify the domain in the dashboard first (DNS record or file upload).

Unverified targets return `403` with the domain named in the error.

---

## Endpoints

### `POST /api/v1/scans`

Runs a scan and returns the result. Synchronous — expect it to take a while
on a large site.

```bash
curl -X POST https://hebridescyber.com/api/v1/scans \
  -H "Authorization: Bearer $HEBRIDES_CYBER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

`201`:

```json
{
  "scan_id": "b3f1c2d4-...",
  "target_url": "https://example.com",
  "status": "completed",
  "score": 72,
  "summary": "Two high-severity issues...",
  "counts": { "high": 2, "medium": 5, "low": 3, "info": 7 },
  "findings": [
    {
      "check_id": "dns.spf-missing",
      "severity": "high",
      "title": "No SPF record",
      "detail": "Email from this domain can be spoofed.",
      "remediation": "Publish an SPF record so receiving servers..."
    }
  ]
}
```

### `GET /api/v1/scans`

Lists your scans, newest first.

| Query param | Default | Notes |
|-------------|---------|-------|
| `limit` | 20 | Max 100 |
| `target_url` | — | Exact match filter |

### `GET /api/v1/scans/{id}`

Full result for one scan, **with each finding tagged against the previous scan
of the same target**:

```json
{
  "scan_id": "b3f1c2d4-...",
  "score": 72,
  "compared_to_previous_scan": true,
  "new_finding_count": 2,
  "fixed_finding_count": 3,
  "findings": [
    { "check_id": "webapp.cors-reflected", "severity": "high", "status": "new", "...": "..." },
    { "check_id": "dns.spf-missing", "severity": "high", "status": "unchanged", "...": "..." }
  ],
  "fixed_findings": [
    { "check_id": "tls.hsts-missing", "severity": "medium", "title": "HSTS header missing" }
  ]
}
```

`status` is `new`, `unchanged`, or `null`. It is `null` when the finding has no
`check_id` (scans predating finding identity) or when there's no previous scan
to compare against — check `compared_to_previous_scan` before relying on it.

**Treat `compared_to_previous_scan: false` as "can't tell what's new", not as
"nothing is new."**

Vulnerable-JS-library findings additionally carry `cve_ids` — real CVE
identifiers looked up live from [OSV.dev](https://osv.dev) against the
detected package name and version. `[]` means the library was checked and
nothing is currently known against it; the field is absent entirely on
finding types that don't get a CVE lookup at all (only outdated JS libraries
are checked today — see `src/lib/scanners/osv.ts` for why that's scoped
narrower than every finding type).

---

## Webhooks

Get a signed `POST` when a scan completes, instead of polling
`GET /api/v1/scans/{id}`. Register one from **Account → Webhooks** — this is
the one part of the API that isn't itself an API-key-authenticated endpoint,
since minting a webhook is a write to your account, gated to a logged-in
session the same way creating an API key is.

### Payload

```json
{
  "event": "scan.completed",
  "sent_at": "2026-08-16T14:02:11.000Z",
  "data": { "...": "the exact same shape GET /api/v1/scans/{id} returns" }
}
```

`data` is a full scan report — same fields, same `new`/`unchanged`/`null`
finding-status semantics documented above. One event type exists today:
`scan.completed`.

### Verifying the signature

Every request carries an `hc-signature` header:

```
hc-signature: t=1755349331,v1=8f3a1c2e9b7d4f6a1c8e2b9d4f7a1c8e2b9d4f7a1c8e2b9d4f7a1c8e2b9d4f7a
```

`t` is a Unix timestamp (seconds); `v1` is `HMAC-SHA256(secret, "{t}.{raw body}")`,
hex-encoded. Verify using the **raw, unparsed** request body — signing a
re-serialized JSON object will not match, since key order/whitespace can
differ from what was actually sent.

**Node.js:**

```js
const crypto = require("node:crypto");

function verify(secret, rawBody, header, toleranceSeconds = 300) {
  const match = /^t=(\d+),v1=([0-9a-f]+)$/.exec(header);
  if (!match) return false;
  const [, tsStr, providedSig] = match;
  const timestamp = Number(tsStr);
  if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) return false;

  const expected = crypto.createHmac("sha256", secret)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");

  const a = Buffer.from(expected);
  const b = Buffer.from(providedSig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

**Python:**

```python
import hmac, hashlib, time, re

def verify(secret: str, raw_body: bytes, header: str, tolerance_seconds: int = 300) -> bool:
    match = re.match(r"^t=(\d+),v1=([0-9a-f]+)$", header)
    if not match:
        return False
    timestamp, provided_sig = int(match[1]), match[2]
    if abs(time.time() - timestamp) > tolerance_seconds:
        return False

    expected = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, provided_sig)
```

Checking the timestamp matters as much as checking the signature — without it,
a captured request/signature pair could be replayed indefinitely. Reject
anything older than a few minutes.

### Delivery and failure handling

- Your endpoint must be `https://` and return a `2xx` status within 8 seconds.
- On failure, one retry follows after ~2 seconds. There is no queue behind
  this — a delivery either succeeds within that single retry or it's recorded
  as failed and the scan request that triggered it moves on regardless.
- After 20 consecutive failed deliveries, the webhook is automatically
  disabled (visible in **Account → Webhooks**) rather than retried forever
  against a dead or mistyped endpoint. Re-registering with a working URL
  starts the failure count fresh.

---

## CI/CD

### Fail a build only on *new* findings

This is the important pattern. Gating on *total* findings red-lines every
pipeline on its first run and the check gets disabled the same day. Gate on
what this change introduced instead.

```yaml
name: Security
on:
  pull_request:
  schedule:
    - cron: "0 3 * * 1"   # Mondays 03:00 UTC

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run security scan
        id: scan
        env:
          API_KEY: ${{ secrets.HEBRIDES_CYBER_API_KEY }}
          TARGET: https://staging.example.com
        run: |
          set -euo pipefail

          response=$(curl -sS -X POST https://hebridescyber.com/api/v1/scans \
            -H "Authorization: Bearer $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"target_url\": \"$TARGET\"}")

          scan_id=$(echo "$response" | jq -r '.scan_id')
          score=$(echo "$response" | jq -r '.score')

          if [ "$scan_id" = "null" ]; then
            echo "Scan failed:"; echo "$response" | jq .
            exit 1
          fi

          # Re-fetch to get findings tagged new/unchanged against last scan
          detail=$(curl -sS "https://hebridescyber.com/api/v1/scans/$scan_id" \
            -H "Authorization: Bearer $API_KEY")

          compared=$(echo "$detail" | jq -r '.compared_to_previous_scan')
          new_high=$(echo "$detail" | jq '[.findings[]
            | select(.status == "new")
            | select(.severity == "critical" or .severity == "high")] | length')

          echo "score=$score" >> "$GITHUB_OUTPUT"
          echo "Security score: $score/100"

          if [ "$compared" != "true" ]; then
            echo "::notice::First scan of this target — no baseline to compare against yet."
            exit 0
          fi

          echo "$detail" | jq -r '.findings[]
            | select(.status == "new")
            | "::warning::NEW [\(.severity)] \(.title)"'

          if [ "$new_high" -gt 0 ]; then
            echo "::error::$new_high new critical/high finding(s) introduced"
            exit 1
          fi
```

### Post the score on the PR

```yaml
      - name: Comment score
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `Security score: **${{ steps.scan.outputs.score }}/100**`
            })
```

### GitLab CI

```yaml
security_scan:
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      curl -sS -X POST https://hebridescyber.com/api/v1/scans \
        -H "Authorization: Bearer $HEBRIDES_CYBER_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"target_url\": \"$TARGET_URL\"}" | tee result.json
      jq -e '.score >= 70' result.json
  artifacts:
    paths: [result.json]
```

---

## Errors

| Status | Meaning |
|--------|---------|
| `400` | Missing/invalid `target_url`, or it failed the SSRF check |
| `401` | Missing, malformed, revoked, or unknown API key |
| `403` | Domain not verified for this account, or scan belongs to someone else |
| `404` | Scan not found |
| `429` | Rate limit exceeded — see the `Retry-After` header |
| `500` | Scan failed; `scan_id` is included so you can inspect it |

All errors return `{ "error": "..." }`.

## Rate limits

Enforced per account. On `429`, back off for the seconds given in
`Retry-After`/`retry_after_seconds` rather than retrying immediately.
