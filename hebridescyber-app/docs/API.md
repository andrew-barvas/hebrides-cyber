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

### IP allowlists

Each key can be restricted to a list of addresses and CIDR ranges, IPv4 or
IPv6, up to 20 entries: **Dashboard → Integrations → API keys → IP
allowlist**. An empty list, the default, means any address.

From an address that isn't on the list, the key gets the same `401` as an
invalid key. That's deliberate: someone holding a leaked key learns nothing
about whether it's real. The dashboard shows the address and date of the
most recent refused request on each key instead, so you can tell when your
CI has moved to a new egress address.

The address checked is the one our edge sees, which is what the "Add my
current IP" button fills in (`GET /api/client-ip` returns it as
`{ "ip": "…" }` if you want to check from a runner). The API is only reachable
over IPv4 today, so an IPv6 entry is accepted but won't match anything yet.
GitHub-hosted runners don't have stable IPs, so an allowlisted key suits
self-hosted runners or a fixed-egress proxy. The allowlist applies only to
API keys; signing in to the dashboard is never IP-restricted.

## Scanning requires a verified domain

The API only scans domains already verified for your account. There's no
interactive challenge step available to a CI runner, and an API key must not be
able to point the scanner at a host its owner hasn't proven they control.
Verify the domain in the dashboard first (DNS record or file upload).

Unverified targets return `403` with the domain named in the error.

---

## Endpoints

### `POST /api/v1/scans`

Queues a scan and returns immediately — it does not wait for the scan to
finish. Get the result via `GET /api/v1/scans/{id}` (poll it) or a webhook
(push, no polling — see below). Usually completes within a minute.

```bash
curl -X POST https://www.hebridescyber.co.uk/api/v1/scans \
  -H "Authorization: Bearer $HEBRIDES_CYBER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'
```

`202`:

```json
{
  "scan_id": "b3f1c2d4-...",
  "target_url": "https://example.com",
  "status": "queued",
  "message": "Scan queued — usually completes within a minute. Poll GET /api/v1/scans/{id} or register a webhook for scan.completed."
}
```

This used to run the scan inline and return the finished report in the same
call. It doesn't anymore — the packaged GitHub Action and both CI examples
below already poll `GET /api/v1/scans/{id}` for you; update any integration
that parsed `score`/`findings` directly off the `POST` response.

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

Findings with CVEs can also carry `threat_intel`, which says whether anyone
is actually exploiting the CVE:

```json
"threat_intel": {
  "known_exploited": true,
  "kev_cve_ids": ["CVE-2021-44228"],
  "ransomware": true,
  "epss": 0.975,
  "epss_percentile": 0.9999
}
```

- `known_exploited`: at least one of the finding's CVEs is in
  [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  listed in `kev_cve_ids`. `ransomware` is present when CISA records
  ransomware use.
- `epss` / `epss_percentile`: the highest [FIRST EPSS](https://www.first.org/epss/)
  probability of exploitation activity in the next 30 days, across the
  finding's CVEs, with its percentile.
- `threat_intel` is omitted when it wasn't looked up (no CVE, or both
  sources unreachable). Treat a missing field as unknown, not as "not
  exploited". `severity` never changes because of it; the dashboard uses it
  to order findings within a severity.

A finding that other tools also reported (nuclei, ZAP, testssl) carries
`corroborated_by: [{ tool, check_id, title }]`; those duplicates are merged into
this one finding and not listed separately. The field is omitted when nothing
corroborated it. The CSV export has a matching `corroborated_by` column.

A finding from a check that made a request it can show (today: exposed files
and directory listings) carries `evidence`:

```json
"evidence": {
  "request": { "method": "GET", "url": "https://example.com/.env" },
  "response": { "status": 200, "headers": { "content-type": "text/plain" }, "bodyExcerpt": "APP_ENV=[redacted]\nDB_PASSWORD=[redacted]" },
  "matched": "DB_",
  "capturedAt": "2026-10-30T12:00:00.000Z"
}
```

`response.headers` is an allowlist (content type and length, server,
last-modified, x-powered-by). Cookies and auth headers are never recorded.
`response.bodyExcerpt` is at most 400 characters, with `truncated: true` when
it was cut. It's redacted before it's stored: every `key=value` or `key:
value` value, token, hash, private key, credential in a URL and email address
becomes `[redacted]`, so you see which keys were exposed but not their values.
It's omitted when the check never read the body, as for directory listings,
which keep only the "Index of" heading in `matched`. Evidence is stored with
the scan result and deleted with it, and is absent on scans from before
2026-10-30. The CSV export puts it in one `evidence` column (last), as
`GET <url> → <status> (<type>); matched: …`.

Each finding also carries `triage` — your current decision about it on this
site, or `null`:

```json
"triage": { "state": "snoozed", "reason": "Fix booked for next sprint", "expires_at": "2026-11-01T00:00:00.000Z", "triaged_at": "2026-10-01T09:12:00.000Z" }
```

`state` is `accepted_risk` (also used for "authorised"), `false_positive` or
`snoozed`. Only triage still in effect is reported: once `expires_at` passes,
the field is `null` again. It's current, not as-of-scan, so an older scan
shows today's decisions. The packaged GitHub Action ignores triaged findings
when deciding pass/fail. Webhook payloads carry the same field; the public
share link does not.

### `GET /api/v1/scans/{id}/export`

Flat, tabular export of one scan's findings — for a spreadsheet or your own
reporting/ticketing pipeline, as opposed to `GET /api/v1/scans/{id}`'s nested
report shape with New/Fixed diffing.

| Query param | Default | Notes |
|-------------|---------|-------|
| `format` | `csv` | `csv` or `json` |

CSV columns: `severity, title, detail, check_id, cve_ids, cvss_score,
cvss_vector, known_exploited, epss, compliance_refs`. `cve_ids` and
`compliance_refs` are `;`-joined lists within a single cell.
`known_exploited`/`epss` are blank when threat intel wasn't looked up,
which is different from `false` (see `threat_intel` above).
`triage_state, triage_reason, triage_expires_at` come last, blank when the
finding isn't triaged; in JSON each finding has `triage` (`state`, `reason`,
`expiresAt`, `triagedAt`) or `null`. JSON returns
`{ scan_id, target_url, findings }` with each finding's full stored shape
(`checkId`, `cveIds`, `threatIntel`, `complianceRefs` and so on, camelCase
as stored).

`compliance_refs` — see `src/lib/scanners/compliance.ts` — maps a finding to
Cyber Essentials, OWASP Top 10, and/or CIS Controls v8 where genuinely
applicable. Deliberately not exhaustive: a finding with no compliance refs
either hasn't been categorised yet or doesn't map cleanly to any of the
three frameworks — never force-fitted.

### `GET /api/v1/scans/{id}/compliance`

The same scan's findings grouped by framework control — ISO 27001, PCI DSS,
Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2 and DORA — as a
document to hand to an auditor or a client. The dashboard's "Compliance
report" button on a scan report downloads the Markdown version.

| Query param | Default | Notes |
|-------------|---------|-------|
| `format` | `md` | `md`, `csv` or `json`; anything else is a `400` |

Each control gets one of three results: `no_issues_found`, `issues_found`
(medium/low/info findings only) or `high_severity_issues_found`. These are
deliberately not "pass" and "fail". The control list covers only the
controls our external checks map to, so `no_issues_found` means none of those
checks detected a problem. It does **not** mean the control is implemented.
Many controls in every framework (policies, internal process, physical
security) can't be assessed from outside at all. Every format carries this
disclaimer: the Markdown report opens with it, the CSV's first row is it, and
JSON returns it as `disclaimer`.

CSV columns: `framework, control, result, finding_count, findings`, one row
per control. JSON:

```json
{
  "disclaimer": "Automated indicator — not an audit, certification or attestation. …",
  "generated_at": "2026-09-27T09:02:11.000Z",
  "target_url": "https://example.com",
  "frameworks": [
    {
      "framework": "cyber-essentials",
      "label": "Cyber Essentials",
      "controls_mapped": 5,
      "controls_without_issues": 4,
      "controls_with_issues": 1,
      "controls": [
        {
          "control": "Secure configuration",
          "result": "issues_found",
          "findings": [{ "checkId": "headers.missing-recommended", "severity": "medium", "title": "…" }]
        }
      ]
    }
  ]
}
```

Scans stored before findings carried their own compliance refs are mapped
from each finding's `check_id` at export time, so an older scan still
exports a populated report.

CSV exports from both `/export` and `/compliance` prefix any cell that starts
with `=`, `+`, `-`, `@`, a tab or a carriage return with `'`. Finding titles
can quote text from the scanned site, and without the prefix a spreadsheet
would run such a cell as a formula.

### `POST /api/v1/dependency-diff`

The vulnerable packages a pull request **introduces** — Pro and Agency plans.
Send a lockfile's content on the PR's base and head; only packages that head
adds (a name and version base didn't have) are checked against OSV.dev, so the
check gates what the change brings, not the existing backlog. Stateless:
nothing is stored and no repository access is needed.

```json
{
  "files": [
    {
      "name": "web/package-lock.json",
      "base": "<content on the base, or null if the file is new>",
      "head": "<content on the head, or null if the PR deletes it>",
      "base_companion": "<web/package.json on the base (optional)>",
      "head_companion": "<web/package.json on the head (optional)>"
    }
  ]
}
```

Up to 20 files; `name` is matched on its file name. Supported: `package-lock.json`,
`npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`,
`Pipfile.lock`, `composer.lock`, `go.sum`, `gradle.lockfile`, `Gemfile.lock`,
`Cargo.lock`, `packages.lock.json`. The optional companion manifest
(`package.json`, `pyproject.toml`, `composer.json`, `go.mod`) lets the parser
tell direct from transitive dependencies.

```json
{
  "status": "completed",
  "complete": true,
  "notes": [],
  "packages_added": 12,
  "counts": { "critical": 0, "high": 1, "medium": 0, "low": 0 },
  "vulnerabilities": [
    {
      "ecosystem": "npm", "name": "lodash", "version": "4.17.0",
      "direct": true, "dev": false, "introduced_via": null,
      "file": "web/package-lock.json",
      "severity": "high",
      "fixed_version": "4.17.21",
      "advisories": [{ "id": "GHSA-35jh-r3h4-6jhm", "cve_ids": ["CVE-2021-23337"], "severity": "high", "summary": "…" }]
    }
  ],
  "files": [{ "file": "web/package-lock.json", "ecosystem": "npm", "status": "ok", "packages_added": 12, "packages_removed": 3 }]
}
```

`complete: false` means something couldn't be checked (a lockfile that won't
parse, more than 2,000 added packages) — **don't treat it as clean**; `notes`
and each file's `error` say why. A new lockfile (`base: null`) counts every
package as introduced. If OSV.dev can't be reached the response is `502` with
`"code": "lookup_failed"` rather than an empty result. `403`
`"code": "plan_required"` on Basic.

### `GET /PUT /DELETE /api/findings/triage`

Accept a risk (or authorise it), mark a false positive, or snooze a finding —
always with a reason — and undo it. A finding is named by site and
`check_id`, so a decision holds for every later scan of that site. Name the
site with `targetHost` (your account) or `scanId` (that scan's site).
`checkId` isn't checked against any scan, so you can triage ahead of time.

```bash
# One finding
curl -X PUT https://www.hebridescyber.co.uk/api/findings/triage \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"targetHost":"shop.example.com","checkId":"headers.csp-absent","state":"snoozed","reason":"Fix booked for next sprint","expiresAt":"2026-11-01T00:00:00Z"}'

# Up to 200 at once
curl -X PUT https://www.hebridescyber.co.uk/api/findings/triage \
  -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d '{"items":[{"targetHost":"shop.example.com","checkId":"dns.dmarc-missing","state":"false_positive","reason":"Parked domain, no mail"}]}'
```

- `state`: `accepted_risk`, `false_positive` or `snoozed`.
- `reason`: 3–2000 characters, required.
- `expiresAt`: ISO 8601, in the future and within a year. Required for
  `snoozed`, optional otherwise (no expiry = until you undo it).
- `GET ?host=` or `?scanId=` (or neither, for your whole account) lists
  decisions, each with `active` (false once expired) and who made it.
- `DELETE` takes `{ targetHost|scanId, checkId }`, `{ items: [...] }`, or the
  same as query parameters (`host`/`scanId`, `checkId`).

Only false positives leave future scores. Every change is audited
(`finding.triaged` / `finding.untriaged`). A bulk request is all-or-nothing.

### `GET /api/portfolio-report`

Agency plan. Every site the account monitors in one client-ready report:
worst site first, open findings by severity (false positives and accepted or
snoozed findings excluded), known-exploited counts, issues shared by more than
one site, and the top priorities per site. White-labelled with the account's
branding. Answers `application/pdf` by default, or `?format=html` for the same
report as HTML. Session or API key. The PDF is generated on request and not
stored.

```bash
curl -o portfolio.pdf https://www.hebridescyber.co.uk/api/portfolio-report \
  -H "Authorization: Bearer $HEBRIDES_CYBER_API_KEY"
```

`403 { "code": "plan_required" }` below an active Agency plan; `404 { "code":
"no_sites" }` when nothing is monitored yet; `429` when rate-limited.

### `GET /POST /PATCH /DELETE /api/account/scheduled-reports`

A security summary emailed daily, weekly or monthly. Session or API key.

- `GET` returns `{ "reports": [...] }`, newest first.
- `POST { "frequency", "recipients", "format"?, "targetUrl"? }` creates one
  (`201`, the stored row). `frequency` is `daily`, `weekly` or `monthly`;
  `recipients` is at least one email address; `targetUrl` is one monitored site,
  or `null` (the default) for every site.
- `PATCH { "id", "enabled"?, "frequency"?, "format"?, "recipients"? }` changes one.
- `DELETE { "id" }` removes one.

`format` decides how the same per-site rows (score, finding counts by severity,
last scan date) arrive:

| `format` | Delivered as |
|---|---|
| `pdf` (default) | A PDF attachment, with the headline figures in the email body |
| `csv` | CSV in the email body |
| `json` | JSON in the email body |

If a PDF can't be generated when the report is sent, that email carries the
same figures as CSV and says so; the stored format stays `pdf`. Counts are
taken from each site's latest completed scan before triage, so false positives
and accepted risks are included. An hourly job sends each report once its
`next_due` has passed; a report with no monitored sites is skipped.

```bash
curl -X POST https://www.hebridescyber.co.uk/api/account/scheduled-reports \
  -H "Authorization: Bearer $HEBRIDES_CYBER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"frequency":"weekly","recipients":["security@example.com"]}'
```

`400` for any other `format` or an invalid field; `503` while the feature isn't
available on the account's database yet.

### `GET /api/v1/targets/{host}/trend`

Score history for every completed scan of `host` you own, oldest first — the
same data the dashboard's score trend chart renders, exposed programmatically.
`host` is a bare hostname (`example.com`, not a full URL), matched against the
hostname of each stored `target_url` rather than an exact string match, since
two scans of "the same" site aren't guaranteed byte-identical URLs.

| Query param | Default | Notes |
|-------------|---------|-------|
| `limit` | 20 | Max 100 |

```json
{
  "host": "example.com",
  "points": [
    { "date": "2026-07-20T09:02:11Z", "score": 61 },
    { "date": "2026-07-27T09:03:02Z", "score": 68 },
    { "date": "2026-08-03T09:01:47Z", "score": 72 }
  ],
  "count": 3
}
```

An empty `points` array means no completed scans of that host exist yet on
this account — not an error.

### `POST /api/dmarc/ingest` — DMARC aggregate (RUA) reports

Receives one DMARC aggregate report (E-66). Unlike the endpoints above this is
**not** authenticated by your API key or session — it's called by a mail /
forwarding provider (a robot, with no session), so it's authenticated by a
**per-owner ingest token**. Generate the token and the full URL from
**Dashboard → Assets → DMARC reports** (or `POST /api/account/dmarc-ingest-token`),
then set it as the destination your DMARC record's `rua=` mailbox forwards to.

- Auth: `?token=<ingest-token>` query parameter, or `Authorization: Bearer <ingest-token>`.
- Body: the raw report — gzip'd XML (the usual case) or plain XML. Max 10 MB.
- Rate-limited per IP (60/hour).

```bash
curl -X POST "https://www.hebridescyber.co.uk/api/dmarc/ingest?token=dmarc_..." \
  --data-binary @report.xml.gz
```

```json
{ "accepted": true, "domain": "example.com", "org": "google.com", "total": 55, "passing": 42, "failing": 13 }
```

Re-POSTing the same report (same org + domain + report id) is idempotent.
`400` = not a parseable DMARC aggregate report; `401` = bad/missing token;
`503` = report storage not enabled on this deployment yet. Read your stored
reports back with `GET /api/dmarc/reports` (session or API key).

---

## Webhooks

Get a signed `POST` when a scan completes, instead of polling
`GET /api/v1/scans/{id}`. Register one from **Dashboard → Integrations → Webhooks** — this is
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
  disabled (visible in **Dashboard → Integrations → Webhooks**) rather than retried forever
  against a dead or mistyped endpoint. Re-registering with a working URL
  starts the failure count fresh.

---

## CI/CD

### Any CI system

The supported route is the scan-gate script and templates served by the app,
documented for customers at **https://www.hebridescyber.co.uk/docs/ci**
(source: `public/ci/`, page `src/app/docs/ci/page.tsx`):

- `public/ci/hebrides-scan.sh` — POSIX `sh` + `curl` + `jq`. Queues a scan
  (`POST /api/v1/scans`), polls `GET /api/v1/scans/{id}`, writes the result to
  `hebrides-scan.json` and optionally a JUnit report. Same gate as the packaged
  Action: it fails only on findings that are **new** since the previous scan,
  at or above `HEBRIDES_FAIL_ON` (default `high`), and **not triaged**; the
  first scan of a target sets the baseline and passes. Exit codes: `0` pass,
  `1` blocked, `2` could not scan (never treated as a pass). The API key is
  passed to curl on stdin, never on its command line.
- Templates: `github-actions.yml`, `gitlab-ci.yml`, `azure-pipelines.yml`,
  `bitbucket-pipelines.yml`, `jenkinsfile.groovy`. Each runs the script from
  the customer's own repository (they keep a reviewed copy rather than
  downloading it on every run) and takes the key from the CI system's secret
  store.

Tests: `src/lib/ciScanScript.test.ts` runs the real script under dash and bash
against a stand-in API; `src/lib/ciTemplates.test.ts` keeps the templates
consistent with it; `tests/e2e/ci-docs.spec.ts` checks the page and downloads.

**Gate on new findings, not totals.** Gating on every finding red-lines a
pipeline on its first run and the check gets disabled the same day.

### GitHub Actions (packaged action)

```yaml
      - uses: andrew-barvas/hebrides-cyber/action@master
        id: scan
        with:
          api-key: ${{ secrets.HEBRIDES_CYBER_API_KEY }}
          target-url: https://staging.example.com
          fail-on: high
```

Outputs `score`, `report-url`, `new-finding-count`, `compared-to-previous-scan`;
`mode: dependencies` runs the pull-request dependency check (see
`POST /api/v1/dependency-diff`). See [`action/README.md`](../../action/README.md).
**Customers can't use it yet:** GitHub only lets other accounts `uses:` an
action from a public repository, and this one is private. Until `action/` is
published from a public repository, point customers at the GitHub Actions
template on `/docs/ci`.

---

## Errors

| Status | Meaning |
|--------|---------|
| `400` | Missing/invalid `target_url`, or it failed the SSRF check |
| `401` | Missing, malformed, revoked, or unknown API key, or a key used from an address outside its IP allowlist |
| `402` | Free-tier scan limit used up — `{ "code": "free_tier_exhausted" }`. Subscribe to a plan to run more; admin accounts are exempt |
| `403` | Domain not verified for this account, or scan belongs to someone else |
| `404` | Scan not found |
| `429` | Rate limit exceeded — see the `Retry-After` header |
| `500` | Could not queue the scan (e.g. a transient database error) — nothing was created, retry the `POST` |

All errors return `{ "error": "..." }`.

A scan that fails **after** being queued doesn't show up as an error from
`POST` — it queued successfully. Check for it via `GET /api/v1/scans/{id}`
returning `"status": "failed"`. The `scan.completed` webhook only fires on a
successful completion today, not on a post-queue failure — poll if you need
to detect that case.

## Rate limits

Enforced per account. On `429`, back off for the seconds given in
`Retry-After`/`retry_after_seconds` rather than retrying immediately.
