# Hebrides Cyber — Scanner → Platform Roadmap

Plan for taking the current scanner to a developer-facing security platform in
the shape of Detectify / Intruder / Probely, kept deliberately lighter and
faster than any of them.

Written against the codebase as it actually stands, not a greenfield design.
Every "already built" claim below was verified against the tree.

---

## 0. Where we actually are

Being honest about the starting line matters more than the destination, because
about half of Part 1 of the brief is already shipped.

### Already built

| Area | Status |
|------|--------|
| TLS / cert grading | `src/lib/scanners/tls.ts` |
| Security headers + CSP grading + cookie flags | `src/lib/scanners/headers.ts` |
| DNS: SPF, DMARC, CAA, DNSSEC | `src/lib/scanners/dns.ts` |
| Sensitive file exposure | `src/lib/scanners/exposure.ts` |
| Tech fingerprinting | `src/lib/scanners/fingerprint.ts` |
| Open ports (Shodan InternetDB) | `src/lib/scanners/ports.ts` |
| Recon: IP, CVEs, crt.sh subdomains | `src/lib/scanners/recon.ts` |
| WordPress deep scan, CORS reflection, JS libs, HTTP methods | `src/lib/scanners/webapp.ts` |
| Severity scoring + 0–100 score | `summariseResults` / `scoreFromFindings` |
| Per-finding remediation | `src/lib/scanners/remediationText.ts` |
| PDF reports | `src/functions/generate-report` |
| Score badge | `src/pages/api/badge/[scanId].ts` |
| Stripe billing + tiers | `src/pages/api/stripe/*` |
| Ownership verification (DNS + file) | `src/lib/ownership.ts` |
| Admin panel | `src/app/admin` |
| Remediation PRs | `src/functions/generate-fix-pr` |

### Genuinely missing

- **Public REST API + API keys** — nothing exists. This is the single biggest
  gap for a "developer-friendly" positioning.
- **Webhooks** on scan completion (Slack notify exists; generic webhooks don't).
- **Teams / roles** — `users` is flat, one owner per scan.
- **Historical comparison & trend graphs** — every scan is an island; no diffing.
- **Shareable report links** — reports are owner-only, no public token.
- **CVE references on findings** — only Shodan CVEs, nothing mapped per-check.
- **CI/CD integration** — no GitHub Action, no example pipelines.
- **Scheduled scans** — `CLAUDE.md` documents `.github/workflows/scheduled-scans.yml`,
  **but that file does not exist**. `monitored_targets` is populated with nothing
  consuming it. This is a documentation/reality mismatch to fix early.
- **Cloud misconfig** (S3 / Azure blob), **directory enumeration**, **CMS beyond
  WordPress** (Joomla, Drupal), **malware / dark-web checks**.
- **Queueing** — `run-scan` executes inline; a slow target blocks the request.

---

## 1. Roadmap

Sequenced so each phase ships something sellable rather than half a platform.

### P0 — Make what exists trustworthy and integrable

Rationale: an API on top of a scanner that reports phantom findings just
distributes the phantoms faster. Correctness first, then the API surface that
makes the product developer-facing.

1. **Close the false-positive class properly.** Done for exposure (catch-all
   baseline + body masking). Apply the same treatment to directory enumeration
   *before* shipping it — it has identical failure modes.
2. **Scan history + diffing.** Cheapest high-value feature; the data is already
   in `scan_results`.
3. **REST API + API keys.** Unlocks CI/CD, the GitHub Action, and the whole
   developer story.
4. **Job queue.** Required before scans get heavier; also fixes the inline
   timeout risk.
5. **Create the missing `scheduled-scans.yml`** so `monitored_targets` does
   something.

### P1 — Platform features

6. Webhooks on completion.
7. GitHub Action + CI examples.
8. Shareable report links.
9. Teams and roles.
10. CVE references per finding.
11. Trend graphs.

### P2 — Depth and premium

12. Directory enumeration, cloud misconfig, Joomla/Drupal.
13. Continuous monitoring with change alerts.
14. AI remediation (extend existing Azure OpenAI wiring).
15. Malware / dark-web (both are buy-not-build — see §7).

---

## 2. Database schema

New migration `sql/migrations/004_platform.sql`. Additive only; nothing below
alters an existing column.

```sql
-- ---------- API keys -------------------------------------------------------
-- Store only a SHA-256 hash. The plaintext key is shown once at creation and
-- is unrecoverable afterwards, so a database leak cannot be replayed.
create table if not exists public.api_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users (id) on delete cascade,
  team_id     uuid references public.teams (id) on delete cascade,
  name        text not null,
  key_hash    text not null unique,
  key_prefix  text not null,          -- first 8 chars, for display: "hc_live_a1b2…"
  scopes      text[] not null default '{scan:read,scan:write}',
  last_used_at timestamptz,
  expires_at  timestamptz,
  revoked_at  timestamptz,
  created_at  timestamptz not null default now()
);
create index on public.api_keys (key_hash) where revoked_at is null;

-- ---------- Teams ----------------------------------------------------------
create table if not exists public.teams (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  owner_id   uuid not null references auth.users (id) on delete restrict,
  created_at timestamptz not null default now()
);

create type team_role as enum ('owner', 'admin', 'member', 'viewer');

create table if not exists public.team_members (
  team_id   uuid not null references public.teams (id) on delete cascade,
  user_id   uuid not null references auth.users (id) on delete cascade,
  role      team_role not null default 'member',
  joined_at timestamptz not null default now(),
  primary key (team_id, user_id)
);

-- ---------- Webhooks -------------------------------------------------------
create table if not exists public.webhooks (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users (id) on delete cascade,
  team_id     uuid references public.teams (id) on delete cascade,
  url         text not null,
  secret      text not null,          -- HMAC-SHA256 signing secret
  events      text[] not null default '{scan.completed}',
  active      boolean not null default true,
  failure_count integer not null default 0,
  created_at  timestamptz not null default now()
);

-- ---------- Shareable reports ---------------------------------------------
create table if not exists public.report_shares (
  id         uuid primary key default gen_random_uuid(),
  scan_id    uuid not null references public.scans (id) on delete cascade,
  token      text not null unique,    -- URL-safe random, 32 bytes
  expires_at timestamptz,
  revoked_at timestamptz,
  view_count integer not null default 0,
  created_at timestamptz not null default now()
);
create index on public.report_shares (token) where revoked_at is null;

-- ---------- Queue ----------------------------------------------------------
create table if not exists public.scan_jobs (
  id           uuid primary key default gen_random_uuid(),
  scan_id      uuid not null references public.scans (id) on delete cascade,
  status       text not null default 'queued',  -- queued|running|done|failed
  priority     integer not null default 0,
  attempts     integer not null default 0,
  max_attempts integer not null default 3,
  locked_by    text,
  locked_at    timestamptz,
  last_error   text,
  created_at   timestamptz not null default now()
);
create index on public.scan_jobs (status, priority desc, created_at)
  where status = 'queued';

-- ---------- Finding-level history -----------------------------------------
-- Denormalised out of scan_results.results so findings are queryable across
-- scans without unpacking JSON. This is what makes diffing and trends cheap.
create table if not exists public.findings (
  id          uuid primary key default gen_random_uuid(),
  scan_id     uuid not null references public.scans (id) on delete cascade,
  fingerprint text not null,          -- stable id: sha256(check_id + target + key detail)
  check_id    text not null,          -- e.g. 'headers.missing.csp'
  severity    text not null,
  title       text not null,
  detail      text,
  remediation text,
  cve_ids     text[] default '{}',
  cwe_id      text,
  created_at  timestamptz not null default now()
);
create index on public.findings (scan_id);
create index on public.findings (fingerprint);
```

Enable RLS on all of the above. Owner-scoped policies mirror the existing
`scans` policies; team access joins through `team_members`.

### The `fingerprint` column is the important one

Diffing two scans is only meaningful if "the same problem" has a stable
identity across runs. Derive it deterministically:

```ts
// src/lib/findingId.ts
import { createHash } from "node:crypto";

/**
 * Stable identity for a finding across scans. Must not include anything that
 * varies run to run (timestamps, counts, expiry dates) or every scan looks
 * like a fresh set of problems and the diff is useless.
 */
export function fingerprintFinding(checkId: string, target: string, key = ""): string {
  return createHash("sha256")
    .update(`${checkId} ${target} ${key}`)
    .digest("hex")
    .slice(0, 32);
}
```

This requires giving each finding a `check_id`, which `summariseResults`
currently does not emit — findings are identified only by human-readable title.
Adding `checkId` to the `Finding` type is a prerequisite for P0 item 2.

---

## 3. REST API

### Authentication

Two credential types against the same routes:

- **Session JWT** (Supabase) — the dashboard.
- **API key** (`Authorization: Bearer hc_live_…`) — CI, scripts, integrations.

```ts
// src/lib/apiAuth.ts
import { createHash, timingSafeEqual } from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export type Caller = { userId: string; teamId: string | null; scopes: string[]; via: "key" | "session" };

export async function authenticate(authHeader: string | undefined): Promise<Caller | null> {
  const token = (authHeader ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return null;

  if (token.startsWith("hc_live_") || token.startsWith("hc_test_")) {
    // Look the key up by hash — never compare plaintext, never store it.
    const hash = createHash("sha256").update(token).digest("hex");
    const { data } = await admin
      .from("api_keys")
      .select("user_id, team_id, scopes, key_hash, expires_at, revoked_at")
      .eq("key_hash", hash)
      .maybeSingle();

    if (!data || data.revoked_at) return null;
    if (data.expires_at && new Date(data.expires_at) < new Date()) return null;

    // Constant-time confirm to avoid leaking hash-prefix timing.
    const a = Buffer.from(hash), b = Buffer.from(data.key_hash);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

    // Fire-and-forget; last_used_at is telemetry, not correctness.
    void admin.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("key_hash", hash);

    return { userId: data.user_id, teamId: data.team_id, scopes: data.scopes, via: "key" };
  }

  const { data: { user } } = await admin.auth.getUser(token);
  return user ? { userId: user.id, teamId: null, scopes: ["*"], via: "session" } : null;
}

export function hasScope(caller: Caller, scope: string): boolean {
  return caller.scopes.includes("*") || caller.scopes.includes(scope);
}
```

Key generation — plaintext returned exactly once:

```ts
import { randomBytes, createHash } from "node:crypto";

export function mintApiKey(live = true) {
  const raw = `hc_${live ? "live" : "test"}_${randomBytes(24).toString("base64url")}`;
  return {
    plaintext: raw,                                        // show once, never stored
    key_hash: createHash("sha256").update(raw).digest("hex"),
    key_prefix: raw.slice(0, 16),
  };
}
```

### Routes

All under `src/pages/api/v1/`.

| Method | Path | Scope | Purpose |
|--------|------|-------|---------|
| `POST` | `/api/v1/scans` | `scan:write` | Queue a scan. `{ target_url, profile? }` → `202 { scan_id, status }` |
| `GET` | `/api/v1/scans` | `scan:read` | List scans, `?limit&cursor&target_url` |
| `GET` | `/api/v1/scans/{id}` | `scan:read` | Status + score + findings |
| `GET` | `/api/v1/scans/{id}/report.pdf` | `scan:read` | PDF |
| `GET` | `/api/v1/scans/{id}/diff/{other}` | `scan:read` | Added / fixed / unchanged |
| `GET` | `/api/v1/targets/{host}/trend` | `scan:read` | Score series |
| `POST` | `/api/v1/keys` | session only | Create key |
| `DELETE` | `/api/v1/keys/{id}` | session only | Revoke |
| `POST` | `/api/v1/webhooks` | `webhook:write` | Register |
| `POST` | `/api/v1/shares` | `scan:write` | Mint share link |

Deliberately: key management is session-only. An API key that can mint more API
keys turns one leaked CI secret into permanent tenant access.

### Response shape

```jsonc
{
  "scan_id": "b3f1…",
  "target_url": "https://example.com",
  "status": "completed",
  "score": 72,
  "started_at": "2026-08-16T09:02:11Z",
  "completed_at": "2026-08-16T09:03:40Z",
  "summary": "Two high-severity issues…",
  "counts": { "critical": 0, "high": 2, "medium": 5, "low": 3, "info": 7 },
  "findings": [
    {
      "check_id": "dns.spf.missing",
      "fingerprint": "9c1f…",
      "severity": "high",
      "title": "No SPF record",
      "detail": "Email from this domain can be spoofed.",
      "remediation": "Publish an SPF record…",
      "cve_ids": [],
      "cwe_id": "CWE-1021",
      "first_seen_scan_id": "a02c…",
      "status": "unchanged"          // new | unchanged | fixed
    }
  ]
}
```

`first_seen_scan_id` and `status` are what make the API useful in CI — they let
a pipeline fail only on *newly introduced* issues rather than the whole backlog.

### Rate limiting

`src/lib/rateLimit.ts` (Upstash) already exists. Apply per API key, not per IP —
CI runners share IPs:

| Tier | Scans/day | API req/min |
|------|-----------|-------------|
| Free | 1 | 10 |
| Basic | 10 | 60 |
| Pro | 50 | 300 |
| Agency | 250 | 1000 |

---

## 4. Queue and async pipeline

`run-scan` currently runs every check inline. Directory enumeration and active
scanning will blow past HTTP timeouts, so the queue is a prerequisite for P2,
not an optimisation.

Postgres-as-queue is the right call at this scale — no new infrastructure, and
`FOR UPDATE SKIP LOCKED` gives safe concurrent claiming:

```sql
-- Claim one job atomically. SKIP LOCKED lets N workers poll the same table
-- without blocking each other or double-claiming.
update public.scan_jobs
set status = 'running', locked_by = $1, locked_at = now(), attempts = attempts + 1
where id = (
  select id from public.scan_jobs
  where status = 'queued'
  order by priority desc, created_at
  for update skip locked
  limit 1
)
returning *;
```

Worker loop (extends the existing `src/worker/runner.ts`):

```ts
async function processOne(workerId: string): Promise<boolean> {
  const job = await claimJob(workerId);
  if (!job) return false;

  try {
    const results = await runAllChecks(job.target_url);
    const { findings } = summariseResults(results);
    const score = scoreFromFindings(findings);
    const summary = await generateAiSummary(results, findings);

    await persistResults(job.scan_id, results, findings, score, summary);
    await markDone(job.id);
    await dispatchWebhooks(job.scan_id, "scan.completed");
  } catch (err) {
    // Retry with backoff; give up after max_attempts and surface the error.
    const fatal = job.attempts >= job.max_attempts;
    await markFailed(job.id, (err as Error).message, fatal);
    if (fatal) await dispatchWebhooks(job.scan_id, "scan.failed");
  }
  return true;
}
```

Per-check isolation matters as much as job-level retry. `runAllChecks` already
uses `Promise.all`, which fails the whole batch if one check throws. Move to
`Promise.allSettled` and record per-check status so one dead third-party API
(Shodan, crt.sh) cannot void an entire scan.

---

## 5. Webhooks

Signed like Stripe's, because that is what developers already know how to verify:

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function signPayload(secret: string, body: string, timestamp: number): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export async function deliver(hook: Webhook, event: string, data: unknown) {
  const body = JSON.stringify({ event, data, sent_at: new Date().toISOString() });
  const ts = Math.floor(Date.now() / 1000);

  const res = await fetch(hook.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "hc-signature": `t=${ts},v1=${signPayload(hook.secret, body, ts)}`,
    },
    body,
    signal: AbortSignal.timeout(10_000),
  });

  // Disable endpoints that keep failing so a dead URL doesn't get retried forever.
  if (!res.ok) await recordFailure(hook.id);
  else await resetFailures(hook.id);
}
```

Include the timestamp in the signed material and reject anything older than
~5 minutes on the receiving side, otherwise a captured payload can be replayed
indefinitely.

Retry on 5xx with backoff (1m, 5m, 30m, 2h, 6h); deactivate after 20 consecutive
failures.

---

## 6. CI/CD integration

### GitHub Action

`action.yml` in a separate `hebrides-cyber/scan-action` repo:

```yaml
name: 'Hebrides Cyber Scan'
description: 'Run a security scan and optionally fail the build on new findings'
inputs:
  api-key:
    description: 'Hebrides Cyber API key'
    required: true
  target-url:
    description: 'URL to scan'
    required: true
  fail-on:
    description: 'Fail if a NEW finding at or above this severity appears (critical|high|medium|low|none)'
    default: 'high'
  timeout:
    description: 'Seconds to wait for completion'
    default: '300'
outputs:
  score:
    description: 'Security score 0-100'
  report-url:
    description: 'Link to the full report'
runs:
  using: 'node20'
  main: 'dist/index.js'
```

Consumer workflow:

```yaml
name: Security
on:
  pull_request:
  schedule:
    - cron: '0 3 * * 1'   # Mondays, 03:00 UTC

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: hebrides-cyber/scan-action@v1
        id: scan
        with:
          api-key: ${{ secrets.HEBRIDES_CYBER_API_KEY }}
          target-url: https://staging.example.com
          fail-on: high

      - name: Comment score on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `🔐 Security score: **${{ steps.scan.outputs.score }}/100** — [full report](${{ steps.scan.outputs.report-url }})`
            })
```

**`fail-on` must mean "new findings only."** Failing on total findings means the
first run red-lights every existing pipeline and teams disable the check that
day. Gate on `status === "new"` from the diff — which is why finding
fingerprints are P0.

### The missing scheduled-scans workflow

`.github/workflows/scheduled-scans.yml` — referenced in `CLAUDE.md` but absent:

```yaml
name: Scheduled Scans
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci
      - run: npx tsx src/scripts/fetch-scheduled-targets.ts
        env:
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_SERVICE_ROLE_KEY: ${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}
          AZURE_FUNCTIONS_URL: ${{ secrets.AZURE_FUNCTIONS_URL }}
          GITHUB_ACTIONS_TOKEN: ${{ secrets.GITHUB_ACTIONS_TOKEN }}
```

Once the queue lands this becomes "enqueue jobs", not "run scans", and stops
being bounded by Action runtime limits.

---

## 7. Additional scanners

### Directory enumeration — build with care

Highest false-positive risk in the whole product. Reuse the exposure module's
baseline machinery rather than writing a second, weaker version:

- Establish a known-404 body baseline first (`fetchBaseline`).
- Mask the probed path before comparing (`normaliseBody`).
- Cap concurrency (≤10) and respect `Retry-After`.
- Skip the check entirely if the origin 200s for random paths *and* bodies are
  non-deterministic — better to report "inconclusive" than to guess.

### Cloud misconfiguration

```ts
// Detect bucket references in page source, then test each for public listing.
const BUCKET_PATTERNS = [
  /https?:\/\/([a-z0-9.-]+)\.s3[.-]([a-z0-9-]+)?\.?amazonaws\.com/gi,
  /https?:\/\/s3[.-]([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9.-]+)/gi,
  /https?:\/\/([a-z0-9]+)\.blob\.core\.windows\.net\/([a-z0-9-]+)/gi,
  /https?:\/\/storage\.googleapis\.com\/([a-z0-9._-]+)/gi,
];
```

Only ever test for **public listing/read of buckets the target site itself
references**. Do not enumerate candidate bucket names — that is scanning
third-party infrastructure the customer does not own.

### CVE references

Map `check_id` → CWE statically (cheap, stable), and enrich version-specific
findings from OSV.dev, which is free and needs no key:

```ts
const res = await fetch("https://api.osv.dev/v1/query", {
  method: "POST",
  body: JSON.stringify({ package: { name: lib.name, ecosystem: "npm" }, version: lib.version }),
  signal: AbortSignal.timeout(8000),
});
```

Cache aggressively — the same jQuery version resolves identically for every
customer.

### Malware and dark-web — buy, don't build

Both are data problems, not code problems. Malware detection without a
maintained signature corpus is worse than none, and "dark web exposure" built
in-house means scraping breach dumps — a legal and ethical liability. Integrate
Google Safe Browsing (free) and Have I Been Pwned's domain API (paid,
legitimate) and be explicit in the UI that these are third-party sources.

---

## 8. UI

The cyber palette is now a set of five theme-aware tokens
(`cyberbg`, `cyberpanel`, `cyberborder`, `cybertext`, `neon`) backed by CSS
variables in `globals.css`. Build new surfaces from those tokens only — never
raw hex, and never `text-white`, which cannot follow the theme.

### Dashboard layout

```
┌──────────────────────────────────────────────────────────┐
│  > Hebrides_Cyber      Services  Pricing  Docs   [☀] [≡] │
├──────────────────────────────────────────────────────────┤
│  $ ./dashboard --overview                                │
│  Security Overview                                       │
│                                                          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐            │
│  │    72      │ │  ▲ +6      │ │  2 new     │            │
│  │  /100      │ │  vs last   │ │  this week │            │
│  │  Fair      │ │  scan      │ │            │            │
│  └────────────┘ └────────────┘ └────────────┘            │
│                                                          │
│  Score trend (90d)                                       │
│  ┌──────────────────────────────────────────────┐        │
│  │            ╭──╮      ╭────────                │        │
│  │      ╭─────╯  ╰──────╯                        │        │
│  │  ────╯                                        │        │
│  └──────────────────────────────────────────────┘        │
│                                                          │
│  Findings                    [All][New][Fixed]           │
│  ┌──────────────────────────────────────────────┐        │
│  │ ● CRITICAL  CORS reflects Origin    NEW      │        │
│  │   ▸ How to fix                               │        │
│  ├──────────────────────────────────────────────┤        │
│  │ ● HIGH      No SPF record          8d old    │        │
│  └──────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

The **New / Fixed** filter is the feature that changes how the product feels —
it turns a static audit into something you check after a deploy.

### Diff view

```
Comparing  #a02c (12 Aug)  →  #b3f1 (16 Aug)

  NEW (2)
    ● HIGH      CORS reflects arbitrary Origin
    ● MEDIUM    Cookie "sid" missing SameSite

  FIXED (3)
    ✓ HIGH      No SPF record
    ✓ MEDIUM    HSTS header missing

  UNCHANGED (14)                            [expand]

  Score  66 → 72  ▲ +6
```

---

## 9. Trust signals

Placement and copy. The constraint on all of it: only claim what the scanner
actually does.

**Hero** — under the existing subheadline:
> OWASP-aligned checks · Powered by Azure · UK-based, GDPR compliant

**Below the scan input:**
> We scan only domains you've verified you own. Results are private to your
> account and never shared or sold.

That line is true today — `src/lib/ownership.ts` enforces it — which is exactly
why it is worth saying.

**Footer / pricing:**
> Used by developers, agencies, and in-house security teams.

Use this only once there are real customers to point at. An unsubstantiated
social-proof claim on a security product is the fastest way to lose a technical
buyer.

**Methodology page** (new, `/methodology`) — how each check works, what it
cannot detect, and false-positive handling. This is the single most persuasive
page for a developer audience and almost nobody in this market has one. It also
gives you somewhere honest to describe the catch-all baseline work rather than
pretending false positives never happen.

**GDPR** — `/privacy` already covers processors, retention, and rights. Link it
from the scan form, not just the footer.

---

## 10. Suggested build order

| # | Work | Why here |
|---|------|----------|
| 1 | `check_id` + `fingerprint` on findings | Everything downstream needs stable identity |
| 2 | `findings` table + backfill | Makes history queryable |
| 3 | Diff endpoint + New/Fixed UI | First visible payoff |
| 4 | `scan_jobs` queue + worker | Unblocks heavier checks |
| 5 | API keys + `/api/v1/scans` | Opens the developer surface |
| 6 | GitHub Action | The reason the API exists |
| 7 | Webhooks | Cheap once the queue emits events |
| 8 | Shareable reports | Agency tier selling point |
| 9 | Teams + roles | Needed before selling to teams |
| 10 | Trend graphs | Data already there by now |
| 11 | CVE/CWE enrichment | Credibility with security buyers |
| 12 | Directory enum, cloud misconfig | Only once the queue can carry them |

Items 1–3 are worth doing as one piece of work; splitting them leaves a
half-migrated findings model in production.

---

## Appendix — conventions for new checks

1. Export the result type from the module; add it to `ScanResults` in
   `src/lib/scanners/index.ts`.
2. Push findings in `summariseResults` with `severity`, `title`, `detail`,
   `remediation`, and (once added) `checkId`.
3. Put remediation prose in `src/lib/scanners/remediationText.ts`, not inline.
4. Never report a finding you cannot evidence. If the server's behaviour is
   ambiguous, return nothing — a false positive costs more trust than a missed
   low-severity finding earns.
5. Every outbound request gets `AbortSignal.timeout()`. A hung third party must
   not hang a scan.
