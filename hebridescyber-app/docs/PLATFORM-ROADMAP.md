# Hebrides Cyber — Scanner → Platform Roadmap

Plan for taking the current scanner to a developer-facing security platform in
the shape of Detectify / Intruder / Probely, kept deliberately lighter and
faster than any of them.

Written against the codebase as it actually stands, not a greenfield design.
Every "already built" claim below was verified against the tree.

> **Status update (16 Aug):** P0 items 2, 3, and 6 below are now built — finding
> identity + scan diffing (in a leaner form than originally sketched here: no
> new `findings` table, findings are diffed directly from the existing
> `scan_results` jsonb — see the correction on item 2), the REST API + API
> keys, and webhooks on scan completion. Shareable report links (P1 item 8)
> are also built. The queue (item 4) turned out to be a different problem
> than described: `src/worker/` already has a complete BullMQ-based queue +
> worker with real nmap/nuclei/sqlmap/ZAP-active-scan integrations — it was
> built and never connected (`enqueueScan()` has zero callers, no `REDIS_URL`
> configured, no deployment target). `scheduled-scans.yml` (item 5) does
> exist — it's at the repo root's `.github/workflows/`, one level up from
> this app directory, which is why it read as "missing" in an earlier pass
> that checked from the wrong directory.
>
> **Hosting constraint (confirmed with the site owner, 16 Aug): this app runs
> on Azure's free tier — Static Web Apps + Consumption-plan Functions — with
> no Redis and no container host.** This ruled out wiring up the orphaned
> BullMQ worker as-is, and ruled out the nmap/nuclei/sqlmap/ZAP tool suite on
> Azure specifically — Consumption Functions and Static Web Apps can't run
> installed binaries at all (no shell access, no custom image, 5–10 min
> execution cap).
>
> **Resolved (17 Aug): wired in via the GitHub Actions queue worker, not
> Azure.** The BullMQ+Redis worker (`src/worker/runner.ts`, `index.ts`,
> `src/lib/queue.ts`, `docker-compose.yml`, `worker.Dockerfile`) is deleted —
> its tool-invocation logic was ported into `executeScan()`
> (`src/lib/scanExecution.ts`), gated behind an explicit `runExtendedTools`
> flag that only `run-queued-scan-jobs.ts` passes. `.github/workflows/scheduled-scans.yml`'s
> `work` job now installs nmap/sqlmap/nuclei and starts a ZAP daemon before
> running the worker — all free (GitHub Actions minutes, no new Azure spend).
> Azure Container Apps Jobs was considered and rejected for now: its free
> tier would likely also have covered this at current volume, but it adds a
> second infrastructure surface for something GitHub Actions runners already
> do for £0. Revisit ACA specifically if tool-version reproducibility or
> IP/isolation hygiene (active-scan payloads currently originate from
> GitHub's shared, well-known IP ranges) becomes a real concern.
>
> **Found and fixed (17 Aug): the scan pipeline had no working deployment.**
> While checking whether `run-scan` was actually live, found that the
> standalone `src/functions/` Azure Functions app (`run-scan`,
> `verify-ownership`, `generate-report`, `generate-fix-pr`,
> `generate-newsletter`) was never deployable in the first place — no
> `host.json`, no Functions-specific `package.json`, no real
> `@azure/functions` registration, just plain TS modules with a hand-rolled
> `HttpRequest`/`HttpResponseInit` stub. The Azure resource
> (`hebrides-cyber-fn`) existed and was running, but had zero functions
> deployed to it. Separately, `src/pages/api/run-scan.ts` turned out to
> already exist as an independent, drifted duplicate of the same logic
> (missing the free-tier cap, admin bypass, shared `executeScan()`, and
> everything else built around those this session) — an earlier build
> attempt that got superseded and never deleted.
>
> **Fix: consolidated everything onto `src/pages/api/*`.** All five
> functions rebuilt/ported as Next.js API routes, deployed via the same
> `deploy.yml`/Azure Static Web Apps pipeline already proven to work — no
> second Azure resource, no second deploy pipeline. `src/functions/` and
> the now-unneeded Function App provisioning (Terraform, `provision.sh`)
> deleted/trimmed. Also fixed while porting: `generate-report` had **no
> auth check at all** — any caller who knew or guessed a `scan_id` could
> download any customer's full report. Now requires scan ownership (or
> admin). And: `ALLOW_DEV_TOKEN_VERIFICATION` now defaults to `false` (real
> domain verification required) instead of `true` — the dashboard's
> "Verify domain ownership" section is no longer just "(recommended)".

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
| Public REST API + API keys | `src/pages/api/v1/*`, `src/pages/api/keys.ts`, `src/lib/apiAuth.ts` |
| Finding identity + scan-to-scan diff | `Finding.checkId` in `src/lib/scanners/index.ts`, `src/lib/findingsDiff.ts` |
| Webhooks on scan completion | `src/lib/webhooks.ts`, `src/pages/api/webhooks.ts` |
| Shareable report links | `src/pages/api/reports/[token].ts`, `src/app/share/[token]/page.tsx`, migration `006_report_shares.sql` |
| CVE references (JS libraries) | `src/lib/scanners/osv.ts`, live OSV.dev lookup |
| Packaged GitHub Action | `action/` at the repo root — `uses: andrew-barvas/hebrides-cyber/action@master` |
| Teams (view-only sharing) | migration `007_teams.sql`, `src/pages/api/team.ts`, `src/pages/api/team/members.ts`, `src/components/TeamSection.tsx` |
| Score trend chart | `src/components/ScoreTrend.tsx` on the scan report page |
| Directory listing (autoindex) detection | `src/lib/scanners/directoryListing.ts`, reuses `src/lib/scanners/httpProbe.ts`'s baseline/masking |
| Cloud storage misconfig (S3 / Azure Blob / GCS public listing) | `src/lib/scanners/cloudMisconfig.ts` — tests only buckets the target's own page source references |
| Joomla / Drupal deep scan | `checkJoomla` / `checkDrupal` in `src/lib/scanners/webapp.ts`, gated on `fingerprint.ts` detection |
| "What we check" technical page | `src/app/what-we-check/page.tsx`, linked from nav + services page |
| Continuous monitoring change alerts (Slack) | `sendSlackAlert` wired into `src/functions/run-scan/index.ts`, gated on Pro/Agency plan + `new_finding_count > 0` — was built but never called from the live path before |
| AI-tailored remediation (on-demand, per-finding) | `src/lib/aiRemediation.ts`, `src/pages/api/scans/[id]/ai-fix.ts`, "✨ Get an AI-tailored fix" button in `ScanReportView.tsx` — reuses the same Azure OpenAI wiring as `generateAiSummary`, no new env vars |
| Job queue (free-tier) | `sql/migrations/008_scan_jobs.sql` (`claim_scan_job()` SKIP LOCKED RPC), `src/scripts/enqueue-scheduled-scans.ts`, `src/scripts/run-queued-scan-jobs.ts` — GitHub Actions shards as ephemeral workers, Postgres as the queue, no Redis/long-lived container. Scopes only the scheduled-monitoring path today; the dashboard's synchronous "Run scan" button still calls `run-scan` directly (see §4) |
| Extended tool suite (nmap/nuclei/sqlmap/ZAP) | `runExtendedTools` option on `executeScan()` (`src/lib/scanExecution.ts`), enabled only by `run-queued-scan-jobs.ts` — tools installed fresh per run in `scheduled-scans.yml`'s `work` job. Ported from the deleted BullMQ worker; findings now carry `checkId` (the original never set one) so they participate in the New/Fixed diff |

### Genuinely missing

- **CVE references beyond JS libraries** — done for vulnerable JS libraries
  via a live OSV.dev lookup (see below); `fingerprint.ts`'s broader
  `riskySoftware` (WordPress core, PHP, Apache) is still prose-only. Those
  don't map cleanly to any single OSV ecosystem the way npm packages do, so
  extending this further needs a different data source per software type, not
  just widening the existing OSV call.
- **Malware / dark-web checks** (buy-not-build — see §7).

~~The `src/worker/` BullMQ+Redis worker is dead code.~~ **Deleted (17 Aug)** —
the Postgres `SKIP LOCKED` design got built instead (§4), and its
`nmap`/`nuclei`/`sqlmap`/`ZAP` tool-invocation logic was ported into
`executeScan()` rather than left as an unused reference. See §4.

---

## 1. Roadmap

Sequenced so each phase ships something sellable rather than half a platform.

### P0 — Make what exists trustworthy and integrable

Rationale: an API on top of a scanner that reports phantom findings just
distributes the phantoms faster. Correctness first, then the API surface that
makes the product developer-facing.

1. ~~**Close the false-positive class properly.**~~ **Done** — catch-all
   baseline + body masking, now shared via `src/lib/scanners/httpProbe.ts`
   between exposure and directory listing detection (identical failure modes,
   same fix).
2. ~~**Scan history + diffing.**~~ **Done**, leaner than sketched below —
   findings carry a `checkId` (`src/lib/scanners/index.ts`), and
   `src/lib/findingsDiff.ts` diffs two scans' findings directly from the
   existing `scan_results.results.findings` jsonb. No new `findings` table
   was needed for this; §2's relational schema is only worth building once
   something needs a cross-scan/cross-customer *query* over findings (trend
   graphs, CVE search) rather than a two-scan comparison.
3. ~~**REST API + API keys.**~~ **Done** — `src/pages/api/v1/scans*.ts`,
   `src/lib/apiAuth.ts`, `src/lib/apiKeys.ts`, migration `004_api_keys.sql`.
4. ~~**Job queue.**~~ **Done** — see §4. Postgres `SKIP LOCKED` +
   GitHub Actions worker shards, not the BullMQ/Redis path.
5. ~~**Create the missing `scheduled-scans.yml`**~~ — it already existed, at
   the repo root, not missing. It had a real bug though (Node 20 CI runner
   lacking a native WebSocket global, which `@supabase/supabase-js` needs even
   for non-realtime calls) — fixed.

### P1 — Platform features

6. ~~Webhooks on completion.~~ **Done** — `src/lib/webhooks.ts`,
   `src/pages/api/webhooks.ts`, `src/components/Webhooks.tsx`. Fires from all
   three scan-completion points (the real Azure Function path, `/api/v1/scans`,
   and the orphaned worker for parity). No queue existed to build proper
   backoff-and-retry on, so delivery is inline: one attempt, one retry after
   ~2s, then recorded as failed; auto-disabled after 20 consecutive failures.
7. ~~GitHub Action + CI examples.~~ **Done** — `action/` at the true repo
   root (not a separate repo, per the sketch below; `uses:` supports a path
   within the same repo), dependency-free Node 20 (`action/index.js`, no
   `node_modules`). Implements the new-findings-only gate: `POST /api/v1/scans`
   already returns the full diff-tagged report in one call, so the action
   doesn't need the two-call polling shape the curl/jq example uses. `docs/API.md`
   keeps the raw curl/jq version too, for non-GitHub CI.
8. ~~Shareable report links.~~ **Done** — `src/pages/api/reports/[token].ts`
   (public, no auth — token is the credential, same trust model as the
   existing badge route), `src/pages/api/scans/[id]/shares.ts` (session-only
   management), `src/app/share/[token]/page.tsx`, migration
   `006_report_shares.sql`. No public RLS policy on `report_shares` — see the
   migration comment for why that would leak every customer's tokens.
9. ~~Teams and roles.~~ **Done, scoped to view-only sharing** — migration
   `007_teams.sql` adds `teams`/`team_members` and extends the existing
   `scans`/`scan_results`/`monitored_targets` SELECT policies with an OR
   clause for team members, rather than changing anything about how those
   rows get created — every scan-creation code path still inserts
   `owner: callerId` exactly as before. Two roles: `admin` (can invite/remove
   `member`-role users) and `member` (read-only). Neither can create scans,
   see billing, or touch API keys/webhooks/share links — those all stay
   owner-only. Real permission checks in `src/pages/api/team/members.ts`
   (owner > admin > member > self-only-leave), not just RLS. Inviting adds an
   *existing* Hebrides Cyber user by email — no invite-token/email-sending
   flow, deliberately, to avoid building that infrastructure for a v1.
10. ~~CVE references per finding.~~ **Done for JS libraries** —
    `src/lib/scanners/osv.ts` queries OSV.dev live (npm ecosystem) for
    vulnerable-library findings from `webapp.ts`, falling back to CVE ids
    already named in the existing static `reason` text if OSV is unreachable.
    Verified against the real OSV.dev API: lodash 4.17.15's hardcoded reason
    names one CVE, the live lookup found six, including ones from 2025/2026
    that couldn't have existed when the static table was written. Not
    extended to `fingerprint.ts`'s broader `riskySoftware` — see the
    correction above.
11. ~~Trend graphs.~~ **Done** — `src/components/ScoreTrend.tsx`, a hand-
    rolled SVG line (not a charting library — one line, 0-100 fixed scale,
    not worth a dependency), on the scan report page. Reuses the same
    hostname-matching pattern as the finding diff to find every past scan of
    the target. In-app dashboard only — no `GET /api/v1/targets/{host}/trend`
    endpoint yet, since nothing asked for programmatic access to this.

### P2 — Depth and premium

12. ~~Directory enumeration, cloud misconfig, Joomla/Drupal.~~ **Done** —
    `src/lib/scanners/directoryListing.ts`, `src/lib/scanners/cloudMisconfig.ts`,
    `checkJoomla`/`checkDrupal` in `src/lib/scanners/webapp.ts`.
13. ~~Continuous monitoring with change alerts.~~ **Done** — scheduled scanning
    already existed (`.github/workflows/scheduled-scans.yml`); what was
    missing was the alert. `sendSlackAlert` existed too, but was only ever
    called from the disconnected `src/worker/runner.ts` — wired into the live
    `run-scan` path instead, gated on Pro/Agency plan and on
    `new_finding_count > 0` so nightly runs with nothing new don't spam the
    channel.
14. ~~AI remediation.~~ **Done** — `src/lib/aiRemediation.ts`. On-demand
    per-finding, not automatic per scan (cost/latency) — a button on the scan
    report calls `POST /api/scans/{id}/ai-fix`, which sends the finding plus
    the detected tech stack (`fingerprint.ts`) to Azure OpenAI for a
    stack-specific fix, distinct from the static `remediationText.ts` content
    and from `generate-fix-pr`'s templated PRs.
15. Malware / dark-web (buy-not-build — see §7).

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
    .update(`${checkId} ${target} ${key}`)
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

## 4. Queue and async pipeline — done, scoped to scheduled scans

Postgres-as-queue, worked by ephemeral GitHub Actions runners instead of a
long-lived container or Redis — the free-tier-compatible option this section
used to just sketch. Built:

- `sql/migrations/008_scan_jobs.sql` — `scan_jobs` table plus a
  `claim_scan_job(worker_id)` RPC that does the atomic
  `SELECT ... FOR UPDATE SKIP LOCKED` + claim in one plpgsql function, since
  PostgREST can't express locking clauses through the normal query builder.
- `src/scripts/enqueue-scheduled-scans.ts` — inserts one `scan_jobs` row per
  monitored target with an active subscription *and* a real, on-file domain
  verification (skips unverified targets rather than relying on `run-scan`'s
  own gate to reject them later, since the worker now runs scans directly
  rather than calling that Function).
- `src/scripts/run-queued-scan-jobs.ts` — the worker. Loops
  `claim_scan_job()` until the queue is empty or its own bounded budget
  (`MAX_JOBS_PER_RUN`, `TIME_BUDGET_MS`) runs out; re-checks SSRF and domain
  verification per job (defense in depth — a job can sit queued for a
  while); runs each one via `src/lib/scanExecution.ts`'s `executeScan()`.
- `src/lib/scanExecution.ts` — extracted from `run-scan`'s step-2 body so
  both the synchronous dashboard path and the queued path share one
  implementation of "run the checks, write results, fire webhooks/Slack
  alert" rather than two that can drift. Split into two phases internally:
  a try/catch that can mark the scan `failed` (the checks + persisting
  results), and a separate try/catch for post-completion notifications
  (webhook dispatch, Slack alert) that logs but never flips an
  already-`completed` scan back to `failed` if, say, the findings-diff
  lookup hits a transient network error.
- `.github/workflows/scheduled-scans.yml` — `enqueue` job then a fixed
  3-shard `work` matrix, each shard running the worker script. Scales by
  adding shards, not by widening a per-target matrix the way the old
  curl-based version did.

**Scope**: this only replaces the *scheduled monitoring* path. The
dashboard's synchronous "Run scan" button still calls `run-scan` directly and
never passes `runExtendedTools` — every passive check runs fine within the
Function's timeout, so there was no forcing reason to change that UX (instant
→ "queued, check back"). The real active-scanning tools (nmap/nuclei/sqlmap/
ZAP — see below) are wired in, but *only* for the queued path; giving the
dashboard button a "deep scan" option that hands off to the queue instead of
running inline is still open, and is the more likely reason to revisit this
scope than tool integration now is. Also revisit if scan volume on the
interactive path itself becomes a problem, which isn't true yet.

Per-check isolation is still worth doing separately: `runAllChecks` uses
`Promise.all`, which fails the whole batch if one check throws. Moving to
`Promise.allSettled` with per-check status recorded would stop one dead
third-party API (Shodan, crt.sh) from voiding an entire scan — orthogonal to
the queue, not solved by it.

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

### Scheduled scans — done, now queue-backed

`.github/workflows/scheduled-scans.yml` exists and now enqueues rather than
running scans directly — see §4 for the full design
(`enqueue-scheduled-scans.ts` / `run-queued-scan-jobs.ts` /
`scan_jobs`/`claim_scan_job()`). No longer bounded by a single Action's
runtime the way the earlier curl-per-target version was, since a backlog
just rolls over to the next scheduled run instead of one job trying to get
through every target before it times out.

---

## 7. Additional scanners

### Directory listing (autoindex) detection — done

`src/lib/scanners/directoryListing.ts`. Highest false-positive risk in the
whole product, so it reuses the exposure module's baseline machinery rather
than a second, weaker version — extracted into `src/lib/scanners/httpProbe.ts`
so both checks share one proven implementation:

- Known-404 body baseline first (`fetchBaseline`), path masked before
  comparing (`normaliseBody`), catch-all bodies rejected (`isCatchAllBody`).
- Scoped narrowly to genuine autoindex pages — requires both an
  `Index of /...` title/heading *and* a "Parent Directory" link, not just any
  200 on a common directory path. A page that merely 200s at `/uploads/`
  (an upload form, say) is not flagged.
- Probes a curated list of commonly-autoindexed paths (`/uploads/`,
  `/backup/`, `/logs/`, etc.) rather than a brute-force wordlist.

### Cloud misconfiguration — done

`src/lib/scanners/cloudMisconfig.ts`. Extracts S3/Azure Blob/GCS references
from the target's own page source, then tests only those specific
buckets/containers for public listing (a real `GET` against the bucket's list
endpoint, checking for `<ListBucketResult>`/`<EnumerationResults>` in the
response — not just a reachability probe). Deliberately never enumerates
candidate bucket names — that would be scanning third-party infrastructure the
customer doesn't own, out of scope for an authorised single-target scan.
Candidate extraction is capped at 15 per scan to bound worst-case request
volume against that third-party infrastructure.

### CMS beyond WordPress — done

`checkJoomla`/`checkDrupal` in `src/lib/scanners/webapp.ts`, gated the same
way `checkWordPress` already was — only runs when `fingerprint.ts` detected
the CMS. Joomla: version disclosure via the administrator manifest, installer
leftover files (`htaccess.txt`/`web.config.txt`). Drupal: version disclosure
via `CHANGELOG.txt`, `update.php` reachability, public JSON:API, and whether
the uid 1 superuser profile is publicly viewable.

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
