# Engineering log — August 2026 (frozen)

> **Frozen 2026-08-23.** This file is a historical record, not current
> documentation — formerly `docs/PLATFORM-ROADMAP.md`. Every present-tense
> claim below was true only as of its nearest dated status update; several
> are now false, and the sections that were pure present-tense status
> (database schema, REST API, webhooks, CI/CD, the "already built" table,
> the conventions appendix) have been replaced with pointers to where that
> content actually lives now, rather than being left to rot in place. What's
> left is genuine decision history — why BullMQ+Redis was deleted, why Azure
> Container Apps was evaluated and rejected (and the specific condition that
> would reopen that evaluation), why `src/functions/` turned out to be
> non-deployable, that `generate-report` briefly had no auth check at all —
> and that record is kept intact rather than rewritten, because sanitising it
> for accuracy would destroy the only thing that makes it worth keeping.
>
> **For current state:** `docs/FUNCTIONALITY-MATRIX.md`.
> **For the forward plan:** `docs/ROADMAP.md`.
> **For the enhancement backlog this file's surviving open items were
> harvested into:** `docs/ENHANCEMENTS.md`.
>
> Nothing after 18 Aug is recorded here — roughly a week of shipped work
> (MS Teams webhooks, Jira/Linear ticket integrations with dedupe/auto-close,
> authenticated scanning, the Vitest test suite, Checkov IaC scanning,
> xsser/commix, white-label branding, the vertical landing pages, this
> documentation set itself) happened after this log stopped being updated —
> that's not a gap in the history, it's simply where the log ends and the
> current docs above pick up.

---

## Original document: "Scanner → Platform Roadmap"

Plan for taking the current scanner to a developer-facing security platform in
the shape of Detectify / Intruder / Probely, kept deliberately lighter and
faster than any of them.

Written against the codebase as it actually stands, not a greenfield design.
Every "already built" claim below was verified against the tree **at the
time it was written** — see the frozen banner above.

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

*Moved to `docs/FUNCTIONALITY-MATRIX.md` — that file is regenerated from
the code and won't drift the way a status table in a frozen log inevitably
does. (This table itself had already gone stale before the file was
frozen — it still pointed PDF reports and remediation PRs at the deleted
`src/functions/` directory, 30 lines below this section's own 17 Aug note
explaining that directory was deleted.)*

### Genuinely missing

- **CVE references beyond JS libraries** — done for vulnerable JS libraries
  via a live OSV.dev lookup (see below); `fingerprint.ts`'s broader
  `riskySoftware` (WordPress core, PHP, Apache) is still prose-only. Those
  don't map cleanly to any single OSV ecosystem the way npm packages do, so
  extending this further needs a different data source per software type, not
  just widening the existing OSV call. **Still genuinely open** — tracked as
  `docs/ENHANCEMENTS.md` E-24.
- ~~**Malware / dark-web checks**~~ (buy-not-build — see §7). **Done** —
  Google Safe Browsing (`src/lib/scanners/safeBrowsing.ts`) and
  HaveIBeenPwned domain search (`src/lib/scanners/hibp.ts`) both shipped,
  exactly as §7's "buy, don't build" reasoning proposed.

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
   `node_modules`). Implements the new-findings-only gate.
   >
   > **Correction (18 Aug):** `POST /api/v1/scans` used to return the full
   > diff-tagged report in one synchronous call, so this originally didn't
   > need to poll. It now queues and returns `202` immediately instead, for the same
   > reason `run-scan.ts` moved off calling `executeScan()` inline: Azure
   > Static Web Apps' Free-tier managed Functions execution ceiling could
   > kill a slow scan mid-request with a proxy error rather than valid JSON.
   > `action/index.js` now polls `GET /api/v1/scans/{id}` after queuing —
   > the two-call shape the curl/jq example always used. `docs/API.md` keeps
   > the raw curl/jq version too, for non-GitHub CI.
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

*Superseded — the sketched `004_platform.sql` was never built as written. API keys/webhooks/teams/shares/scan-jobs each got their own focused migration instead (`004`-`008`), and the proposed relational `findings` table was deliberately never built — P0 item 2 in §1 explains why (the existing `checkId` + jsonb-diff approach turned out to be sufficient). Current schema: `CLAUDE.md`'s "Database schema" section and the `sql/migrations/` files themselves.*

## 3. REST API

*Moved to `docs/API.md` — the full, current endpoint reference. This section was a design sketch superseded by the real implementation.*

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

**Scope, updated (18 Aug)**: originally only replaced the *scheduled
monitoring* path — the assumption above was that every passive check ran
fine within the Function's timeout on the dashboard's synchronous "Run scan"
button. That assumption turned out to be wrong in production: a real scan
against a real target ("Backend call failure" on the dashboard) exceeded
Azure Static Web Apps' Free-tier execution ceiling and returned a proxy
error instead of JSON. Both `run-scan.ts` (dashboard) and `POST
/api/v1/scans` (public API) now enqueue via `scan_jobs` the same way the
scheduled path does — see `.github/workflows/on-demand-scan.yml`, a
lightweight sibling of `scheduled-scans.yml`'s `work` job that skips the
nmap/sqlmap/nuclei/testssl.sh/gitleaks/ZAP installs (on-demand jobs stay
passive-only, distinguished from scheduled jobs by whether `scan_jobs.scan_id`
arrives pre-set — see `run-queued-scan-jobs.ts`'s `runOne()`). Both routes
trigger that workflow immediately via the GitHub API
(`src/lib/onDemandScanTrigger.ts`) rather than waiting for the next cron,
falling back to the daily cron if `GITHUB_PAT` isn't configured. `docs/API.md`
and `action/index.js` were updated to poll `GET /api/v1/scans/{id}` instead
of expecting a synchronous report — a breaking change for any existing API
integration that parsed the `POST` response directly, accepted deliberately
since the alternative was leaving a real, already-observed production bug in
place.

Per-check isolation is still worth doing separately: `runAllChecks` uses
`Promise.all`, which fails the whole batch if one check throws. Moving to
`Promise.allSettled` with per-check status recorded would stop one dead
third-party API (Shodan, crt.sh) from voiding an entire scan — orthogonal to
the queue, not solved by it.

---

## 5. Webhooks

*Moved to `docs/API.md`'s webhooks section — current and accurate, this duplicated it.*

## 6. CI/CD integration

*Moved to `docs/API.md` (CI/CD recipes) and `action/README.md` (the packaged GitHub Action itself) — both are current and this section duplicated them.*

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

**Done** — nearly everything proposed here shipped: the hero tagline is
live on the homepage, `/what-we-check` covers the `/methodology` goal, and
the ownership-verification line is live on the dashboard's scan form. The
one still-deferred item (the "Used by developers, agencies..." footer
social-proof line, gated on having real customers) moved to
`../marketing/01-homepage-copy.md` alongside the testimonials placeholder
it's the same kind of claim as. The GDPR footer-link gap this section
assumed was already closed turned out not to be — tracked as
`docs/ENHANCEMENTS.md` E-23.

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

*Extracted to `docs/SCANNER-CONVENTIONS.md` — this is live normative content
six scanner source files reference directly, not just history, so it moved
to its own file rather than being frozen here alongside the rest of this
log.*
