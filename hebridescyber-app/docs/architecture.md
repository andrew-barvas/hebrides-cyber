# Architecture

Current, as of the live production system — not an aspirational or MVP
description. Last checked against `master` on 2026-11-20. For the day-to-day technical reference (what to read before
editing which file), see this same folder's `CLAUDE.md` (not the git
root — this repo has two roots; see `docs/README.md`); this doc is the
higher-level picture.

## System diagrams

Diagrams render inline on GitHub. The canonical sources are the Mermaid files in
[`diagrams/`](diagrams/) (`npm run docs:diagrams` exports SVG/PNG to
`diagrams/exports/` for slide decks). Full index: [`diagrams/README.md`](diagrams/README.md).
Every box follows the folder's standing rule — it marks `STUB`/`GAP`/`FINDING`
where that is the truth, per `FUNCTIONALITY-MATRIX.md`.

### C4 — system context

```mermaid
flowchart TB
    classDef person fill:#08427b,stroke:#052e56,color:#fff
    classDef system fill:#1168bd,stroke:#0b4884,color:#fff
    classDef ext fill:#999,stroke:#6b6b6b,color:#fff
    classDef feed fill:#2d6a4f,stroke:#1b4332,color:#fff

    subgraph Users
        U1([SMB / site owner]):::person
        U2([Developer / CI]):::person
        U3([Agency / consultant]):::person
        U4([Operator / admin]):::person
    end
    HC[["Hebrides Cyber<br/>Scanner SaaS + Lookout managed review<br/>(single Next.js surface)"]]:::system
    U1 & U2 & U3 & U4 --> HC
    subgraph Platform_services[Platform services]
        SB[(Supabase<br/>Postgres + Auth + Storage, RLS<br/>Storage bucket cve-index)]:::ext
        AZ[Azure Static Web Apps<br/>+ Blob Storage: report PDFs, host screenshots]:::ext
        GH[GitHub Actions runners<br/>+ GitHub App/PAT]:::ext
        ST[Stripe<br/>Scanner checkout configured, no real purchase tested]:::ext
        RS[Resend<br/>transactional email]:::ext
        GO[Google OAuth - opt, hidden until OT-63]:::ext
    end
    subgraph Intel[Threat-intel & scan feeds - free/keyless]
        F1[OSV.dev / NVD / CISA KEV / FIRST EPSS]:::feed
        F2[crt.sh / Shodan InternetDB / Cloudflare DoH]:::feed
        F3[endoflife.date / Wayback / Safe Browsing opt / HIBP opt]:::feed
    end
    HC --> SB & AZ & GH & ST & RS & GO
    GH -->|executeScan runs here| F1 & F2 & F3
```

### C4 — containers

```mermaid
flowchart TB
    classDef app fill:#1168bd,stroke:#0b4884,color:#fff
    classDef store fill:#2d6a4f,stroke:#1b4332,color:#fff
    classDef worker fill:#6a040f,stroke:#370617,color:#fff
    classDef ext fill:#999,stroke:#6b6b6b,color:#fff
    Browser([Browser]):::ext
    subgraph SWA[Azure Static Web Apps - one deployed surface]
        Pages[App Router pages src/app/*]:::app
        API[API routes managed Functions src/pages/api/*]:::app
        MW[middleware.ts auth gate]:::app
    end
    subgraph Data[Supabase]
        PG[(Postgres + RLS<br/>about 17 MB, 500 MB Free-plan limit)]:::store
        AUTH[Auth: magic link + password + TOTP<br/>Google OAuth hidden until OT-63]:::store
        OBJ[(Storage bucket cve-index<br/>gzipped CPE to CVE index objects)]:::store
    end
    BLOB[(Azure Blob<br/>report PDFs, host screenshots)]:::store
    JOBS[(scan_jobs queue - claim_scan_job SKIP LOCKED)]:::store
    subgraph Workers[GitHub Actions runners - NOT Azure]
        WON[on-demand-scan.yml - passive]:::worker
        WSCHED[scheduled-scans.yml - active tools<br/>work job pinned to ubuntu-24.04]:::worker
        EXE[[executeScan - one implementation]]:::worker
        CRON[scheduled scripts: CVE sync, weekly fix email,<br/>DB size guard, alerts, reports - see WORKFLOWS.md]:::worker
    end
    Browser -->|anon key, RLS| Pages
    Browser --> MW --> Pages --> API
    API -->|service role, bypasses RLS| PG
    API --> AUTH
    API -->|PDF renders, screenshots| BLOB
    API -->|enqueue 202| JOBS
    API -->|dispatch| WON
    JOBS <--> WON & WSCHED
    WON & WSCHED --> EXE -->|service-role writes| PG
    EXE -->|service CVE lookups| OBJ
    EXE -->|host screenshots| BLOB
    CRON --> PG
    CRON -->|nightly index refresh| OBJ
```

The CPE to CVE index lives in object storage, not Postgres, since migration 081
(#268). It was 612 MB of a 629 MB database, over the Supabase Free plan's 500 MB.
`src/lib/objectStore.ts` uses the private Supabase Storage bucket `cve-index` by
default, or Azure Blob when `CVE_INDEX_STORE=azure` (never switched implicitly,
because a new backend starts empty). See "Data flow: the CVE index" below.

For the scan-pipeline component view, see
[`diagrams/c4-component-scanner.mmd`](diagrams/c4-component-scanner.mmd).

## One deployed surface

The entire app — marketing site, client dashboard, and every API route —
is one Next.js app deployed to Azure Static Web Apps. Oryx auto-deploys
`src/pages/api/*` as managed Functions behind the CDN. There is no separate
standalone Azure Functions app; one existed early on, was never actually
deployable, and was fully consolidated into this single surface.

## Data flow: an on-demand scan

1. A user signs up/in via Supabase Auth (magic link, or password for seeded
   and opted-in accounts). "Continue with Google" is built (#273) but only
   shows when the `NEXT_PUBLIC_GOOGLE_SIGNIN` repository variable is `true`,
   which waits on the Supabase Google provider (OT-63).
2. From the dashboard, they submit a target URL. The client calls
   `/api/run-scan` **twice**:
   - First with `{ targetUrl }` — creates a `scans` row (`pending`) and
     returns a proof token.
   - Then with `{ scanId }` — verifies real domain ownership (DNS TXT
     record or file upload; a dev-only token-echo shortcut exists but is
     off by default everywhere), and if verified, **enqueues** a
     `scan_jobs` row and returns `202 { status: "queued" }`.
3. The scan does **not** run inline in that request. A real production
   scan once exceeded Azure Static Web Apps' Free-tier Functions execution
   ceiling and returned a proxy error instead of JSON — every scan-running
   path was moved off synchronous HTTP execution as a result (this applies
   to the daily blog/weekly newsletter generation too, which hit the exact
   same failure independently and was fixed the same way).
4. `src/lib/onDemandScanTrigger.ts` immediately dispatches
   `.github/workflows/on-demand-scan.yml` via the GitHub API, so the job is
   usually picked up within about a minute; if that dispatch fails, the job
   still gets picked up by the next scheduled cron as a fallback.
5. The dashboard polls step 2 again to see `queued` → `running` →
   `completed`/`failed`.

```mermaid
sequenceDiagram
    autonumber
    actor U as User (dashboard)
    participant API as /api/run-scan
    participant DB as Supabase
    participant GH as on-demand-scan.yml
    participant W as Worker (executeScan, passive)
    U->>API: POST { targetUrl }
    API->>DB: free-tier cap? rate limit? SSRF ok? INSERT scans (pending)
    API-->>U: { scanId, proofToken }
    Note over U: add DNS TXT or /.well-known file
    U->>API: POST { scanId }
    API->>API: verify ownership + SSRF re-check
    API->>DB: INSERT scan_jobs (queued)
    API->>GH: dispatch workflow
    API-->>U: 202 { queued }
    GH->>DB: claim_scan_job() SKIP LOCKED
    GH->>W: run (profile forced "safe")
    W->>DB: write scan_results, status=completed, diff + notifiers
    loop poll
        U->>API: POST { scanId }
        API-->>U: queued -> running -> completed
    end
```

Scheduled scans share the same queue but run the full/active tool suite — see
[`diagrams/seq-scheduled-scan.mmd`](diagrams/seq-scheduled-scan.mmd) and the
profile/offensive-gate flow in
[`diagrams/flow-scan-profile-gating.mmd`](diagrams/flow-scan-profile-gating.mmd).

## Data flow: the queue worker (shared by on-demand and scheduled scans)

`src/scripts/run-queued-scan-jobs.ts` claims jobs via a Postgres
`claim_scan_job()` RPC (`SELECT ... FOR UPDATE SKIP LOCKED`) and runs each
one with `src/lib/scanExecution.ts`'s `executeScan()` — the single
implementation every scan-running path shares, so behaviour never drifts
between an on-demand scan and a scheduled one.

- `executeScan()` always runs the **base passive suite**
  (`src/lib/scanners/index.ts`'s `runAllChecks()`) — TLS, headers, DNS,
  exposure, cloud misconfig, fingerprinting, ports, recon, WordPress/
  Joomla/Drupal deep scans, JS library CVEs, SRI, Safe Browsing, Wayback,
  HaveIBeenPwned, WPScan plugin CVE matching.
- Pass `runExtendedTools: true` to also run the **extended active-tool
  suite** — nmap, nuclei (template-scoped to detected technology),
  Subfinder, testssl.sh, plus (with a GitHub repo linked to the scanned
  site) Gitleaks secret scanning, dependency-manifest scanning, Dockerfile
  base-image checks and code scanning, plus (with a saved credential) the
  authenticated header/cookie recheck. Since #248, `src/lib/repoTargets.ts`
  picks only the repository linked to that site (`repo_connections.target_host`,
  www and the bare domain treated as one); an unlinked repository is never
  scanned, and another site's repository is never used.
- Only jobs from `scheduled-scans.yml` get that flag — on-demand jobs stay
  passive-only, distinguished by whether the job's `scan_id` arrived
  pre-set (an on-demand job reuses an existing `scans` row created at step
  2 above; a scheduled job creates its own).

Two GitHub Actions workflows work this same queue:

- `scheduled-scans.yml` — nightly cron, installs the real tool binaries +
  a ZAP daemon fresh each run (no persistent infrastructure), then a
  fixed-size matrix of worker shards drains the queue.
- `on-demand-scan.yml` — a lighter sibling with no tool installs, dispatched
  immediately per on-demand scan rather than waiting for the next cron.

Neither runs on Azure — Azure Static Web Apps' Consumption-plan Functions
have no shell access and can't install binaries at all, which is the whole
reason this queue design exists rather than running tools inline.

## After a scan completes

- Results + score write to `scan_results` via the service-role key.
- A compliance-mapping pass (`src/lib/scanners/compliance.ts`) tags each
  finding against Cyber Essentials/OWASP Top 10/CIS Controls v8 where it
  genuinely applies.
- The New/Fixed diff is computed against the previous scan of the same
  target (by hostname, not exact URL string).
- Outbound webhooks fire (HMAC-signed), a Slack and/or Teams alert posts if
  configured and something changed, and a critical-finding email sends on
  any active plan (not gated to a paid tier the way Slack/Teams are).
- The dashboard reads the result back through the user's own RLS-scoped
  Supabase session — the service-role key never reaches the browser.

## Data flow: the CVE index

Service CVE matching (`serviceCve.ts`, for services nmap identifies) reads a
local CPE to CVE index instead of calling NVD per scan. Since #268 the index is
a set of gzipped objects, not Postgres tables: 1,024 match objects sharded by a
hash of `vendor:product` and 256 record objects sharded by a hash of the CVE id,
about 63 MB in total. `cveIndexObjects.ts` implements the same `CveIndexStore`
and `CveIndexWriter` interfaces the Postgres store did, so matching and findings
did not change. Migration 081 dropped `cve_cpe_matches`, `cve_records`,
`cve_index_state` and `replace_cve_batch`.

```mermaid
flowchart LR
    classDef job fill:#6a040f,stroke:#370617,color:#fff
    classDef store fill:#2d6a4f,stroke:#1b4332,color:#fff
    classDef ext fill:#999,stroke:#6b6b6b,color:#fff
    NVD[NVD CVE API 2.0<br/>NVD_API_KEY optional]:::ext
    SYNC[cve-index-sync.yml<br/>nightly 02:50 UTC<br/>sync-cve-index.ts]:::job
    W[cveIndexObjects.ts writer<br/>buffers, one flush per run]:::job
    STORE{objectStore.ts<br/>CVE_INDEX_STORE}:::job
    SUPA[(Supabase Storage<br/>private bucket cve-index<br/>default)]:::store
    AZB[(Azure Blob container cve-index<br/>only when CVE_INDEX_STORE=azure)]:::store
    SCAN[executeScan<br/>networkExposure / serviceCve.ts]:::job
    IDX[cveIndex.ts lookup<br/>CPE or vendor+product+version]:::job
    NVD --> SYNC --> W --> STORE
    STORE --> SUPA
    STORE -.-> AZB
    SCAN --> IDX --> STORE
    IDX -->|index missing, half-built or over 7 days stale| ERR[status error, never no CVEs]:::ext
```

`cve-index-export.yml` copied the old tables into object storage once, on
2026-11-20, before migration 081 ran; it has no source now and is kept for
reference. `db-size-guard.yml` checks the database size every day (see
[`WORKFLOWS.md`](WORKFLOWS.md)).

## Data flow: a Lookout report

Lookout is the managed exposure review. A Lookout customer's sites are scanned
under the non-intrusive `exposure` profile, set per site (there is no Lookout
plan in code yet; checkout is #199, waiting on owner items). An analyst turns
the results into a report in the admin panel; the customer reads, downloads and
acknowledges it.

```mermaid
sequenceDiagram
    autonumber
    actor A as Analyst (admin panel)
    participant ADM as /api/admin/lookout/reports
    participant DB as Supabase (lookout_reports, lookout_report_items)
    participant SRC as Ranking, drift, lookalikes, HIBP results
    actor C as Customer (/dashboard/lookout)
    participant API as /api/lookout/reports
    participant PDF as /api/lookout/report-pdf (Chromium)
    participant BLOB as Azure Blob (host screenshots)
    A->>ADM: POST { customer: email or user id, period_days }
    ADM->>SRC: estate ranking, drift, lookalikes, breaches for the period
    ADM->>DB: INSERT draft report + prefilled items and summary
    A->>ADM: PATCH items (include, priority, notes, who fixes it), status published
    C->>API: GET list, then GET {id}
    API->>DB: published reports for this customer only
    API-->>C: items, lookalikes, breaches, galleryScanId
    C->>PDF: GET ?id= (rate-limited)
    PDF->>BLOB: up to 12 screenshots from the latest scan by period end
    PDF-->>C: lookout-report-PERIOD-END.pdf
    C->>API: POST {id} { action: acknowledge }
    Note over DB: acknowledged reports are frozen, and admins preview drafts at /api/admin/lookout/report-pdf
```

The breached-accounts section is left out entirely while `HIBP_API_KEY` is
unset (OT-17), and shows "not enabled yet" for a domain not verified with
HIBP. The estate gallery is empty without `AZURE_STORAGE_CONNECTION_STRING`;
the report is complete without it.

## Scheduled work

Every scheduled job is a GitHub Actions workflow running a script directly
against Supabase. The full list, with schedules, secrets and what a failure
means, is in [`WORKFLOWS.md`](WORKFLOWS.md). Added since 2026-11-18:

```mermaid
flowchart LR
    classDef new fill:#e85d04,stroke:#9a3b00,color:#fff
    classDef job fill:#6a040f,stroke:#370617,color:#fff
    classDef store fill:#2d6a4f,stroke:#1b4332,color:#fff
    classDef ext fill:#999,stroke:#6b6b6b,color:#fff
    WFE[weekly-fix-email.yml<br/>Mon 08:00 UTC]:::new
    DSG[db-size-guard.yml<br/>daily 06:15 UTC]:::new
    RLR[repo-link-reminders.yml<br/>manual, dry run by default]:::new
    CVS[cve-index-sync.yml<br/>nightly 02:50 UTC]:::job
    SCH[scheduled-scans.yml<br/>daily 03:00 UTC, work job on ubuntu-24.04]:::job
    PG[(Postgres)]:::store
    OBJ[(Storage bucket cve-index)]:::store
    RS[Resend email]:::ext
    GHA[GitHub failed-run alert]:::ext
    WFE -->|top of estatePriority rank per subscriber| PG
    WFE --> RS
    DSG -->|size and largest tables| PG
    DSG -->|warn from 70% of 500 MB| RS
    DSG -->|fail from 85%| GHA
    RLR -->|unlinked repo_connections, once each| PG
    RLR --> RS
    CVS --> OBJ
    SCH --> PG
```

## Content generation (daily blog + weekly newsletter)

Two independently-scheduled posts, not one replacing the other, sharing
real-event sourcing (`src/lib/newsletter.ts`: CISA's KEV catalog, NVD
high-severity CVEs, established security-news RSS feeds). Both run as
plain scripts (`src/scripts/generate-daily-blog.ts` /
`generate-weekly-newsletter.ts`) executed directly by their GitHub Actions
workflows against Supabase — not API routes. They used to be, and hit the
same Azure Functions execution-ceiling failure the scan pipeline did; fixed
the same way, by removing the HTTP hop entirely.

## Security model

- **RLS everywhere.** Every table holding user data has row-level security
  enabled. The only code path that bypasses it is server-side code using
  the service-role key — never the browser.
- **Credential sensitivity tiers.** A webhook URL (Slack/Teams) is
  client-writable via RLS. A third-party API token (GitHub, Jira, Linear)
  or a session cookie for authenticated scanning is not — those tables ship
  with no client-writable RLS policy at all, and are only ever written by a
  dedicated API route that validates the credential against the real
  service first (where a generic "am I authenticated" signal exists to
  validate against — GitHub, Jira, and Linear all have one; an arbitrary
  customer site being authenticated-scanned does not, so that one credential
  type is saved without a live validation call, documented as a deliberate
  limitation rather than a false assurance).
- **Real ownership verification.** No scan runs against a domain without a
  DNS TXT record or file-upload proof of control — required by default on
  every deployment.
- **SSRF checks** run at scan-creation time and again at execution time
  (a job can sit queued for a while) before any target is actually
  fetched.
- **Secrets never in git.** `.env.example` documents required variable
  names with no real values. See `docs/security.md` for where each secret
  actually belongs (Azure app settings vs. GitHub Actions secrets — note
  that GitHub hard-rejects any Actions secret name starting with `GITHUB_`,
  which is why `GITHUB_PAT`/`GITHUB_APP_ID`/`GITHUB_APP_PRIVATE_KEY` are
  stored there under different names and remapped in each workflow's own
  `env:` block).

## Observability

**Updated 2026-09-04** — E-03/E-04 (`docs/ENHANCEMENTS.md`) shipped, but
read the distinction below carefully before treating this as solved.

- **Error tracking**: `@sentry/nextjs` is wired (`src/instrumentation.ts`,
  `instrumentation-client.ts`, `sentry.server.config.ts`/`sentry.edge.config.ts`,
  `src/app/error.tsx`/`global-error.tsx`) with redaction via
  `src/lib/sentryScrub.ts`. **But it captures nothing yet** — like every
  other optional external service in this app, it initializes into a real
  no-op until `SENTRY_DSN`/`NEXT_PUBLIC_SENTRY_DSN` are actually set,
  which needs a real Sentry account that doesn't exist yet (see the
  Operational Checklist in `../README.md`). The code shipping and the
  capability existing are two different facts — don't conflate them.
- **Health check endpoint**: `GET /api/health` exists now — Supabase,
  Stripe, and `scan_jobs` queue-depth sub-checks, 200/503. This one is
  fully live today, no external account needed.
- **No request correlation IDs** — still genuinely absent. Tracing one
  customer's request across the dashboard → API route → queue worker →
  `executeScan()` still means reading logs and guessing from timestamps
  and target URLs. Not part of E-03/E-04's scope; still open.
- **Practical consequence, updated**: once a Sentry DSN is actually set, a
  failed scan's underlying exception becomes visible for the first time.
  Until then, the original gap still holds exactly as before — no error
  detail column exists on `scans` either, so a failure is still only
  visible as `scans.status = 'failed'` with nothing about why.

## Scaling notes

- The Postgres queue (`scan_jobs`) scales by adding worker shards to the
  GitHub Actions matrix, not by widening a per-target curl matrix — no
  Redis/BullMQ, no long-lived container, nothing Azure's free tier can't
  already run.
- Each worker run is bounded (`MAX_JOBS_PER_RUN`/`TIME_BUDGET_MS`), so a
  backlog rolls over to the next run rather than one Actions job running
  unbounded.
- Nuclei's template set is scoped by detected technology (Sprint 5) rather
  than firing the entire default library at every target — a scaling and
  noise fix, not just a speed one.
- PDF report generation via Playwright is CPU/memory-heavy; if it becomes
  a bottleneck, move it to a dedicated container job rather than running
  it inline in a Function.

## Deployment & CI topology

```mermaid
flowchart TB
    classDef live fill:#2d6a4f,stroke:#1b4332,color:#fff
    classDef ext fill:#1168bd,stroke:#0b4884,color:#fff
    classDef warn fill:#e85d04,stroke:#9a3b00,color:#fff
    USER([Users]) --> CDN[Azure SWA CDN - hebridescyber.co.uk]:::live
    CDN --> NEXT[Managed Next.js server - pages + API Functions<br/>security headers in next.config.mjs]:::live
    NEXT --> SUPA[(Supabase: Postgres, Auth, Storage bucket cve-index)]:::ext
    NEXT --> BLOB[(Azure Blob)]:::ext
    NEXT --> STRIPE[Stripe - Scanner prices set, no real purchase tested, Lookout prices not created - OT-34]:::warn
    subgraph GHA[GitHub Actions - only place scans run]
        DEPLOY[deploy.yml: lint->tsc->unit->e2e->migrate->deploy->health]:::live
        SCANWF[scheduled-scans work job on ubuntu-24.04 + on-demand-scan]:::live
        CONTENT[blog / newsletter / threats / reports / retention / deletion /<br/>weekly fix email / DB size guard / CVE index sync]:::live
    end
    DEPLOY --> CDN
    SCANWF --> SUPA
    CONTENT --> SUPA
    SUPPLY[Supply-chain gap: 'uses:' pinned to mutable tags, not SHAs - FINDING I-4]:::warn
```

Full CI gate detail: [`diagrams/cicd-pipeline.mmd`](diagrams/cicd-pipeline.mmd).
Deployment detail incl. the unapplied Container Apps path:
[`diagrams/deploy-topology.mmd`](diagrams/deploy-topology.mmd). Data model and RLS
tiers: [`DATA-MODEL.md`](DATA-MODEL.md). Auth, MFA and plan-gating:
[`diagrams/flow-auth.mmd`](diagrams/flow-auth.mmd),
[`diagrams/map-plan-gating.mmd`](diagrams/map-plan-gating.mmd).
