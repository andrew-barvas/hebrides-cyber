# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev                  # Start dev server (Next.js 16 + Turbopack, port 3000)
npm run build                # Production build
npm run lint                 # ESLint
npx tsc --noEmit             # TypeScript check — build does NOT run tsc, always run this separately
npm test                     # Playwright e2e (builds app + starts server automatically — slow, hermetic)
npm run test:unit            # Vitest unit/integration tests
npm run test:unit:coverage   # Same, with a coverage report — thresholds in vitest.config.mts are a
                              # calibrated floor, never lowered; raise them when a change adds real coverage
npm run scan:local           # Run a real scan against a URL and persist to Supabase (needs SCAN_OWNER_ID)
npm run seed:users           # Create demo accounts in Supabase (admin, basic/pro/agency/no-plan)
npm run queue:enqueue-scheduled-scans  # Manually run the scheduled-scan enqueue step locally
npm run queue:run-worker               # Manually claim + run one batch of queued scan_jobs locally
npm run newsletter:daily               # Run the daily blog generation script directly (no HTTP hop)
npm run newsletter:weekly              # Run the weekly newsletter generation script directly
npm run threats:check -- --dry-run     # Emerging-threat alerts: print KEV matches without writing/sending
```

## Environment

Copy `.env.example` to `.env.local`. Minimum to boot locally:

```
NEXT_PUBLIC_SUPABASE_URL=https://<project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon-key>
```

Without those, the app boots but all auth/data calls fail. The Supabase client logs a warning and uses a placeholder rather than throwing.

## Architecture

### One API layer

**`src/pages/api/`** — every server-side route, including the scan pipeline (`run-scan`, `verify-ownership`, `generate-report`, `generate-fix-pr`), Stripe webhooks/checkout/portal, admin panel endpoints, and the contact form. Runs as Next.js API routes deployed to Azure Static Web Apps (Oryx auto-deploys them as managed Functions behind the CDN) — there is no separate standalone Azure Functions app. The daily blog and weekly newsletter are **not** API routes — see "Content generation" below for why. There used to be one (`src/functions/`); it was never actually deployable (no `host.json`, no real `@azure/functions` registration) and got fully consolidated here — see `src/pages/api/run-scan.ts`'s header comment and `docs/decisions/ENGINEERING-LOG-2026-08.md`'s "17 Aug" note. All of `src/pages/api/` has access to `NEXT_PUBLIC_*` env vars alongside server-only vars, and uses `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` (server-only) directly for privileged operations — never the anon key.

### Two routers in one Next.js app

- **App Router** (`src/app/`) — all pages and layouts
- **Pages Router** (`src/pages/api/`) — API routes only

### Supabase access pattern

| Context | Client | Key used |
|---------|--------|----------|
| Browser (dashboard, login) | `src/lib/supabaseClient.ts` | anon key — RLS enforced |
| API routes & Functions | `createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)` | service role — bypasses RLS |
| Admin API routes | service role for writes; anon client to verify the caller's JWT | both |

`SUPABASE_SERVICE_ROLE_KEY` must never appear in a `NEXT_PUBLIC_*` var or any client bundle.

### Scan flow (two-step proof of ownership, queue-backed)

1. Dashboard POSTs `{ targetUrl }` to `/api/run-scan` → creates a `scans` row (status `pending`) and returns `{ scanId, proofToken }`. Rejected with 402 if the caller is on the free tier and has already used their one free scan (`src/lib/freeTier.ts`) — admins exempt.
2. Dashboard POSTs `{ scanId }` to `/api/run-scan` → verifies domain ownership (real DNS/file verification, required by default — admins exempt, see `src/lib/ownership.ts`'s `isDomainVerified`), then **enqueues** a `scan_jobs` row and returns `202 { status: "queued" }`. It does not run the scan pipeline inline — a real production scan once exceeded Azure Static Web Apps' Free-tier Functions execution ceiling and returned a proxy error instead of JSON, so nothing calls `executeScan()` synchronously from an HTTP request anymore. `src/lib/onDemandScanTrigger.ts`'s `triggerOnDemandWorkflow()` immediately dispatches `.github/workflows/on-demand-scan.yml` via the GitHub API (needs `GITHUB_PAT`) so the job is usually picked up within about a minute; if that dispatch fails or the token isn't set, the job still gets picked up by the next `scheduled-scans.yml` cron as a fallback. The dashboard polls step 2 again to see `queued` → `running` → `completed`/`failed`. Replaying step 2 against an already-`completed` scan returns the cached result instead of re-queuing.

`POST /api/v1/scans` (the public API) enqueues the same way and also returns `202` immediately — `action/index.js` (the packaged GitHub Action) and `docs/API.md` both poll `GET /api/v1/scans/{id}` rather than expecting a synchronous report.

`executeScan()` (`src/lib/scanExecution.ts`) is the single implementation that actually runs a scan, called only by the queue workers (`src/scripts/run-queued-scan-jobs.ts`) — never directly from a request handler. It always runs the base passive check suite; the active-tool suite runs according to `ExecuteScanOptions.profile` (`src/lib/scanProfiles.ts`; `"safe"` runs none of it) plus per-scan `toolOverrides`, merged by `resolveToolConfig()`. `decideScanConfig()` in `run-queued-scan-jobs.ts` picks the profile: a job's own `scan_profile`, else `"safe"` for on-demand jobs (those arrive with `scan_jobs.scan_id` pre-set, from `run-scan.ts`/`v1/scans.ts`), else the scan bundle, else the target's profile, defaulting to `"full"` — so in practice only scheduled jobs run active tools.

`ALLOW_DEV_TOKEN_VERIFICATION` defaults to unset/`false` (real DNS/file verification required). Set it `true` only for local dev, to use the `X-Scan-Token` echo shortcut instead.

### Scheduled + on-demand queue (Postgres, no Redis)

Both scan-triggering paths share one Postgres-backed queue (`sql/migrations/008_scan_jobs.sql`) worked by ephemeral GitHub Actions runners — deliberately not BullMQ/Redis (an earlier `src/worker/` attempt along those lines was built, never wired to a real Redis instance, and later deleted once this replaced it).

- **Scheduled**: `.github/workflows/scheduled-scans.yml` cron → `src/scripts/enqueue-scheduled-scans.ts` inserts one `scan_jobs` row per verified target that's due (see "Scan cadence by plan" below), then a matrix of worker shards (`src/scripts/run-queued-scan-jobs.ts`) claim jobs via the `claim_scan_job()` RPC (`SELECT ... FOR UPDATE SKIP LOCKED` — needed because PostgREST can't express locking clauses) and run them under the target's profile (default `"full"`). This is the only place the real active-scanning tools run — the workflow installs nmap/sqlmap/nuclei/xsser/commix/testssl.sh/gitleaks and starts a ZAP daemon fresh each time.
- **On-demand**: `.github/workflows/on-demand-scan.yml`, a lighter sibling that skips those tool installs, dispatched immediately by `triggerOnDemandWorkflow()` (see above). Jobs it picks up run passive-only.

### Scan cadence by plan

`src/lib/scanCadence.ts`'s `isScanDue(plan, lastCompletedScanAt, now)` — Basic gets weekly, Pro/Agency get daily (matching the once-a-day `scheduled-scans.yml` cron; there's no faster-than-daily tier without a second cron). Pure/sync so it's unit-testable without touching Supabase — `enqueue-scheduled-scans.ts` does the DB lookup and passes the result in.

### Scanner pipeline

`src/lib/scanners/` — two tiers, not one flat list. Writing or extending a
check must follow `docs/SCANNER-CONVENTIONS.md`'s five rules (evidence
discipline, `checkId`, `AbortSignal.timeout()`, etc.) — six existing modules
reference that file directly. For which checks are plan-gated, credential-
dependent, or tested, see `docs/FUNCTIONALITY-MATRIX.md` rather than this
section, which covers what each check does, not how it's gated.

**Base passive suite** — always runs, on every scan regardless of plan or repo connection. Wired into `runAllChecks()`/`summariseResults()` in `src/lib/scanners/index.ts`:
- `tls.ts` — certificate grade and expiry, and why a browser would refuse the certificate (expired, self-signed, wrong hostname, incomplete chain, untrusted). It handshakes with `rejectUnauthorized: false` and reads Node's `authorizationError`: with the default, every broken certificate failed the handshake and became a generic error, never a finding. `readCertificate()` is the shared reader
- `subdomainCerts.ts` — certificate expiry on up to 20 of recon.ts's CT-log subdomains (most recently certified first), one finding per certificate. If the CT lookup failed (`recon.ctLookupFailed`), this and `takeover.ts` report `error`, never an empty "checked" — crt.sh is often down, and an empty list would mark every subdomain finding fixed
- `headers.ts` — security header presence, CSP grading, cookie flags, CORS, info disclosure
- `dns.ts` — SPF, DMARC, DKIM (best-effort selector guessing), MTA-STS (DNS record + live policy-file fetch), TLS-RPT, CAA, DNSSEC. MTA-STS/TLS-RPT only get evaluated when the domain has MX records — silent otherwise, not a false "missing"
- `exposure.ts` — sensitive paths (.env, .git, phpinfo, etc.), security.txt presence
- `directoryListing.ts` — autoindex detection, reuses `httpProbe.ts`'s baseline/masking
- `cloudMisconfig.ts` — public S3/Azure Blob/GCS buckets, but only ones the target's own page source references
- `fingerprint.ts` — technology detection (WordPress etc.)
- `ports.ts` — common open ports via Shodan InternetDB
- `recon.ts` — IP resolution, Shodan CVEs, crt.sh subdomain enumeration
- `webapp.ts` — robots.txt, HTTP OPTIONS, error disclosure, WordPress/Joomla/Drupal deep scan, CORS reflected-origin, JS library versions (CVE-enriched via `osv.ts`), Subresource Integrity on cross-origin `<script>`/`<link rel=stylesheet>` tags (same-origin resources are never flagged — SRI protects against a compromised third party, not the site's own origin)
- `safeBrowsing.ts` — Google Safe Browsing malware/phishing check (needs `GOOGLE_SAFE_BROWSING_API_KEY`; `not_configured` without it)
- `waybackDiscovery.ts` — checks historical URLs from the Wayback Machine CDX API that still resolve live, surfacing forgotten endpoints a fresh crawl can't find
- `hibp.ts` — HaveIBeenPwned domain breach check (needs `HIBP_API_KEY`; `not_configured` without it)
- `wpvdb.ts` — matches `webapp.ts`-detected WordPress plugin versions against the real WPScan Vulnerability Database (needs `WPSCAN_API_TOKEN`; `not_configured` without it). Runs after `webapp` resolves, not in the main `Promise.all` batch, since it needs `webapp.wordpress.plugins` as input — enrichment only, does no detection of its own.
- `takeover.ts` — dangling DNS / subdomain takeover over the site and recon.ts's CT-log subdomains (runs after recon resolves). Reports only with two pieces of evidence: a CNAME to a provider in `TAKEOVER_PROVIDERS` *and* that provider's proof the resource is gone (NXDOMAIN on the CNAME target, or its own "unclaimed" page). Resolver timeouts/SERVFAIL are "unknown", never NXDOMAIN. Detection only.
- `endOfLife.ts` — end-of-life software the site reveals (PHP/nginx/Apache from headers, Drupal/Joomla from webapp.ts probes, Angular/jQuery/Bootstrap), against endoflife.date release-line dates. Runs after webapp resolves. Also holds the endoflife.date client `dockerBaseImage.ts` uses. A version is matched to a cycle only exactly; a distro hint in the header (`fingerprint.ts`'s `packagedBy`) downgrades the finding, since distributions backport fixes; any failed lookup is an `error`, never "nothing is EOL". Where it reaches a verdict, its `eol.unsupported:<product>` finding replaces `fingerprint.risky-library` for that technology. WordPress is excluded on purpose (see the file header).
- `domainRegistration.ts` — registered-domain expiry and (gTLDs only) transfer lock, from the registry's RDAP record via IANA's bootstrap file. `registrableDomain.ts` holds the small multi-label-suffix list both of these use; a wrong guess just finds no RDAP record.
- `playwright.ts` — headless browser checks (needs Playwright's browser binaries: both scan workflows install Chromium, cached, after `npm ci`, which doesn't download browsers — before that step every production run of this check errored; a bare local `tsx` run of this without `npx playwright install` will show `status: "error"`, not a real bug)
- `zap.ts` (inline in `index.ts`, not its own file) — kicks off an async ZAP spider if `ZAP_API_URL` is set; the real active ZAP *scan* is a separate module below

**Extended active-tool suite** — opt-in only, via `runExtendedTools()` in `src/lib/scanExecution.ts`, gated per tool by the scan's profile (`src/lib/scanProfiles.ts` `ExtendedToolName`/`EXTENDED_TOOL_NAMES`) — in practice scheduled jobs only, see "Scan flow" above. Real binaries/daemons that only exist in that GitHub Actions job:
- `src/worker/tools/{nuclei,zap,sqlmap,nmap,xsser,commix}.ts` — real active scans, ported out of the deleted BullMQ worker (xsser/commix are newer additions, scoped from a review of eccouncil.org's pentest tool list — see their own file headers for a CONFIDENCE NOTE: both were written without a real binary available to verify against, unlike the others). `nuclei.ts` is scoped by `-tags` (Sprint 5) rather than firing nuclei's entire default template set — a fixed baseline (`cve`/`exposure`/`misconfig`/`default-login`/`takeover`) plus tags mapped from whatever `fingerprint.ts` detected (`TECH_TAG_MAP`), fed in from `scanExecution.ts`'s `results.fingerprint`. An unmapped or wrong tag just contributes nothing to nuclei's OR-match — never an error, never a reason to fall back to the unscoped scan
- `subdomains.ts` — Subfinder subdomain discovery (supersedes `recon.ts`'s lighter crt.sh-only finding when it finds anything)
- `deepTls.ts` — testssl.sh
- `secretScan.ts`, `dependencyManifest.ts`, `dockerBaseImage.ts`, `trivyScan.ts` — all four require a connected GitHub repo (`repo_connections` table, `sql/migrations/009_repo_connections.sql`, set via `src/pages/api/account/connect-repo.ts`); each returns a clean `not_applicable`/`not_configured` result with no repo rather than an error. `secretScan.ts` runs Gitleaks against repo contents; `dependencyManifest.ts` (E-67) lists the repo root once, then per ecosystem prefers a lockfile — package-lock.json/npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock (v1 and berry), poetry.lock, Pipfile.lock, composer.lock, go.sum (+go.mod), gradle.lockfile, Gemfile.lock, Cargo.lock, packages.lock.json — giving exact versions of every package, transitive ones included, with direct/transitive, dev scope and an "introduced via a > b > c" chain where the format records a graph. The parsers are pure functions of file contents in `dependencyLockfiles.ts` (`parseLockfile(name, content, companionManifest)`, `LOCKFILES`; minimal YAML/TOML readers in `lockfileSyntax.ts`, no dependency) so a pull-request check can reuse them. With no readable lockfile it falls back to the old manifest-range check (`package.json`, `requirements.txt`, `composer.json`, `go.mod`, `pom.xml`: lowest version a range allows — findings say so and stay `medium`). Up to 2000 packages per repo go to OSV.dev in one `POST /v1/querybatch` (≤1000 per request, per-query `next_page_token` followed), then `GET /v1/vulns/{id}` for CVE aliases, severity (GHSA rating, else CVSS v3 band) and fixed versions (`osv.ts`; SEMVER *and* ECOSYSTEM ranges via `ecosystemVersion.ts`). A failed batch makes the result `error` — never "no vulnerabilities". checkIds stay `dependency-manifest.<slug>:<name>` (slugs npm/pip/composer/go/maven/ruby/cargo/nuget), one finding per package name across its vulnerable versions. The result carries `inventory` (every package, scope, graph as indices, advisories), which `sbomExport.ts` turns into the CycloneDX SBOM served by `GET /api/v1/scans/{id}/sbom`; scans stored before the inventory existed fall back to the old finding-based SBOM; `dockerBaseImage.ts` extracts a `Dockerfile`'s base image tag and checks it against real end-of-life dates (endoflife.date), not OSV.dev — real installed-package CVE matching needs the actual dpkg/apk manifest a tag name alone doesn't give you, which is what `trivyScan.ts` (E-34) exists to fill: it resolves the same Dockerfile's final-stage base image (reusing `dockerBaseImage.ts`'s own `parseDockerfileStages`/`resolveBaseImages`) and runs a real `trivy image` scan against it, plus a separate `trivy config` scan (shallow clone, no image involved) for Terraform/Kubernetes/Dockerfile misconfigurations — the only IaC scanning in the whole suite.
- `authenticatedCheck.ts` (Sprint 3, "authenticated scanning, first slice") — requires a saved credential in `target_auth_credentials` (`sql/migrations/014_target_auth_credentials.sql`, one row per `monitored_targets` row, set via `src/pages/api/account/target-auth.ts` — no live-validation call, since unlike GitHub/Jira/Linear there's no generic "am I authenticated" signal for an arbitrary customer site). Re-runs `headers.ts`'s `buildHeaderAnalysis` (exported specifically so this doesn't duplicate it) against a request carrying the credential — not a crawl behind login, not IDOR testing. `checkId`s are prefixed `auth-check.*`, distinct from the identical-looking unauthenticated `headers.*` findings, since they describe a genuinely different response.

When adding a new check to either tier: export its result type from the module, add it to `ScanResults` (base) or the `extended` object (extended tier), and push `Finding` entries with a stable `checkId` (`"<module>.<check-name>"`, or `"<module>.<check-name>:<key>"` in a loop) — `src/lib/findingsDiff.ts` matches on this to tell "new" from "unchanged" between two scans of the same target, so an untagged finding never participates in diffing.

Import the base pipeline as `@/lib/scanners` (the directory). A single-file `src/lib/scanners.ts` used to sit alongside it and **shadowed the directory in module resolution**, so every entry point silently ran an old 4-check version. It has been deleted — do not recreate a file at that path.

**Remediation text** lives in `src/lib/scanners/remediationText.ts` and is attached to each finding as `Finding.remediation` at the point the finding is created, where the check result is still in scope. The field is optional because scans stored before it existed deserialise without it, so any consumer must guard. Never re-derive which fix applies by string-matching a finding's title.

**Threat intelligence** (`src/lib/scanners/threatIntel.ts`) is another final pass, run by `executeScan()` right after CVSS enrichment: every CVE-backed finding gets `threatIntel` — CISA KEV membership (and ransomware use) plus the highest FIRST EPSS score across its CVEs. Both sources are free and keyless; the KEV feed is cached per worker process. It never changes `severity` (that's the finding's evidence); the report sorts known-exploited and higher-EPSS findings first *within* a severity and shows badges. Absent `threatIntel` means unknown, never "not exploited" — `knownExploited: false` is only written when the KEV feed was actually read.

**Compliance mapping** (`src/lib/scanners/compliance.ts`) is different from remediation text: applied as a *final pass* over the whole `findings` array (in `summariseResults()` for the base suite, and again in `scanExecution.ts` for extended-tool findings appended afterward), not set at any individual push site. `getComplianceRefs(checkId)` matches on the checkId's base (the part before its first `:`) against a hand-curated, deliberately non-exhaustive table mapping to Cyber Essentials, OWASP Top 10, and CIS Controls v8 — a checkId with no entry gets no refs, meaning "not yet categorised" or "genuinely doesn't fit," never a forced mapping. When adding a new check that has a genuine compliance angle, add its base checkId to `COMPLIANCE_MAP` rather than leaving it uncategorised by default. `ComplianceSummary` in `ScanReportView.tsx` renders the Cyber-Essentials-specific breakdown on the scan report — worded as an "automated indicator," never a certification claim.

**False positives.** `exposure.ts` fetches a random-slug URL alongside the site root to learn what a "not found" response looks like, masks the probed path out of both bodies, and discards any probe whose body matches that baseline. Without this, every SPA that returns its shell for unknown paths reports an exposed `.env`. Any new check that probes for a file must reuse `fetchBaseline`/`normaliseBody` (`httpProbe.ts`) rather than trusting a 200 status.

### Real remediation PRs vs AI-tailored fixes vs static remediation text

Four distinct, non-overlapping "help me fix this" features — don't conflate them:
- `remediationText.ts` — static markdown, attached to every finding unconditionally (see above).
- `src/lib/aiRemediation.ts` / `POST /api/scans/[id]/ai-fix` — on-demand, per-finding, sends the finding + detected tech stack to Azure OpenAI for a stack-specific fix (only live if `AZURE_OPENAI_*` is configured).
- `POST /api/generate-fix-pr` — opens a real GitHub pull request. Auth resolves via `src/lib/githubApp.ts`'s `resolveGithubAuth(githubRepo)` (see below); for dependency findings it bumps the actual version in `package.json` (via `osv.ts`'s `lookupOsvFixInfo`), not just a recommendations file.
- `POST /api/scans/[id]/create-ticket` — opens a real Jira, Linear, ServiceNow or GitHub issue from one finding, via `buildProviderClient()` in `src/lib/ticketLinks.ts` (clients in `ticketIntegrations.ts` and `ticketProviders.ts`). Reuses the finding's own detail/remediation text as the ticket body rather than generating new prose — the point of this feature is "send existing guidance to where my team tracks work," not a fifth kind of write-up. Requires a saved `ticket_integrations` row (`sql/migrations/013_ticket_integrations.sql`, one per owner+provider, written only by `src/pages/api/account/ticket-integration.ts` after a real validate call against Jira/Linear's own API — same "verify before saving" precedent as `connect-repo.ts`). The "Create ticket" button in `ScanReportView.tsx`'s `FindingCard` only renders when the caller has already confirmed an integration exists (`hasTicketIntegration` prop) — it never has to know which provider is behind it.

### Ticket lifecycle: dedupe and auto-close

`sql/migrations/016_ticket_links.sql`'s `ticket_links` is the finding→issue ledger, keyed `(owner, provider, target_host, check_id)`. It exists because nothing previously recorded which finding produced which issue — `createJiraIssue()` read the issue key only to build a URL and discarded it, so clicking "Create ticket" twice opened two identical issues.

- **Dedupe** — `decideTicketAction(link, issueState)` in `src/lib/ticketLinks.ts` is a *pure* function holding the whole decision table, so every branch is unit-testable without a mocked Jira. It matches on `checkId` (the same stable identity `findingsDiff.ts` uses) rather than issue title, and on `target_host` rather than raw `target_url` (same normalisation as `scanReport.ts`'s `findPreviousFindings`) — so the ledger agrees with the new/fixed diff by construction. It always re-checks the tracker before reusing a row, since an issue deleted in Jira must not suppress ticketing for a live finding. Its `"blocked"` outcome is load-bearing: an unreachable tracker is not evidence of anything, so it creates nothing *and* suppresses nothing, and retries next scan.
- **Auto-close** — `src/lib/ticketAutoClose.ts`, called from `executeScan()`'s Phase 2 alongside the other notification hooks (same never-throw contract). Consumes `ScanReport.fixed_findings`, which `findingsDiff.ts` already computes — it does not form a second opinion about what counts as fixed. **Opt-in via `ticket_integrations.auto_close_enabled`, default false**: transitioning an issue in someone else's tracker is a visible action in a system this app doesn't own, and an account that connected Jira before this existed must never find its board moving on its own.
- Jira has no "set status" API — `transitionJiraIssueToDone()` lists the issue's *currently available* transitions and picks one whose target `statusCategory.key === "done"`, rather than string-matching a name like "Done" which breaks on any customised workflow. Linear's `WorkflowState.type` vocabulary is fixed workspace-wide, so its equivalent needs no such care.
- Close happens *before* the comment, deliberately: a workflow with no available done-transition would otherwise collect an identical "verified as fixed" comment on every nightly scan forever, since nothing records that we already said it.

### Finding lifecycle and remediation SLAs

`src/lib/findingLifecycle.ts` keeps `finding_lifecycle` (`043_finding_lifecycle_sla.sql`): one row per (owner, target host, checkId) with first seen, last seen and resolved. `executeScan()` syncs it after every completed scan (Phase 1.75, never throws, no-op before 043). Identity is checkId, same as `findingsDiff.ts`.

**A scan can only resolve what it could have detected.** On-demand scans are passive-only, so a passive scan's silence about a nuclei/sqlmap finding is not a fix. Each row records its `source`: `"base"`, the normalised `extended` key of the tool that produced it (from the checkId namespace, `"deep-tls.x"` → `deeptls`), or `"extended"` if unmatched. A scan resolves a row only if that source completed in it (`isCovered`). If you add an extended tool whose checkId namespace doesn't normalise to its `extended` key, add it to `TOOL_ALIASES`. A finding that reappears within 7 days of resolving reopens with its original `first_seen_at`, so a flapping check can't reset its clock. A site's first sync backfills first-seen from up to 45 earlier scans under the same coverage rule.

`slaMonitoring.ts` is the pure maths on top (policy, due dates, due-soon/breached, time-to-fix); `slaAlerts.ts` emails the owner once per finding per stage (`sla_warned_at`, `sla_breach_notified_at`), only marking what was actually delivered. Agency plan, admins exempt (`hasSlaAccess`). Per-account targets live in `sla_policies`, written only by `PUT /api/account/sla`.

Note the same passive-vs-active gap still affects `findingsDiff.ts`'s `fixed_findings`, and therefore ticket auto-close: an on-demand scan after a scheduled full scan reports the active-tool findings as fixed.

### Emerging-threat alerts

`.github/workflows/emerging-threats.yml` (every 6 hours) runs `npm run threats:check` (`src/scripts/check-emerging-threats.ts`, `--dry-run` writes and sends nothing). It takes CVEs CISA added to KEV in the last 3 days (`threatIntel.ts`'s cached `loadKev`), reads their affected versions from NVD's CVE API configurations and, for npm libraries, OSV.dev's GHSA ranges (OSV wins for npm-mapped libraries whenever it has npm data — NVD misfiles some, e.g. Angular CVEs under AngularJS), and compares them with each paid owner's (and admin's) latest completed scan per host from the last 30 days. Matching is pure (`src/lib/emergingThreats.ts`); I/O, the ledger and sending are in `emergingThreatAlerts.ts`. What a scan saw comes from `scanners/techInventory.ts`'s `collectTechInventory`, shared with `endOfLife.ts`; technology → CPE is `softwareCveDb.ts`'s `NVD_CPE_BY_NAME` (add entries only after checking a real NVD record).

Evidence tiers: `affected` = detected version inside a range; `possibly_affected` = product seen but version unknown or partial, distro-packaged (`packagedBy`), or in range only under an NVD AND-configuration we can't see (e.g. PHP-on-Windows). Never a name-only match. A failed KEV/NVD/OSV lookup is an error (KEV → exit 1; NVD/OSV → that CVE skipped, exit 1), never "not affected"; a CVE NVD hasn't analysed yet is "pending". Ledger: `emerging_threat_alerts` (`045_emerging_threat_alerts.sql`, unique owner+host+CVE, owner-read, service-role write). Only rows matched in the current run are sent, `notified_at` is stamped after at least one channel delivered, and a stamped row is never re-sent. Email for every paid plan; Slack/Teams (`sendSlackThreatAlert`/`sendTeamsThreatAlert`, which throw on failure) for Pro/Agency, admins exempt. Read by `GET /api/emerging-threats` and `EmergingThreatsPanel` on `/dashboard`; both no-op before 045.

### GitHub access for customer repos

`src/lib/githubApp.ts`'s `resolveGithubAuth(githubRepo)` is the one function every customer-repo-touching module calls (`generate-fix-pr.ts`, `secretScan.ts`, `dependencyManifest.ts`, `dockerBaseImage.ts`, `connect-repo.ts`) — never read `process.env.GITHUB_PAT` directly in a new one. It tries a GitHub App installation token first (per-repo, expires in an hour, resolved live via `GET /repos/{owner}/{repo}/installation` — no webhook or install-callback flow needed), falling back to the shared `GITHUB_PAT` when the App isn't configured or isn't installed on that repo. `GITHUB_PAT` is also used, unrelated to any of this, by `src/lib/onDemandScanTrigger.ts` to dispatch this repo's own `on-demand-scan.yml` — don't conflate the two concerns when reasoning about that token's scope.

### Content generation: daily blog + weekly newsletter

Two genuinely separate, independently-scheduled posts — not one replacing the other — sharing real-event sourcing in `src/lib/newsletter.ts`:
- **Daily** (`generateDailyBlogPost`, run by `src/scripts/generate-daily-blog.ts`, `.github/workflows/daily-blog.yml` at 07:00 UTC every day) — narrower lookback (KEV 7d / NVD 1d / news 2d), slug `cyber-brief-YYYY-MM-DD`.
- **Weekly** (`generateWeeklyNewsletterPost`, run by `src/scripts/generate-weekly-newsletter.ts`, `.github/workflows/weekly-newsletter.yml` at 07:00 UTC every Monday) — full 7-day window on everything, fuller own-scan-stats section, slug `week-of-YYYY-MM-DD`.

Both real-event sources, no fabrication: CISA's Known Exploited Vulnerabilities catalog (`fetchRecentKevEntries`), high-severity CVEs from the NVD API (`fetchRecentHighSeverityCves`, CVSS ≥ 7.0, no key needed at this volume), and a curated set of security-news RSS feeds parsed with hand-rolled regex extraction, not a dependency (`fetchRecentSecurityNews` — The Hacker News, BleepingComputer, Krebs on Security), de-duplicated by normalised title across feeds. AI narrative write-up if `AZURE_OPENAI_*` is configured, otherwise a deterministic templated post from the same fetched data — either path always publishes something rather than silently skipping a day/week.

**Not API routes.** Both used to be `POST /api/generate-daily-blog` / `POST /api/generate-newsletter`, curled from their workflows with a shared service token — the same "GitHub Actions → Next.js API route on Azure" pattern the scan pipeline used before it hit Azure Static Web Apps' Free-tier Functions execution ceiling. A real run of `daily-blog.yml` hit the identical failure (`"Backend call failure"` after 46s — see `src/scripts/generate-daily-blog.ts`'s header), so both were converted the same way `run-scan.ts` was: the workflow runs the script directly against Supabase (`SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY`, same credentials pattern as `run-queued-scan-jobs.ts`), no HTTP hop through Azure at all. The two API routes and their service token are fully deleted — not kept as a fallback, and not read by any code today (its old name lingered as a stale doc reference until this pass). The monthly digest (`src/lib/monthlyDigest.ts`, run by `src/scripts/send-monthly-digest.ts`) used to be the one exception — deliberately kept as an HTTP route gated by `DIGEST_SERVICE_TOKEN` since it sends real customer email — until `docs/ENHANCEMENTS.md` E-11 found the identical N+1-query execution-ceiling risk there too. Converted the same way; `DIGEST_SERVICE_TOKEN` and the route it gated are both deleted. All three scheduled content/email jobs now follow the exact same pattern with no remaining exception.

Deliberately not a Supabase Edge Function either: this app has exactly one pattern for scheduled work now (GitHub Actions running a script directly against Supabase — matches `scheduled-scans.yml`), and a second execution environment with its own secrets to keep in sync is a cost already paid once (the deleted standalone Azure Functions app) and not worth reintroducing.

### Audit log

`src/lib/audit.ts`'s `logAuditEvent(supabaseAdmin, event)` is the one shared writer for the `audit_logs` table, called from `scanExecution.ts` (`scan.started`/`scan.completed`/`scan.failed`) and the Stripe webhook (which also (ab)uses the same table as an idempotency ledger for Stripe event ids). Best-effort by design — logging a security event must never be the reason the action it describes fails, so every call site `await`s it but never lets its result gate anything. `action` values follow a stable `"<resource>.<verb>"` vocabulary since the admin Audit tab's search filters on it — keep new call sites consistent with existing ones rather than inventing new verb shapes.

### Vertical landing pages

`src/app/{tourism,churches,local-trades}/page.tsx` — SEO/positioning content, not scanner or pricing logic. Reuses the same components and CSS tokens as the rest of the marketing site; no new abstractions were introduced for these.

### Theme system

Tailwind `darkMode: 'class'`. `ThemeScript` in `src/app/layout.tsx` adds `dark` to `<html>` on load unless `localStorage.getItem('hc-theme') === 'light'`. Default is dark (cyber theme).

**The cyber tokens are CSS variables, not fixed hex.** `tailwind.config.cjs` maps them to `rgb(var(--c-*) / <alpha-value>)`, and the `:root` / `.dark` blocks in `src/app/globals.css` hold the two palettes. This is what makes light mode work: any surface built from these tokens re-themes automatically, with no `dark:` variant on any of the ~700 usages.

| Token | Role | Light | Dark |
|-------|------|-------|------|
| `cyberbg` | page background | `#F6F7F9` | `#070B14` |
| `cyberpanel` | card/panel background | `#FFFFFF` | `#0D1524` |
| `cyberborder` | borders on panels | `#D6DCE4` | `#1C2940` |
| `cybertext` | primary body text | `#2F3A44` | `#FFFFFF` |
| `neon` | accent, links, glow | `#067A5B` | `#39FFC0` |

Rules when adding UI:

- **Never use `text-white` on a themed surface** — it cannot follow the theme and turns invisible in light mode. Use `text-cybertext`. `text-white` is correct only on a permanently dark background such as `bg-atlantic`.
- Same for `bg-white/N` and `border-white/N` overlays — use `bg-cybertext/N`.
- Fixed brand colours (`atlantic`, `seafoam`, `heather`, `slatedark`, `slatelight`) do not change between themes. Pair them with an explicit text colour rather than letting text inherit.
- Low-opacity steps of `cybertext` and `neon` get an alpha boost in light mode (the parity block in `globals.css`). Alpha tuned for white-on-black reads far too faint as dark-on-light — `/40` would otherwise sit at ~2.1:1 contrast.
- `shadow-glow` / `shadow-glowsm` vary by theme too; the neon bloom is dialled right down in light mode.

Three more per-theme tokens meet WCAG AA without the parity overrides above — prefer them over alpha steps in new code: `cybermuted` (secondary text), `danger`, `warning`. The shadcn/ui names (`bg-primary`, `text-muted-foreground`, `border-input`, …) are aliases onto the same variables so CLI-generated components render on-brand; don't use them in hand-written code.

### UI primitives

New UI is composed from `src/components/ui/` — the shadcn/ui pattern, hand-written against the cyber tokens (lowercase filenames there, matching shadcn). `components.json` is configured so `npx shadcn@2 add <component>` works for Radix-backed pieces (dialog, dropdown, tooltip); **never run `shadcn init`**, it overwrites `globals.css` and `tailwind.config.cjs`. Current set: `button` (primary/secondary/ghost/danger; `asChild` to style a `<Link>`; defaults to `type="button"`), `card` (+`CardTitle`, the `// section` overline with the `//` hidden from screen readers), `input`/`label` (every input gets a label, `sr-only` if visually redundant), `alert` (danger → `role="alert"`, else `role="status"`), `stat-card`, `segmented-control` (`aria-pressed`), `page-header`, `empty-state`, `skeleton`. Use `cn()` (`src/lib/utils.ts`) so callers can override classes. Don't hand-roll another panel/button/input — the older feature components still do, and migrate incrementally.

### App shell

`src/components/app-shell/AppShell.tsx`, mounted by `src/app/dashboard/layout.tsx` and `src/app/account/layout.tsx`: sidebar (lg+) or scrolling section tabs, plus one session + subscription load exposed through `useAppSession()`. Use its `plan` for feature gating (the stored plan only while `status === "active"`, else `"none"`) and `billingPlan` for billing display. It also runs the MFA (AAL2) step-up redirect for every route it wraps — `middleware.ts` only checks authentication. Pages inside it render content only: no `min-h-screen`/`bg-grid` wrapper, no "← Dashboard" button.

| Route | Holds |
|---|---|
| `/dashboard` | Overview — KPIs, trends, latest findings, onboarding checklist |
| `/dashboard/scans` | `RunScanForm` + paginated scan list |
| `/dashboard/scans/history` | Trends (per-site score/category history) |
| `/dashboard/assets` | domain verification, monitored sites, discovered inventory |
| `/dashboard/sla` | remediation SLAs — open-finding deadlines, time-to-fix, targets (Agency) |
| `/dashboard/integrations` | every external connection; plan-gated ones render `LockedFeature` rather than disappearing |
| `/account` | profile, billing, branding, team, 2FA, audit requests, deletion |

Nav items and active-state matching live in `AppNav.tsx` (`NAV_ITEMS`, `activeNavHref` — longest segment-prefix wins).

### Database schema

Key tables (all in `sql/migrations/`):
- `users` — profile data keyed to `auth.users`; `is_admin` grants admin panel access
- `subscriptions` — plan, status, slack_webhook_url, ms_teams_webhook_url (`src/lib/msTeams.ts` — independent of Slack, either/both/neither), brand_logo_url/brand_name (white-label, Agency-gated in app code not schema); kept in sync by Stripe webhooks
- `ticket_integrations` — one row per owner+provider: trackers (`jira`/`linear`/`servicenow`/`github`) **and** on-call rows (`pagerduty`/`opsgenie`, 028) share this table, so a ticketing read must filter on `TICKET_PROVIDERS` — use `findTicketIntegration()` (ticketLinks.ts) rather than querying it directly; no client-writable RLS policy, only `src/pages/api/account/ticket-integration.ts` writes a row, and only after validating the credentials against the real API (`013_ticket_integrations.sql`). `auto_close_enabled` (`016_ticket_links.sql`) opts into auto-close, default false. Because the table is unique on `(owner, provider)`, an owner can have **two** rows — every read must `.order("created_at", { ascending: false }).limit(1)` before `.maybeSingle()`, which would otherwise throw on exactly those accounts
- `ticket_links` — finding→issue ledger for dedupe and auto-close (`016_ticket_links.sql`); owner-readable, service-role-write-only (a forgeable row could suppress ticketing for a real finding)
- `emerging_threat_alerts` — newly-exploited-CVE matches per (owner, host, CVE) and when each was notified (`045_emerging_threat_alerts.sql`); owner-readable, service-role-write-only — see "Emerging-threat alerts"
- `finding_lifecycle` + `sla_policies` — per-site first-seen/resolved per checkId, and per-account SLA targets (`043_finding_lifecycle_sla.sql`); owner-readable, service-role-write-only — see "Finding lifecycle and remediation SLAs"
- `api_keys` — hashed keys; `allowed_cidrs` (042) is the per-key IP allowlist enforced in `apiAuth.ts`
- `scans` + `scan_results` — scan records and findings/score; RLS-protected by owner
- `scan_jobs` — the on-demand + scheduled queue (`008_scan_jobs.sql`); `claim_scan_job()` RPC does the `SKIP LOCKED` claim
- `repo_connections` — GitHub repos per user (unique on owner + repo; the most recently connected one is scanned until targets map to repos), gates `secretScan.ts`/`dependencyManifest.ts`/`dockerBaseImage.ts` (`009_repo_connections.sql`)
- `monitored_targets` — agency-tier sites for nightly scheduled scans
- `contact_enquiries` — contact form submissions; service-role only (no browser RLS policy)
- `verifications` — domain ownership tokens
- `blog_posts` — both the daily blog and weekly newsletter live here, differentiated only by slug prefix (`cyber-brief-` vs `week-of-`); a row needs both `status = 'published'` and `published_at` non-null to be publicly visible
- `audit_logs` — see "Audit log" below

RLS is enabled on all tables. The only code path that bypasses it is server-side code using the service role key.

### Rate limiting

`src/lib/rateLimit.ts` uses Upstash Redis (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`) for shared-state rate limiting across Function instances. Falls back to an in-memory `Map` in dev — not safe across instances; don't rely on it in production.

**Client IP: always `getClientIp(req)`, never a header directly.** Azure Static Web Apps *appends* to a client-supplied `X-Forwarded-For` (`<forged…>, <client>:<port>, <edge>:<port>`, measured in production), so the leftmost entry is attacker-controlled, and `X-Client-IP`/`X-Azure-ClientIP`/`X-Real-IP` are the edge's address or client pass-through. `getClientIp` takes the entry `TRUSTED_PROXY_HOPS` (default 2) from the right and strips the port. It feeds both per-IP rate limits and API-key IP allowlists (`apiAuth.ts`), so a forgeable value would be an auth bypass, not just a rate-limit one. `GET /api/client-ip` returns what it resolves — probe it with a forged `X-Forwarded-For` after any hosting change.

### Payments

Stripe webhooks at `src/pages/api/stripe/webhook.ts` update `subscriptions` on `checkout.session.completed`, `invoice.payment_failed`, and `customer.subscription.deleted`. Requires `STRIPE_WEBHOOK_SECRET` and the three `STRIPE_PRICE_*` env vars (see `.env.example`).

### Testing strategy

Four independent gates, all run by `deploy.yml` in this exact order before every deploy — reproduce locally with the matching command from "Commands" above rather than inventing a different check:

1. **Lint** (`npm run lint`) — ESLint, zero-tolerance for errors; pre-existing `react-hooks/set-state-in-effect` warnings on a handful of components are known and not a regression signal.
2. **Type check** (`npx tsc --noEmit`) — `next build` does **not** run this itself, so a type error can pass a build and still be wrong; always run it separately.
3. **Unit/integration tests** (`npm run test:unit`, or `:coverage` for the report) — Vitest, colocated as `*.test.ts`/`*.test.tsx` next to the module they cover (e.g. `src/lib/scanCadence.test.ts`), except API-route tests under `src/__tests__/api/` (Next.js's Pages Router would otherwise treat a colocated test file under `src/pages/api/` as a route and break `npm run build`). Favour pure, dependency-free functions where the logic allows it — `scanCadence.ts`'s `isScanDue()` and `ticketLinks.ts`'s `decideTicketAction()` are the model to follow, unit-testable without a mocked Supabase/Jira. Coverage thresholds in `vitest.config.mts` are a calibrated **floor** (18–19%, matching this 25k+ LOC codebase's first real test-writing pass), not a target — CI fails on any regression below it; raise the numbers to match (never exceed) whatever a PR's `test:unit:coverage` run actually reports, never lower them.
4. **E2E** (`npm test`) — Playwright, builds the app and starts its own server automatically (slow, hermetic — no separate dev server or real Supabase project needed for the unauthenticated flows covered, see `tests/e2e/`). `playwright.config.ts` hardcodes `NEXT_PUBLIC_SUPABASE_URL=https://example-project.supabase.co` for every run — tests seed `localStorage` with `sb-example-project-auth-token` and mock `*.example-project.supabase.co` network requests. Never use real Supabase credentials in e2e tests; the hardcoded project ref must stay `example-project`.

When adding a new scanner check or API route: a unit test belongs alongside it per the pattern above; there's no requirement to add e2e coverage for server-only logic the Playwright suite doesn't already touch.

### Deployment

Azure Static Web Apps hybrid mode (not pure static export) is the default, live path. Every route (App Router pages, `pages/api/*`) is served by the managed Next.js server (Oryx-provisioned Functions), which bypasses `staticwebapp.config.json`'s `globalHeaders` entirely — confirmed by curling production and finding CSP/X-Frame-Options/etc. absent even on a 404, with only platform-level HSTS coming through. **Security headers are set in `next.config.mjs`'s own `headers()`**, which runs inside the Next.js response path and is what actually applies in production; `staticwebapp.config.json`'s `globalHeaders` is kept in sync as a fallback for any file served as a pure static asset without hitting the Next server, but is not load-bearing. Keep both files in sync if the header policy changes. `next.config.mjs` also sets `poweredByHeader: false`.

**Alternate path: Azure Container Apps** (`Dockerfile`, `.github/workflows/deploy-containerapp.yml`, the `azurerm_container_registry`/`azurerm_container_app*` resources in `azure/terraform/main.tf`) — exists to get off SWA's Free-tier Functions execution ceiling (the same ceiling that already forced the queue-worker architecture above) without adopting a second cloud. Deliberately parallel, not a migration: `deploy.yml` still owns the live push-to-master deploy; `deploy-containerapp.yml` is `workflow_dispatch`-only. `next.config.mjs`'s `output: 'standalone'` only activates when the Dockerfile's build stage sets `NEXT_OUTPUT_MODE=standalone` — Oryx's SWA build never sets that var, so its build output is untouched by this path's existence. Not yet applied anywhere; see that Terraform block's own comments for the TODOs (globally-unique names, secret values) before a real `terraform apply`.
