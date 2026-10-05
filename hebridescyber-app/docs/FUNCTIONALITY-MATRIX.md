# Functionality matrix

The single source of truth for **what exists, how it's triggered, and how
it's actually gated** — as opposed to how it's described on the pricing page
or in marketing copy. Built by reading the code, not the docs; where this
disagrees with another doc, this file is right and the other one needs
fixing (file an issue/PR against it, or check `docs/ROADMAP.md` — a known
mismatch may already be tracked there as an `E-nn`).

This file owns *what exists and how it's gated*. It does not own *what a
feature is for or how a customer uses it* (`docs/USER-GUIDE.md`), or *how
the code implements it* (`CLAUDE.md`). Link to a row here rather than
re-describing it elsewhere.

**Two-root repo layout**, relevant to the "code path" columns below: the app
lives in `hebridescyber-app/`; `marketing/`, `action/`, and the primary
`.github/workflows/` (including `deploy.yml` and `scheduled-scans.yml`) live
one level up, at the git root. Paths below are relative to
`hebridescyber-app/` unless prefixed `../`.

**Enforcement column legend:**
- ✅ **server** — enforced in an API route or RLS policy; a client can't bypass it
- ⚠️ **client-only** — a UI element is hidden/shown by plan, but the underlying API has no check
- ❌ **none** — no plan check exists at any layer; available to any authenticated account regardless of tier
- 🔒 **service-role-only** — not plan-gated because it's not customer-writable at all (admin/service paths)

*As of 2026-09-14.*

---

## 1. Pricing tiers (context for every gate below)

| Tier | Price | Advertised (`src/app/pricing/page.tsx`) |
|---|---|---|
| Free | £0 | 1 scan, ever |
| Basic | £20/mo | "Weekly automated scans, monthly Security Score email, critical alerts" |
| Pro | £35/mo | "Daily automated scans, plus everything in Basic — dependency monitoring, Slack alerts" (marked "Most popular") |
| Agency | £75/mo | "Daily automated scans across multi-site monitoring, white-label PDF reports, priority support" |
| One-off audits | £300 / £800 / £1,800 | Small Website / Standard Web App / Full SaaS — manual, routes to `/contact`, no self-serve path |

---

## 2. Base passive scanner suite

Runs via `runAllChecks()` (`src/lib/scanners/index.ts`) on **every** scan
regardless of plan, including the one free scan. Extraction/normalisation
rules for all of these live in `docs/SCANNER-CONVENTIONS.md`.

| Module | What it checks | External credential | Unconfigured behaviour | Plan gate | Tests |
|---|---|---|---|---|---|
| `tls.ts` | Protocol/cipher strength, cert expiry/age, self-signed, SANs, HSTS | none | n/a | none — every scan | ✅ `tls.test.ts` |
| `headers.ts` | OWASP Secure Headers, CSP parsing, cookie flags, CORS wildcard, info disclosure | none | n/a | none | ✅ `headers.test.ts` |
| `dns.ts` | SPF, DKIM, DMARC, MTA-STS, TLS-RPT, CAA, DNSSEC signal, IPv6, MX | none | n/a | none | ✅ `dns.test.ts` |
| `exposure.ts` | Sensitive paths (`.git/HEAD`, `.env`, backups, debug pages), `security.txt` | none | n/a | none | partial |
| `directoryListing.ts` | Autoindex on ~20 common paths | none | n/a | none | no |
| `cloudMisconfig.ts` | Public S3/Azure Blob/GCS buckets referenced by the target's own page | none | n/a | none | no |
| `fingerprint.ts` | Passive tech detection (40+), risky-software flags | none | n/a | none | no |
| `ports.ts` | ~30 security-relevant TCP ports, pure `node:net` | none | n/a | none | no |
| `playwright.ts` | Load errors, mixed content, console errors, redirect chain | Chromium binary | `status: "error"` if not installed | none | no |
| `recon.ts` | Shodan InternetDB (CVEs/ports/tags), crt.sh subdomains | none (free/keyless) | n/a | none | no |
| `webapp.ts` | robots.txt, dangerous methods, error disclosure, WP/Joomla/Drupal deep scan, CORS reflected-origin, vulnerable JS libs, missing SRI | none | n/a | none | no |
| `osv.ts` | CVE enrichment for JS libs via OSV.dev | none (free/keyless) | n/a | none | no |
| `safeBrowsing.ts` | Google Safe Browsing (malware/phishing) | `GOOGLE_SAFE_BROWSING_API_KEY` | `not_configured`, no findings | none | no |
| `waybackDiscovery.ts` | Historical still-live endpoints via CDX | none (free/keyless) | n/a | none | no |
| `hibp.ts` | HaveIBeenPwned domain breach search | `HIBP_API_KEY` (paid) | `not_configured`; even with a key, most domains show `not_verified` (HIBP's own separate verification) | none | no |
| `wpvdb.ts` | WordPress plugin CVE matching via WPScan VDB | `WPSCAN_API_TOKEN` (free 25 req/day) | `not_configured`; the plain "plugin detected" finding still fires | none | no |
| `takeover.ts` | Dangling DNS / subdomain takeover: CNAMEs from the site and its CT-log subdomains (≤60) to 15 provider patterns (Azure ×5, Elastic Beanstalk, S3, GitHub Pages, Bitbucket, Pantheon, Surge, Heroku, Shopify, Fastly, Tumblr), reported only with NXDOMAIN or the provider's own unclaimed page | none | n/a; `not_applicable` for a bare IP | none | ✅ `takeover.test.ts` |
| `domainRegistration.ts` | Registered-domain expiry (≤30 days / expired) and gTLD transfer lock, from the registry's RDAP record | none (IANA bootstrap + registry RDAP, keyless) | `not_applicable` when the TLD has no RDAP or the registry has no record; `error` if unreachable — never a finding | none | ✅ `domainRegistration.test.ts` |
| `subdomainCerts.ts` | Certificate expiry (expired / within 21 days) on up to 20 CT-log subdomains, most recently certified first; one finding per certificate; the site's own cert skipped | none | `not_applicable` with no other hostnames; `error` when crt.sh failed or no host answered on 443 — never "all fine" | none | ✅ `subdomainCerts.test.ts` |
| `endOfLife.ts` | End-of-life software: PHP/nginx/Apache (headers), Drupal/Joomla (webapp probes), Angular/jQuery/Bootstrap, against endoflife.date release-line dates; heads-up 90 days out; distro-packaged versions downgraded to "confirm with vendor". WordPress/IIS/Ghost deliberately excluded | none (endoflife.date, keyless) | `not_applicable` when nothing versioned is detected; `error` if any lookup fails — never "nothing is EOL" | none | ✅ `endOfLife.test.ts` |
| `scriptInventory.ts` | Third-party script inventory (PCI DSS 6.4.3 / 11.6.1): external script origins from the HTML and the headless browser's runtime capture, ≤50 origins, ≤5 sample URLs each, integrity all/some/none/unknown; one `script-inventory.unreviewed:<origin>` finding per origin (medium on pages with payment signals) until accepted with a justification; report table on the owner's scan page | none (Chromium for runtime capture) | `partial` (HTML only, can't resolve findings) when the browser fails; `error` when neither source loads — never an empty list | none | ✅ `scriptInventory.test.ts`, `playwright.test.ts`, `ScanReportView.scriptInventory.test.tsx` |
| `crawler.ts` + `crawlFindings.ts` | Site crawler (E-70): breadth-first, same site only (www/apex one site), read-only GETs, ≤50 pages / depth 3 / 4 concurrent / 45 s, honours robots.txt (`*` group), seeds from links, sitemap.xml and live Wayback URLs; never follows logout/delete/cart-action links, never submits forms; per-page headers, cookie flags, mixed content, SRI, forms over HTTP, error disclosure on 404/5xx pages, third-party scripts merged into the script inventory. Findings: `crawl.header-gap:<header>` (sent by the home page, missing on inner pages — one finding listing pages), `crawl.cookie-flags:<name>`, `crawl.missing-sri`, and `crawl.mixed-content:<path>` / `crawl.insecure-form:<path>` / `crawl.error-disclosure:<path>` (≤10 pages each). Start page is left to the existing checks so nothing is scored twice | none | `error` if the start page is unreachable or returns ≥400 (e.g. a firewall); `partial` on page cap, time budget, 429/503, many failed requests or unreadable robots.txt — `findingLifecycle.ts` never resolves crawl findings on those | none | ✅ `crawler.test.ts` |
| `threatIntel.ts` (final pass) | CISA KEV membership (+ ransomware use) and FIRST EPSS for every CVE-backed finding; report badges and within-severity ordering, `threat_intel` in the API, CSV columns | none (both free/keyless) | fields omitted — never shown as "not exploited" | none | ✅ `threatIntel.test.ts` |
| ZAP spider (`checkZap` in `index.ts`) | Kicks off an async spider only | `ZAP_API_URL` | `not_configured` | none | no |
| `compliance.ts` | Maps `checkId` → Cyber Essentials / OWASP Top 10 / CIS Controls v8 | none | n/a (deliberately non-exhaustive) | none | ✅ `compliance.test.ts` |
| `remediationText.ts` | Static fix prose attached per finding | none | n/a | none | ✅ `remediationText.test.ts` |

Scoring: `scoreFromFindings()` — 100 minus `{critical:30, high:15, medium:7,
low:2, info:0}`, floored at 0. Summary: Azure OpenAI if configured, else a
deterministic templated fallback (no plan gate either way).

---

## 3. Extended active-tool suite

Gated by `ExecuteScanOptions.runExtendedTools`, set **only** in
`src/scripts/run-queued-scan-jobs.ts` (`const runExtendedTools = !scanId`) —
i.e. **scheduled monitored-target jobs only**. On-demand dashboard scans and
`POST /api/v1/scans` never trigger this, regardless of plan.

| Module | What it checks | Requirement | Unconfigured behaviour | Gate | Tests |
|---|---|---|---|---|---|
| `src/worker/tools/nmap.ts` | SYN scan, top-1000 ports, service/OS detect | `nmap` binary | `not_configured` on ENOENT | ⚠️ path-gated, not plan-gated | no |
| `src/worker/tools/nuclei.ts` | Templates scoped to detected tech + baseline tags | `nuclei` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/zap.ts` | Full spider + active scan | `ZAP_API_URL` + `ZAP_API_KEY` (E-14 fixed: no default, returns `not_configured` if either is unset) | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/sqlmap.ts` | SQL injection confirmation | `sqlmap` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/xsser.ts` | XSS confirmation | `xsser` binary. **Written without a verified reference run against a real binary** | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/commix.ts` | OS command injection confirmation | `commix` binary. **Same unverified caveat as xsser** | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/subdomains.ts` | Subfinder passive enumeration, takeover candidates | `subfinder` binary | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/deepTls.ts` | testssl.sh: protocol/cipher/FS/named-CVE suite | `TESTSSL_PATH` or on PATH | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/secretScan.ts` | Gitleaks over a connected repo | connected repo + GitHub access + `git` | `not_configured`/`not_applicable` | 🔒 requires repo connection (ungated by plan) | no |
| `src/lib/scanners/dependencyManifest.ts` (+ `dependencyLockfiles.ts`) | Lockfiles (npm/pnpm/Yarn, Poetry/Pipfile, Composer, go.sum, Gradle, Bundler, Cargo, NuGet) → every package incl. transitive, exact versions → OSV.dev querybatch + advisory details; manifest-range fallback (npm/pip/Composer/Go/Maven); full inventory → CycloneDX SBOM (E-67) | connected repo + GitHub access | `not_configured`/`not_applicable`; `error` when OSV.dev or GitHub can't be read | 🔒 requires repo connection (ungated by plan) | yes — every lockfile parser on fixtures (`dependencyLockfiles.test.ts`), scan flow with stubbed GitHub/OSV incl. fallback and error paths (`dependencyManifest.test.ts`), querybatch/pagination/ECOSYSTEM fix versions (`osv.test.ts`), SBOM (`sbomExport.test.ts`, `src/__tests__/api/v1/scans/[id]/sbom.test.ts`), legacy manifest parsers (`src/__tests__/scanners/dependencyManifest.test.ts`). Not yet run against live OSV.dev from this branch |
| `src/lib/scanners/dockerBaseImage.ts` | Dockerfile base-image EOL via endoflife.date | connected repo + GitHub access | `not_configured`/`not_applicable` | 🔒 requires repo connection (ungated by plan) | no |
| `src/lib/scanners/authenticatedCheck.ts` | Header/cookie recheck against an authenticated request | saved credential on a monitored target | `not_applicable` | ❌ **no plan check** despite being labelled "Optional (Agency)" on `/what-we-check` | no |
| `src/worker/tools/wpscan.ts` | WPScan WordPress enumeration | `wpscan` binary + `WPSCAN_API_TOKEN` | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/cmsmap.ts` | CMSmap CMS fingerprint/scan | `cmsmap` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/gospider.ts` | Web spidering/link extraction | `gospider` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/photon.ts` | Data extraction/OSINT | `photon` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/metadataLeak.ts` | Document metadata OSINT | none (HTTP-based) | n/a | ⚠️ path-gated | no |
| `src/worker/tools/ajaxSpider.ts` | ZAP AJAX spider for JS-heavy SPAs | `ZAP_API_URL` | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/whatwaf.ts` | WAF/IDS detection | `whatwaf` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/kiterunner.ts` | API endpoint brute-force discovery | `kiterunner` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/arjun.ts` | Hidden parameter discovery | `arjun` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/sessionCheck.ts` | Session management analysis | none (HTTP-based) | n/a | ⚠️ path-gated | no |
| `src/lib/scanners/trivyScan.ts` | Base-image CVEs + IaC misconfig | connected repo + `trivy` binary | `not_configured`/`not_applicable` | 🔒 requires repo connection | yes (parsers) |
| `src/worker/tools/sast.ts` | Static code analysis (Opengrep engine, own rule pack in `sast-rules/`, JS/TS + Python + PHP) | connected repo + `opengrep` binary + `sast-rules/` | `not_configured`/`not_applicable` | 🔒 requires repo connection (full + osint profiles) | yes (parser on captured output, all status paths; rule tests in `sast-rules.yml`) |

`DANGEROUS_TOOL_PORTS` in `scanExecution.ts` escalates nmap hits on
2375/2376/6379/9200/27017/2379 to critical unconditionally.

---

## 4. API routes

Auth models: **session** (`authenticateApiRequest()`, `caller.via === "session"`
required) · **key-or-session** (either credential) · **admin**
(`requireAdmin()`) · **service-token** (`X-Service-Token`) · **public**.

### Scanning

| Route | Methods | Auth | Trigger | Plan gate | Enforcement |
|---|---|---|---|---|---|
| `run-scan.ts` | POST | session only | on-demand, two-step | free-tier cap (1 scan ever); 10/hr rate limit | ✅ server (`isFreeTierExhausted`, `checkRateLimit`) |
| `verify-ownership.ts` | POST | session only | manual | none | ✅ server — 10/hr rate limit (E-12, fixed); no plan gate |
| `generate-report.ts` | GET | key-or-session | manual | branding applied only on `plan === "agency"`; 10/hr rate limit (E-12) | ✅ server for branding and rate limit |
| `generate-fix-pr.ts` | POST | session only | manual, **no UI caller exists** | none | ✅ server — 10/hr rate limit (E-12, fixed); no plan gate |
| `scans/[id]/ai-fix.ts` | POST | key-or-session | manual, per-finding | none | ✅ server — 10/hr rate limit (E-12, fixed); no plan gate, Azure OpenAI spend still uncapped per-request within that limit |
| `scans/[id]/create-ticket.ts` | POST | key-or-session | manual, per-finding | none | ✅ server — 10/hr rate limit (E-12, fixed); no plan gate |
| `scans/[id]/retest-finding.ts` | POST | key-or-session | manual, per-finding | none | ✅ server — 10/hr rate limit, plus a correctness gate: 400s any finding from an extended scan tool (`src/lib/extendedToolCheckIds.ts`) since the on-demand path this triggers never runs them (E-30) |
| `scans/[id]/shares.ts` | GET/POST/DELETE | session only | manual | max 10/scan, max 365-day expiry (hardcoded, not plan-varied) | ✅ server (caps), ❌ not plan-differentiated |
| `scans/[id]/replay.ts` | POST | key-or-session | manual | none | ✅ server — 10/hr rate limit; resolves scan profile from `monitored_targets`, defaults to `safe` |

### Account / settings

| Route | Auth | Plan gate | Enforcement |
|---|---|---|---|
| `keys.ts` | session only | max 20 keys | ❌ no plan gate — not advertised as tier-specific anywhere; not gated by this pass, needs an explicit product decision if that's meant to change (`docs/ENHANCEMENTS.md` E-02) |
| `webhooks.ts` | session only | max 20 | ✅ **intentional, not a gap** — `docs/USER-GUIDE.md` §3.5 explicitly documents outbound webhooks as "for anyone building their own integration," unlike Slack/Teams alerts (Pro/Agency) on the same page |
| `account/connect-repo.ts` | session only | Pro/Agency (POST only) | ✅ **server** (E-02, fixed) — `subscription?.plan` must be `"pro"`/`"agency"`; DELETE stays available regardless of plan |
| `account/ticket-integration.ts` | session only | — | ❌ no plan gate — not advertised as tier-specific anywhere; not gated by this pass, needs an explicit product decision |
| `account/target-auth.ts` | session only | Agency (POST only) | ✅ **server** (E-02, fixed) — `subscription?.plan !== "agency"` → 403; DELETE stays available regardless of plan |
| `account/branding-logo.ts` | session only | Agency | ✅ **server** — `subscription?.plan !== "agency"` → 403 |
| `team.ts` / `team/members.ts` | session only | max 25 members; Agency (create/invite only) | ✅ **server** (E-02, fixed) — `team.ts`'s `createTeam` and `team/members.ts`'s `invite` both check `plan === "agency"` (the latter checks the team *owner's* plan, not the caller's, since an admin-role member could invite on an owner's behalf); role changes/removal/viewing stay available regardless of plan |

### Billing

| Route | Auth | Notes |
|---|---|---|
| `stripe/create-checkout-session.ts` | Bearer session JWT | **500s until `STRIPE_PRICE_BASIC/PRO/AGENCY` are set** — currently blocks the entire paid-signup funnel |
| `stripe/customer-portal.ts` | Bearer session JWT | 404 if no `stripe_customer_id` |
| `stripe/webhook.ts` | Stripe signature | Plan defaults to `"basic"` on missing metadata — a metadata-less event silently *downgrades* an Agency customer |

### Admin (all `requireAdmin`, 403 otherwise) 🔒

`admin/overview.ts`, `customers.ts`, `scans.ts`, `queue.ts`, `metrics.ts`,
`audit.ts`, `contacts.ts`, `blog.ts`, `blog/[slug].ts`,
`blog/upload-image.ts`. All now call the shared `requireAdmin()` —
`overview.ts`/`contacts.ts` previously hand-rolled their own check, fixed
(`docs/ENHANCEMENTS.md` E-08, 2026-08-28).

### Public / unauthenticated

| Route | Notes |
|---|---|
| `badge/[scanId].ts` | Public SVG badge, service-role read, exposes only the score. Never 500s — renders a "no data" badge on failure |
| `reports/[token].ts` | Token *is* the credential; expiry-checked, audit-logged |
| `contact.ts` | Rate-limited by IP (10/hour, own `"contact"` namespace — `docs/ENHANCEMENTS.md` E-05, fixed). No CAPTCHA/honeypot beyond that, judged sufficient for current volume |
| `health.ts` | Supabase/Stripe/queue-depth sub-checks, 200/503, booleans and counts only — never a raw error message. Fixed (`docs/ENHANCEMENTS.md` E-04, 2026-09-04) |

### Service-token (cron)

No entries — the last one (`send-monthly-digest.ts`) is no longer an HTTP
route (`docs/ENHANCEMENTS.md` E-11, 2026-09-05: converted to a bare script,
`src/scripts/send-monthly-digest.ts`, run directly against Supabase by
`.github/workflows/monthly-digest.yml` — same pattern as the daily blog/
weekly newsletter, see CLAUDE.md's "Content generation" section — to fix
the same N+1-query execution-ceiling risk).

### Public REST v1 (`/api/v1/`)

Full endpoint reference: `docs/API.md`. Summary here for gating purposes
only — none of these are plan-gated beyond the same free-tier scan cap and
rate limit as `run-scan.ts`.

| Endpoint | Method | Notes |
|---|---|---|
| `v1/scans` | POST | Queues a scan, 202. Same free-tier + rate-limit + SSRF + ownership checks as `run-scan.ts` |
| `v1/scans` | GET | Lists caller's scans |
| `v1/scans/{id}` | GET | Full report incl. New/Fixed diff |
| `v1/scans/{id}/export` | GET | CSV/JSON export |
| `v1/targets/{host}/trend` | GET | Score history |

Packaged GitHub Action: `../action/` (outside `hebridescyber-app/`) —
`action.yml` + `index.js`, dependency-free, polls `GET /api/v1/scans/{id}`,
fails the build only on newly-introduced findings.

---

## 5. Dashboard / account capabilities

| Capability | Component | Plan gate | Enforcement |
|---|---|---|---|
| First-run onboarding checklist | `OnboardingChecklist.tsx`, rendered on the dashboard for any authenticated account | — (useful pre-subscription too) | n/a — not a gated capability. Fixed (`docs/ENHANCEMENTS.md` E-16, 2026-08-28) |
| Multi-target fleet overview | `FleetOverview.tsx`, rendered on the dashboard for any account with 2+ monitored targets | — (same access as monitored targets themselves — Basic 1/Pro 3/Agency 15, so in practice mostly a Pro/Agency-visible view) | n/a — not separately gated, just naturally needs 2+ targets to have anything to show. Fixed (`docs/ENHANCEMENTS.md` E-27, 2026-09-04) |
| Findings-by-category / compliance-coverage trend | `ComplianceTrend.tsx`, rendered on the dashboard alongside `ScoreTrend` | — | n/a — not a gated capability. Fixed (`docs/ENHANCEMENTS.md` E-28, 2026-09-04) |
| Per-plan monitored-site cap | `MonitoredTargets.tsx`, rendered for any active plan in `dashboard/page.tsx` | Basic 1 / Pro 3 / Agency 15 (defaults pending explicit product confirmation — not researched numbers, see `sql/migrations/018_monitored_targets_plan_cap.sql`'s own comment) | ✅ **server** — `monitored_targets_cap()` + the table's INSERT policy (migration 018) reject an over-cap insert regardless of client; UI reads the same function via RPC so the displayed count can't drift from what's enforced |
| **Scheduled scanning for Basic/Pro** | scan cadence enforced in `scanCadence.ts`/`enqueue-scheduled-scans.ts`, keyed off `monitored_targets` rows | Basic weekly, Pro/Agency daily (advertised) | ✅ **UI gap closed** (was the single largest gap between advertised and actual capability, `docs/ROADMAP.md` POC-1) — cadence logic was already correct, the fix was exposing the "add a target" UI to Basic/Pro and adding the cap enforcement above. **Not yet verified against a live staging environment** — POC-1's own verify step (`npm run queue:enqueue-scheduled-scans` with a clock override, assert a `scans` row) hasn't been run since this landed |
| Slack alerts | dashboard form | Pro/Agency | ✅ **server** — `scanExecution.ts`: `if (sub.plan !== "pro" && sub.plan !== "agency") return;` |
| MS Teams alerts | dashboard form | Pro/Agency | ✅ **server**, same function |
| Critical-finding email alert | `scanAlerts.ts` | Any active plan, incl. Basic | ✅ server, deliberately not tier-gated |
| Monthly digest email | `send-monthly-digest.ts` | Any active plan | ✅ server, not tier-gated (advertised as a Basic bullet, but not a differentiator since every tier gets it) |
| Emerging-threat alerts (new CISA KEV CVEs vs each site's latest scan, every 6 h) | `emergingThreats.ts` (pure matching), `emergingThreatAlerts.ts`, `check-emerging-threats.ts` + `emerging-threats.yml`, `GET /api/emerging-threats`, `EmergingThreatsPanel.tsx` on `/dashboard` | Email: any active paid plan; Slack/Teams: Pro/Agency; admins exempt | ✅ server (owner selection + `channelsFor`). NVD configurations + OSV npm ranges; `affected` only for a detected version in range, else `possibly_affected`, never name-only. Needs migration 045 — no-op before it. Tests: `emergingThreats.test.ts`, `emergingThreatAlerts.test.ts`, `techInventory.test.ts`, `threatAlertChannels.test.ts`, `__tests__/api/emerging-threats.test.ts`, `EmergingThreatsPanel.test.tsx` |
| Authenticated scanning | `MonitoredTargets.tsx` + `target-auth.ts` | "Optional (Agency)" per `/what-we-check` | ✅ server — `target-auth.ts` enforces `plan !== "agency"` → 403 on POST (E-02 fix, 2026-08-28); DELETE stays ungated so downgraded accounts can remove a credential |
| Partner Portal (fleet management) | `PartnerPortalPanel.tsx`, rendered on the dashboard | Agency | ⚠️ **client-only** — `{plan === "agency" && ...}` in `dashboard/page.tsx`; component shows only the caller's own RLS-scoped data, so exposure is informational not exploitable (E-39) |
| Asset inventory | `AssetInventory.tsx`, `/dashboard/assets` | — | n/a — not a gated capability; populated by `syncAssetInventory()` post-scan (E-40) |
| Critical path analysis | `CriticalPaths` in scan detail page | — | n/a — not a gated capability (E-41) |
| Multi-framework compliance tabs | `ScanReportView.tsx` framework-tabbed `ComplianceSummary` | — | n/a — not a gated capability (E-41) |
| Fix Wizard | `FixWizard.tsx`, `/dashboard/scans/[id]?wizard=1` | — | n/a — not a gated capability (E-42) |
| Scan diff view | `DiffView.tsx`, `/dashboard/scans/[id]/diff` | — | n/a — not a gated capability (E-43) |
| Score/category history | `/dashboard/scans/history`, `CategorySparklines.tsx` | — | n/a — not a gated capability (E-43) |
| Scan replay | `ReplayButton` in scan detail page | — | n/a — not a gated capability; rate-limited (E-44) |
| Scan profile selector | `ScanProfileConfig` in `MonitoredTargets.tsx` | — (per-target) | n/a — requires monitored-targets access (plan-capped); requires migration 026 for UPDATE RLS (E-46) |
| Extended team roles (developer, auditor) | `TeamSection.tsx`, `team/members.ts` | Agency (team creation) | ✅ server for team creation; roles themselves are ungated once in a team (E-45) |
| Two-factor auth (TOTP) | `TwoFactor.tsx`, `auth.ts` MFA functions | — | ❌ no plan gate (not advertised either — see §7) |
| API keys / webhooks / share links / CSV-JSON export / CI Action | `ApiKeys.tsx`, `Webhooks.tsx`, `ShareLinks.tsx` | — | ❌ **no plan gate at all** — available on free tier |
| Repo connection (dependency/secret/Docker scanning) | `ConnectRepo.tsx` | Pro ("dependency monitoring", advertised) | ❌ **none** — connection itself is ungated; consumption is path-gated (see §3), not plan-gated |
| Jira/Linear ticketing + auto-close | `TicketIntegration.tsx` | — | ❌ no plan gate |
| ServiceNow ticketing | `src/lib/ticketProviders.ts` | — | ❌ no plan gate — same contract as Jira/Linear |
| GitHub Issues ticketing | `src/lib/ticketProviders.ts` | — | ❌ no plan gate — same contract as Jira/Linear |
| Teams/collaboration (invite, roles) | `TeamSection.tsx` | Agency, per `docs/USER-GUIDE.md` §3.7 | ❌ **none** — also not on the pricing page at all |
| White-label branding (upload) | `BrandingSection.tsx` | Agency | ✅ server (see API table above) |
| White-label applied to PDF | `generate-report.ts` | Agency | ✅ server |
| "Priority support" | — | Agency (advertised) | — no code representation; no SLA field, no routing |

---

## 5b. Enterprise features (Sprints 9–13)

Shipped 2026-09-12 – 2026-09-14. All implemented as pure library modules
with comprehensive test coverage. None are plan-gated — they're available
to any authenticated account. API route wiring is deferred until production
readiness (Sprint 15+); the library layer is complete and tested.

### Identity & Access

| Module | What it does | Code path | Tests |
|---|---|---|---|
| SSO/SAML | SAML 2.0 assertion parsing, IdP metadata validation, SP metadata generation | `src/lib/ssoSaml.ts` | ✅ `ssoSaml.test.ts` (10 tests) |
| RBAC | Role hierarchy (viewer→editor→admin→owner), permission checks, role assignment validation | `src/lib/rbac.ts` | ✅ `rbac.test.ts` (9 tests) |
| SCIM 2.0 provisioning | User resource parsing/serialization, list responses, bearer token validation | `src/lib/scimProvisioning.ts` | ✅ `scimProvisioning.test.ts` (10 tests) |
| IP allowlisting | **Live, per API key** (IPv4 + IPv6). Enforced in `apiAuth.ts`; a refused key gets the same 401 as an unknown one, and the refusal is recorded on the key. Set via `PATCH /api/keys` and the dashboard's API keys panel. Needs migration 042; until then keys stay unrestricted and saving returns 503 | `src/lib/ipAllowlist.ts`, `src/lib/apiAuth.ts`, `src/pages/api/keys.ts`, `src/components/ApiKeys.tsx` | ✅ `ipAllowlist.test.ts`, `apiAuth.test.ts`, `__tests__/api/keys.test.ts`, `ApiKeys.test.tsx` |

### Organization & Multi-tenancy

| Module | What it does | Code path | Tests |
|---|---|---|---|
| Org/workspace model | Organization CRUD, membership management, workspace isolation | `src/lib/orgModel.ts` | ✅ `orgModel.test.ts` (8 tests) |
| MSP portal | Per-client health scoring (healthy/warning/critical), cross-org dashboard aggregation | `src/lib/mspPortal.ts` | ✅ `mspPortal.test.ts` (4 tests) |
| Custom scan policies | Policy validation, check enable/disable, finding exclusion, pass/fail evaluation | `src/lib/customScanPolicies.ts` | ✅ `customScanPolicies.test.ts` (9 tests) |

### Reporting & Compliance

| Module | What it does | Code path | Tests |
|---|---|---|---|
| Scheduled reports | Report scheduling (daily/weekly/monthly), recipient management, due-report identification | `src/lib/scheduledReports.ts` | ✅ `scheduledReports.test.ts` (7 tests) |
| Multi-framework compliance reporting | Per-framework control pass/fail across 7 frameworks (ISO 27001, PCI DSS, Cyber Essentials, OWASP Top 10, CIS Controls v8, NIS2, DORA), overall score, markdown export | `src/lib/complianceReport.ts` | ✅ `complianceReport.test.ts` (5 tests) |
| SLA monitoring | **Live, Agency (admins exempt).** Per-account remediation targets in days (default 15/30/90/180, critical/high per CISA BOD 19-02), open-finding deadlines across sites, median time-to-fix, one email per finding when due soon and when breached. Built on `finding_lifecycle`, synced after every scan; a scan only resolves findings whose producing check it actually ran. `/dashboard/sla`, `GET/PUT /api/account/sla`. Needs migration 043; until then tracking is a no-op and the page says so | `src/lib/slaMonitoring.ts`, `src/lib/findingLifecycle.ts`, `src/lib/slaAlerts.ts`, `src/pages/api/account/sla.ts`, `src/components/SlaDashboard.tsx` | ✅ `slaMonitoring.test.ts`, `findingLifecycle.test.ts`, `slaAlerts.test.ts`, `__tests__/api/account/sla.test.ts`, `SlaDashboard.test.tsx` |
| Finding triage (E-64) | **Live, all plans.** Per finding per site (owner, host, checkId): accepted risk / authorised, false positive, or snoozed (7/30/90 days from the report; any expiry up to a year via the API), always with a reason; Undo. Active triage leaves the report's open list and executive-summary counts (collapsed "Triaged" group), SLA tracking and alerts, new-finding email/on-call alerts, and the GitHub Action's gate; only false positives leave future scores. `triage` field on `GET /api/v1/scans/{id}`, the webhook payload and the CSV/JSON export. `GET/PUT/DELETE /api/findings/triage` (bulk up to 200, audited `finding.triaged`/`finding.untriaged`). Needs migration 046; until then nothing is triaged and writes return 503 | `src/lib/findingTriage.ts`, `src/pages/api/findings/triage.ts`, `src/components/FindingTriage.tsx`, `src/components/ScanReportView.tsx`, `src/lib/slaMonitoring.ts`, `src/lib/scanExecution.ts`, `action/index.js` | ✅ `findingTriage.test.ts`, `__tests__/api/findings/triage.test.ts`, `FindingTriage.test.tsx`, `slaMonitoring.test.ts`, `slaAlerts.test.ts`, `__tests__/api/account/sla.test.ts`, `scanReport.test.ts`, `export.test.ts`, `scanAlerts.test.ts`, `oncallAlerts.test.ts`, `githubAction.test.ts` |
| Risk scoring | 5-factor composite scoring (severity 0.35, exploitability 0.25, density 0.15, attack surface 0.15, compliance impact 0.10), A-F grading, trend comparison | `src/lib/riskScoring.ts` | ✅ `riskScoring.test.ts` (8 tests) |

### Advanced Scanning

| Module | What it does | Code path | Tests |
|---|---|---|---|
| GraphQL scanning | Schema introspection detection, query depth analysis, field suggestion leak detection | `src/lib/scanners/graphql.ts` | ✅ `graphql.test.ts` (7 tests) |
| Proof-of-exploit | Safe, verifiable proof generation for findings (metadata-enriched) | Integrated into `src/lib/scanners/index.ts` via `Finding.metadata` | ✅ covered by scanner tests |
| Scan windows | Maintenance window definition, overlap detection, scan-eligibility checks | `src/lib/scanWindows.ts` | ✅ `scanWindows.test.ts` (8 tests) |

### Integrations

| Module | What it does | Code path | Tests |
|---|---|---|---|
| SIEM integration | Syslog (RFC 5424) and webhook event forwarding, severity filtering | `src/lib/siemIntegration.ts` | ✅ `siemIntegration.test.ts` (8 tests) |
| CI/CD SDK | Pipeline configuration generation, threshold-based gating, multi-provider support | `src/lib/cicdSdk.ts` | ✅ `cicdSdk.test.ts` (6 tests) |
| ServiceNow tickets | Incident create/get/close/comment via Table API, Basic auth | `src/lib/ticketProviders.ts` | ✅ `ticketProviders.test.ts` (11 tests, shared with GitHub Issues) |
| GitHub Issues tickets | Issue create/get/close/comment via REST API | `src/lib/ticketProviders.ts` | ✅ (same test file) |
| GraphQL API | Schema definition, query parsing, operation name extraction, introspection detection, depth validation | `src/lib/graphqlApi.ts` | ✅ `graphqlApi.test.ts` (7 tests) |
| Audit logging (expanded) | Extended event vocabulary, org-scoped audit trails | `src/lib/audit.ts` (extended) | ✅ `audit.test.ts` |

---

## 6. Plan-gating summary

| Enforcement | Count of rows above |
|---|---|
| ✅ Server-enforced | 11 (free-tier cap, rate limit, Slack, Teams, branding upload, branding-on-PDF, target-auth POST, authenticated-scan POST, team create/invite, connect-repo POST, monitored-targets cap) |
| ⚠️ Client-only / soft | 2 (Partner Portal Agency gate, extended-tool-suite path-gating) |
| ❌ No gate at all | 6 (AI fix, remediation PR, tickets, keys, shares, 2FA) |
| — Intentionally ungated | 7 (webhooks, repo-connection consumption, scan replay, Fix Wizard, asset inventory, diff view, score history — none advertised as tier-specific; rate-limited not plan-gated, per E-02's "don't invent pricing policy" decision) |

**Bottom line (2026-09-13 re-audit)**: plan enforcement has improved
significantly since the first audit (was 14 ❌ + 3 ⚠️). The 3
advertised-but-unenforced gaps (target-auth, team, connect-repo) are now
server-enforced; authenticated scanning is also now Agency-gated
server-side. The remaining 6 ❌ items are capabilities not advertised as
tier-specific anywhere in current copy — gating them would mean inventing
new product policy, not fixing a documented mismatch (`E-02`'s
"intentionally open" decision, confirmed by the account owner). The 7
"intentionally ungated" items are new features shipped 2026-09-11 that
were never advertised as tier-specific. See `docs/ENHANCEMENTS.md` E-02
for the full decision record.

---

## 7. Integrations — required vs optional

| Integration | Required for | Degrades to when unset |
|---|---|---|
| Supabase | Everything — auth, data, RLS | Throws at lazy access; admin routes catch → 403 |
| Stripe | Billing | "Stripe is not configured"; `STRIPE_PRICE_*` unset → 400/500 |
| Azure Blob Storage | Report hosting (optional), image/logo upload (**required**, 503 if unset) | PDF falls back to raw bytes; upload 503s |
| Playwright/Chromium | Page-health check, PDF rendering | Required for those two features specifically |
| Slack, MS Teams, Jira, Linear, GitHub App/PAT, Azure OpenAI, Upstash Redis, WPScan, Safe Browsing, HIBP, Resend, Google Analytics | Various (see rows above / `docs/architecture.md`) | All degrade gracefully to `not_configured`/disabled — **except** Upstash, which fails **open** (allows the request) when unreachable, silently removing the only cost control on the two rate-limited routes |
| Shodan InternetDB, OSV.dev, crt.sh, Cloudflare DoH, Wayback/CDX, endoflife.date, CISA KEV/NVD/security RSS | Free, keyless, no config | Any failure degrades to a clean empty result, never an error |
