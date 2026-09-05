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

*As of 2026-08-23.*

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
| `src/worker/tools/zap.ts` | Full spider + active scan | `ZAP_API_URL` (+`ZAP_API_KEY`, defaults `"changeme"` — see `docs/ENHANCEMENTS.md` E-14) | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/sqlmap.ts` | SQL injection confirmation | `sqlmap` binary | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/xsser.ts` | XSS confirmation | `xsser` binary. **Written without a verified reference run against a real binary** | `not_configured` | ⚠️ path-gated | no |
| `src/worker/tools/commix.ts` | OS command injection confirmation | `commix` binary. **Same unverified caveat as xsser** | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/subdomains.ts` | Subfinder passive enumeration, takeover candidates | `subfinder` binary | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/deepTls.ts` | testssl.sh: protocol/cipher/FS/named-CVE suite | `TESTSSL_PATH` or on PATH | `not_configured` | ⚠️ path-gated | no |
| `src/lib/scanners/secretScan.ts` | Gitleaks over a connected repo | connected repo + GitHub access + `git` | `not_configured`/`not_applicable` | 🔒 requires repo connection (ungated by plan) | no |
| `src/lib/scanners/dependencyManifest.ts` | npm/pip/Composer/Go/Maven manifests → OSV.dev | connected repo + GitHub access | `not_configured`/`not_applicable` | 🔒 requires repo connection (ungated by plan) | yes — parsers only (`src/__tests__/scanners/dependencyManifest.test.ts`); OSV-querying paths still need local/manual verification, matching the module's own stated verification method |
| `src/lib/scanners/dockerBaseImage.ts` | Dockerfile base-image EOL via endoflife.date | connected repo + GitHub access | `not_configured`/`not_applicable` | 🔒 requires repo connection (ungated by plan) | no |
| `src/lib/scanners/authenticatedCheck.ts` | Header/cookie recheck against an authenticated request | saved credential on a monitored target | `not_applicable` | ❌ **no plan check** despite being labelled "Optional (Agency)" on `/what-we-check` | no |

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
| `verify-ownership.ts` | POST | session only | manual | none | n/a |
| `generate-report.ts` | GET | key-or-session | manual | branding applied only on `plan === "agency"` | ✅ server for branding; ❌ **PDF generation itself is ungated — any tier, unlimited** |
| `generate-fix-pr.ts` | POST | session only | manual, **no UI caller exists** | none | ❌ none |
| `scans/[id]/ai-fix.ts` | POST | key-or-session | manual, per-finding | none | ❌ **none — Azure OpenAI tokens spent per click, uncapped, any tier** |
| `scans/[id]/create-ticket.ts` | POST | key-or-session | manual, per-finding | none | ❌ none |
| `scans/[id]/shares.ts` | GET/POST/DELETE | session only | manual | max 10/scan, max 365-day expiry (hardcoded, not plan-varied) | ✅ server (caps), ❌ not plan-differentiated |

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
| Authenticated scanning | `MonitoredTargets.tsx` + `target-auth.ts` | "Optional (Agency)" per `/what-we-check` | ❌ **none** — attaching a credential to a target has no plan check of its own; only the target-count cap above is enforced, so any plan with monitored-site access can add authenticated-scan credentials to it |
| Two-factor auth (TOTP) | `TwoFactor.tsx`, `auth.ts` MFA functions | — | ❌ no plan gate (not advertised either — see §7) |
| API keys / webhooks / share links / CSV-JSON export / CI Action | `ApiKeys.tsx`, `Webhooks.tsx`, `ShareLinks.tsx` | — | ❌ **no plan gate at all** — available on free tier |
| Repo connection (dependency/secret/Docker scanning) | `ConnectRepo.tsx` | Pro ("dependency monitoring", advertised) | ❌ **none** — connection itself is ungated; consumption is path-gated (see §3), not plan-gated |
| Jira/Linear ticketing + auto-close | `TicketIntegration.tsx` | — | ❌ no plan gate |
| Teams/collaboration (invite, roles) | `TeamSection.tsx` | Agency, per `docs/USER-GUIDE.md` §3.7 | ❌ **none** — also not on the pricing page at all |
| White-label branding (upload) | `BrandingSection.tsx` | Agency | ✅ server (see API table above) |
| White-label applied to PDF | `generate-report.ts` | Agency | ✅ server |
| "Priority support" | — | Agency (advertised) | — no code representation; no SLA field, no routing |

---

## 6. Plan-gating summary

| Enforcement | Count of rows above |
|---|---|
| ✅ Server-enforced | 7 (free-tier cap, rate limit, Slack, Teams, branding upload, branding-on-PDF, PDF-branding-decision) |
| ⚠️ Client-only / soft | 3 (multi-site monitoring, authenticated-scan labelling, extended-tool-suite path-gating) |
| ❌ No gate at all | 14 (AI fix, remediation PR, tickets, teams, keys, webhooks, shares, repo connection, target-auth, 2FA, generate-fix-pr, generate-report base cost, ai-fix cost, dependency-scan consumption) |

**Bottom line: plan enforcement is essentially unbuilt beyond a binary
free-vs-paid scan cap and white-label branding.** The Basic/Pro/Agency
ladder exists in Stripe billing and in marketing copy; in the product it
mostly doesn't exist. See `docs/ROADMAP.md` BETA-5 for the exit criterion
this drives, and `docs/ENHANCEMENTS.md` for the itemised backlog.

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
