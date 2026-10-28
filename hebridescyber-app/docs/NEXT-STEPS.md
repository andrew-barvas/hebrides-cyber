# Next steps — session handoff

**Last updated: 2026-10-22.** Read this first in any new session (local or
cloud), after `CLAUDE.md` and `docs/SCANNER-CONVENTIONS.md`. It says where
things stand, the rules that kept biting, the plan in order, and what only
the owner can do.

To resume in a cloud session: open the repo `andrew-barvas/hebrides-cyber`,
branch from `master`, and prompt *"Read hebridescyber-app/docs/NEXT-STEPS.md
and implement plan item N."* Do one item per session.

## Session handover — 2026-10-22

A long interactive session reviewed `master`, landed/verified work, and wrote a
full 7+6 sprint plan to `~/.claude/plans/pull-from-master-review-eventual-beaver.md`
(Part A harden-then-launch Sprints 1–7; Part B Burp/peer capability track C1–C6;
launch-readiness ≈ **58/100** — reliability + payments are the gating
weaknesses). That plan file is **outside the repo**; the Done/Todo below is the
in-repo summary.

**Done (merged / pushed):**
- **Sprint 1 / H1** — Stripe webhook silent-downgrade fix: **merged as #89**
  (`webhook.ts` never defaults a metadata-less event to `basic`; audits
  `plan_missing`; added no-downgrade tests + `pricing-checkout.spec.ts` +
  `planAccess` assertion).
- **PR #88** (nonce CSP / DNSSEC-via-DoH / set-plan): CI green, **still draft**.
  Verified safe on a local prod build (per-request nonce CSP, no `unsafe-inline`,
  zero violations, GA/Stripe allow-listed). The Next 16.4 `middleware`→`proxy`
  deprecation migration was added on its branch (commit `05605dd`, pushed).
- Config-remediation + attack-path + scanner work (#79–#87) already on master.
- **#90** (`feat/ai-triage-and-burp-parity`) merged — **token entropy** (via
  `sessionCheck`), **bounded replay** (`replayProbe`), **configurable OOB**
  (nuclei/sessionCheck), and **AI triage** (`aiTriage`, **off unless
  `AI_TRIAGE=1`** + Azure OpenAI configured); each with tests + docs
  (`BURP-PARITY.md`, `AI-TRIAGE-DESIGN.md`). Verified wired + green.
- **#92** strategy addendum (Burp/AI review) merged.

**Todo (next session, in order):**
1. **Merge #88** (verdict: safe), then run the two post-deploy checks the local
   preview couldn't: COEP `require-corp` vs live GA/Stripe, and the SSG
   `/blog/[slug]` route under the strict CSP.
2. **Sprint 2 (next undone, code-only)** — reliability/observability: add
   `src/sentry.worker.config.ts` (`@sentry/node`, reuse `scrubSentryEvent` as
   `beforeSend`); wire `Sentry.init`/`captureException`/`await Sentry.flush()`
   into `src/scripts/run-queued-scan-jobs.ts` (`main`, `failJob`, `main().catch`,
   the claim/reset error paths); add a `crypto.randomUUID()` correlation id
   threaded into the `[job …]` logs + the `executeScan()` call + `Sentry.setTag`;
   add a no-op-without-DSN unit test. No schema change for v1.
3. **Sprint 3** — a `verify` job in `scheduled-scans.yml` asserting ≥1 extended
   tool `status === "completed"` + per-tool artifact + alert; a progress-total
   unit test (non-safe `totalChecks === 58`); a controlled vulnerable staging
   target + bench fixture; a `/api/health` smoke step in `deploy.yml`; confirm a
   Basic subscriber receives a scheduled scan (POC-1).
4. **Sprint 4** — bounded, redacted `evidence` field on findings; fix the
   scheduled-report `pdf` branch (today emits JSON — `send-scheduled-reports.ts`).
5. **Sprint 5** — gating decision for the open routes
   (`ai-fix`/`keys`/`shares`/tickets); reconcile stale docs; prune ~20 merged
   remote branches; branch protection (owner).
6. **Sprint 6** — make the offensive tier real **and admin-only** (real
   `strix`/`cairn` pins + SHA-256; `is_admin` runtime gate; lock the consent
   route).
7. **Sprint 7** — admin-scoped API key + `profile` param on `POST /api/v1/scans`.
8. **Part B (post-launch)** — capability track. **C1 (token/JWT entropy) and
   much of C5 (configurable OOB + bounded replay) are now delivered by #90**,
   and AI triage shipped off-by-default. Remaining: **C2** GraphQL/API depth →
   **C3** authenticated scanning depth → **C4** DOM-XSS engine → **C6**
   custom-checks + MCP (and full OAST callback confirmation on top of #90's
   configurable OOB).
- *Minor:* Sprint 1's price-ID fallback on `checkout.session.completed` was not
  implemented (the core silent-downgrade safety is).

**Owner (manual, non-code) — these gate launch:**
- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_*`
  (unblocks billing + flips `/api/health` to `ok`).
- `SENTRY_DSN` + `NEXT_PUBLIC_SENTRY_DSN`; `UPSTASH_REDIS_REST_URL`/`_TOKEN`
  (rate limiting **fails open** without it).
- GitHub branch protection requiring the `Lint, typecheck, test` check (needs
  GitHub Pro for a private repo).
- A controlled vulnerable staging target (Sprint 3); customer ToS + PI insurance
  before any offensive traffic (Sprint 6).

## Where things stand

Everything below is merged to `master`, passed CI, and is deployed.
Database migrations: files exist through **059**; the next free number is **060**. **Auto-apply on deploy is live** (since 2026-10-14): the `DATABASE_URL` secret is set and every push to master applies pending files through `src/scripts/apply-migrations.ts` (ledger table `schema_migrations`, checksum drift check) before the deploy, then re-verifies the schema. The one-time baseline is done — production was migrated by hand through 047 (+050 applied individually), so a `workflow_dispatch` run with `baseline_up_to=047` recorded 001–047 and the same run applied 048–058; the drift check then reported `57 applied, 0 pending` (001–058; the sequence skips 023). **059 merged with PR #55 and applied automatically on the same day** — the first migration to go through the normal push path — so a brand-new sign-up now gets its `public.users` row and the Stripe welcome email. A new migration added in a PR applies automatically when that PR merges — no manual SQL-editor step except in exceptional circumstances. 051 widens the plan CHECK for Tier A + adds the offensive-scan tables; 052 adds admin plan-override columns; 053 the lookalike-domain tables; 054 the `scheduled` blog status; 055 the `tool_kill_switches` table; 056 the `email_events` table; 057 corrects the `cloud_credentials` column comment (S-1 fix, see CLAUDE.md); 058 adds `scans.error_detail`; 059 adds the `handle_new_user()` trigger + backfill that auto-creates a `public.users` row for every `auth.users` row.

| Shipped | Where |
|---|---|
| Emerging-threat alerts (E-68) | PR #1 — `emergingThreats.ts`, `emergingThreatAlerts.ts`, `emerging-threats.yml` (every 6 h), migration 045 |
| Lockfile + transitive dependency scanning, inventory SBOM (E-67) | PR #2 — `dependencyLockfiles.ts`, `lockfileSyntax.ts`, `ecosystemVersion.ts`, `osv.ts` querybatch |
| SAST with Opengrep + our own 34-rule pack (E-69) | PR #3 — `src/worker/tools/sast.ts`, `sast-rules/`, `repoClone.ts`, `sast-rules.yml` |
| Third-party script inventory, PCI 6.4.3/11.6.1 (E-62) | PR #4 — `scriptInventory.ts`; `info` on ordinary pages, `low` on payment pages (owner decision) |
| Finding triage: accept/authorise, false positive, snooze (E-64) | PR #5 — `finding_triage` (046), `/api/findings/triage`, report UI; only false positives leave the score |
| Signed-in crawl, slice 1 (E-70 follow-up) | `authenticatedCrawl.ts`, `crawl.auth.*` findings, design + safety rules in `docs/AUTHENTICATED-CRAWL.md`; uses the saved cookie/Basic credential |
| Next.js route discovery in the crawler | `readNextRoutes` reads `/_next/static/<id>/_buildManifest.js` (`sortedPages`, static routes only, same site) and seeds the crawl with pages nothing links to. A passive Next.js middleware-bypass check was considered and not built: the version isn't exposed, so any finding would be a guess |
| GraphQL exposure check in every scan | `graphql.ts` rewritten (it existed but was never wired in, and its checks were unevidenced) and wired into `runAllChecks`: open introspection (`graphql.introspection:<path>`, with type count), field-suggestion leakage when introspection is off (`graphql.suggestions`), public GraphiQL/Playground/Sandbox (`graphql.ide`). An endpoint counts only if the response has GraphQL's own shape; "no auth" and "no depth limit" findings were dropped as unevidenced. Bench: `graphql-open`, `graphql-locked`, and every SPA/catch-all trap must not report `graphql.*` |
| Confirmed-exploitable findings | `enrichWithProofOfExploit` now runs in `executeScan()` for every profile except `safe` (cap 20 per scan; `DISABLE_PROOF_OF_EXPLOIT=1` turns it off): open redirect, CORS, exposed file and reflected XSS (api-spec and ZAP alerts, which now carry url+parameter metadata). "Confirmed exploitable" badge, sort rank, `proof_of_exploit` in the API, flag in the executive report |
| Worker observability (Sprint 2) | `workerSentry.ts`: the Actions scan worker now reports unexpected failures to Sentry (`SENTRY_DSN` secret passed by `scheduled-scans.yml` and `on-demand-scan.yml`; no-op without it), tags `scan_id`/`job_id`/`worker_id`/`target_host`/`correlation_id` (the scan id, else the job id) and logs every job line as `[scan <id>]`. One job throwing no longer aborts the whole batch: it is recorded as failed against that job and scan and the worker continues. Only unexpected failures are reported (engine error, row not created), not normal outcomes like a no-longer-verified domain |
| Blog coverage fix | Daily and weekly posts now cover critical CVEs the old first-page NVD read missed (PHP2Shell) and cloud outages (Google, Azure, AWS status feeds). Details in `ARCHITECTURE-NOTES.md`, "Content generation". Posts already published are not rewritten; consider a catch-up post |
| Uptime monitor for our own site | `uptime.yml` probes `/api/health` every 10 min and opens or closes an `uptime`-labelled GitHub issue (down vs degraded, retried 3x); `/api/health` now answers HEAD (production returned 405, which HEAD-only monitors read as down). UptimeRobot setup in `OWNER-SETUP.md` |
| Uptime monitoring, bring-your-own UptimeRobot (Pro+) | `uptimeRobot.ts`/`uptimeProvider.ts`/`uptimeService.ts`/`uptimeAlerts.ts`, migration 062, three routes, `sync-uptime-monitors.ts` + `uptime-sync.yml` (15 min), `UptimeMonitoringConfig` on Integrations and an uptime badge per site in Assets. One down + one recovered message per outage (compare-and-set, so concurrent syncs can't double it); a failed provider call changes no status; the cron skips owners whose plan lapsed. **Before launch:** verify with a real free UptimeRobot key that a dashboard API key works as the v3 bearer token and that status strings map as expected (steps in `OWNER-SETUP.md`) |
| Bounded replay + AI triage (off by default) | `replayProbe.ts` (allowlisted read-only request) and `aiTriage.ts`: a model proposes one request, the replay runs it, the model judges the response; `confirmed` needs a quote verified in the response and a non-catch-all page. Annotates `metadata.aiTriage` only (never severity or lifecycle); "AI-verified" badge in `ScanReportView`. `AI_TRIAGE=1` to enable; design in `AI-TRIAGE-DESIGN.md`. **Before enabling for customers:** benchmark precision/recall by hand, use a UK/EU Azure OpenAI deployment, update the privacy notice |
| Session-token entropy ("sequencer") | `tokenEntropy.ts` + `sessionCheck.ts`: twelve cookie-less home-page requests, statistical checks, `sessionCheck.weak-session-token:<cookie>`; measurements only, never token values |
| Configurable out-of-band server | `nuclei.ts`: `INTERACTSH_SERVER`/`INTERACTSH_TOKEN`, `DISABLE_OAST=1`; passed through `scheduled-scans.yml` and `on-demand-scan.yml` (repo vars `AI_TRIAGE`, `INTERACTSH_SERVER`, `DISABLE_OAST`; secret `INTERACTSH_TOKEN`) |
| Burp parity audit | `BURP-PARITY.md`: Burp MCP is not used in the product (interactive, per-seat); capability-by-capability gap table |
| "Fixed" needs coverage | `diffFindings(…, { canDetect })` + `canDetectFromResults()`: a scan that couldn't have run a finding's tool (passive scan after a full scan, errored base check) no longer reports it fixed, which also stops ticket auto-close firing on it |
| Scanner inventory | `docs/SCANNER-INVENTORY.md`: every tool, service and check family, derived from the code, with the discrepancies found against the docs |
| Executive PDF report | `executiveReport.ts` (pure HTML: score, severity counts, top priorities, compliance snapshot incl. SOC 2/HIPAA, all findings, accepted risks, checks that did not finish; false positives left out; white label removes every "Hebrides Cyber"), rendered by `/api/generate-report`, "↓ Executive PDF" button on the scan page (`executiveReportClient.ts`). Not plan-gated yet (the route never was) |
| Reflected-XSS confirmation | `xssConfirm.ts` + `validateExploit` (`proofOfExploit.ts`): one harmless GET probe, context-aware verdict (body / quoted attribute confirmed; encoded, comment, script, textarea, title not), optional browser check; runs in every non-`safe` scan via `enrichWithProofOfExploit` (row above) |
| Domain fix | The Action's default API URL, `docs/API.md` and `security.txt` pointed at the never-registered `hebridescyber.com`; now `www.hebridescyber.co.uk`, pinned by a test |
| CI templates for any CI system | `public/ci/hebrides-scan.sh` + GitHub Actions, GitLab, Azure DevOps, Bitbucket, Jenkins templates, `/docs/ci` guide (see CLAUDE.md "CI templates"); replaces the broken `sdk/` |
| Supabase storage + Firebase exposure | `backendExposure.ts` lists one object name from buckets the code names (`.storage.from("x")`, `backend-exposure.storage-bucket`); `firebaseExposure.ts` checks the site's own Firebase config: RTDB shallow root read (`firebase-rtdb`, key names only), Storage list (`firebase-storage`), Firestore collections the code names (`firestore`, one document name). Only config keys count (`databaseURL`/`storageBucket`/`projectId`), so a site reading a public RTDB API isn't flagged. No bench fixture: the probes go to fixed Google/Supabase hosts, so evidence is covered by unit tests on recorded response shapes |
| Page metadata for client-component routes | `pricing/`, `contact/`, `login/` layouts (own title/description; login noindex); `/agencies` added to the sitemap |
| commix parser from a real run | `commixOutput.ts`, `fixtures/commix/`; unfinished/unreachable runs are `error`, nothing to test is `not_applicable` |
| Site crawler with page-level checks on every page (E-70) | `crawler.ts`, `crawlFindings.ts`, `crawl` in `ScanResults`; script inventory merges inner-page origins |
| Pull-request dependency checks (E-71) | `POST /api/v1/dependency-diff`, `dependencyDiff.ts`, Action `mode: dependencies` |
| End-of-life detection; certificate checks (incl. subdomains); TLS now reads broken certs | `endOfLife.ts`, `subdomainCerts.ts`, `tls.ts` |
| Fix-PR repo-ownership check; multi-repo scans; Playwright on scan runners | commit 3180aa6 |
| Report fixes: security.txt not an "exposed file"; one compliance badge per framework | commit a91ad40 |
| Mobile card-stack tables, PWA manifest/icons/viewport | `ScanList.tsx`/`FleetOverview.tsx`/`SlaDashboard.tsx`/`ScanReportView.tsx`'s tables stack into cards below `sm:`; `manifest.ts`, `touch-icon-180.png`/`icon-192.png`/`icon-512.png`, `viewport` export; `tests/e2e/mobile-tables.mobile.spec.ts` + a Chromium-based mobile Playwright project — see CLAUDE.md "Mobile & PWA" |
| Item 10, part 1: remediation pack | `buildRemediationPack()` (`remediation.ts`), `GET /api/v1/scans/{id}/remediation-pack` — every actionable finding as one category-grouped Markdown download, no connected repo needed. "↓ Remediation pack" button on the report page |
| Item 10, part 2: DOM-based XSS confirmation | `xssConfirm.ts`'s `confirmDomXss()`, wired into `playwright.ts`'s existing browser check via the URL fragment (never reaches the server) — `playwright.dom-xss` findings are confirmed by construction |
| Item 10, part 3: login recording | `loginRecorder.ts`, `POST /api/account/record-login` — records a session by driving the target's real login form, for form/CSRF/MFA-free apps; saves the same `target_auth_credentials` row the manual-entry path does. See CLAUDE.md "Login recording" and `docs/AUTHENTICATED-CRAWL.md` for the still-owed consent-copy review |
| EASM discovery wired in (was dead code) | `easmDiscovery.ts`'s `runEasmDiscovery` now runs in `executeScan` after `syncAssetInventory` — crt.sh on every scan, DNS brute-force only once the Tier A offensive gate has cleared. See CLAUDE.md "EASM discovery" |
| Magento/Shopify deep scanning | `webapp.ts`'s `checkMagento`/`checkShopify`, gated on `fingerprint.ts`'s CMS detection like WordPress/Joomla/Drupal — `env.php`/downloader/default-admin-path exposure (content-signature validated) and leaked Shopify Admin API tokens (never the intentionally-public Storefront token) |
| Admin: customer plan override + read-only customer detail | `POST /api/admin/subscription` upserts `subscriptions` tagged `source='admin'` (migration 052 also fixes `tier_a` never having been added to the plan CHECK constraint); `GET /api/admin/customers/[id]` is a read-only profile+subscription+recent-scans view reached from the Customers tab's "View" button, logged as `admin.customer_viewed`. Not session impersonation — see the file header on why |
| Admin: stuck/failed queue job retry | Queue tab's "Retry" button on a failed job reuses the existing scans-tab retry path; new "Recover stuck jobs" button runs `reset_stale_scan_jobs()` on demand via `PATCH /api/admin/queue` instead of waiting for the next scheduled worker run |
| GitHub Actions workflow security scanning | `src/worker/tools/workflowSecurity.ts` wraps the real zizmor tool (PyPI, pinned `1.30.1`) over the connected repo's `.github/workflows/` — script injection, insecure `pull_request_target`, unpinned actions, excessive permissions, secret exposure. `workflowSecurityCatalog.ts` maps all 41 real audit idents to 7 categories; full + osint profiles, same repo gating as `sast.ts` |
| JWT security analysis | `src/worker/tools/jwtAnalysis.ts` decodes JWTs observed in a Set-Cookie header, the response body or the URL — `alg:"none"`, missing `exp`, a weak HMAC secret found by local signature recomputation, HTTP transmission, exposure in a URL. Never forges or replays a token (`docs/NEXT-STEPS.md`'s own "not doing: JWT forging" line already ruled that out); `api` profile, same placement as `sessionCheck.ts` |
| HTTP request smuggling detection | `headers.ts`'s `headers.smuggling-surface`: a response carrying both Content-Length and Transfer-Encoding (RFC 7230 §3.3.3 framing ambiguity) — passive only, part of the base suite, no extra request. A genuine desync probe needs raw-socket framing this codebase has never written and risks corrupting a connection pool shared with other tenants of the same front-end/CDN — out of scope even for Tier A |
| Typosquat/supply-chain package risk scoring | `dependencyManifest.ts` now also runs `typosquatRisk.ts`: an npm/PyPI dependency name one Levenshtein edit from a curated well-known-package list, corroborated against the real registry (`registry.npmjs.org`/`pypi.org`) — reported only when the candidate has far fewer published releases than the mature package it resembles (verified against a real, still-live example: `loadsh`, 4 releases since 2018, vs `lodash`'s 117). Never on name similarity alone, never when the registry lookup 404s or fails — no evidence either way. `dependency-manifest.typosquat-risk:<name>`, medium severity |
| Lookalike-domain / phishing monitoring | `lookalikeDomainMonitor.ts`'s `sendLookalikeDomainAlerts`, run from `executeScan` Phase 2 alongside attack-surface alerts: a small, bounded set of one-edit-away candidates (omission/doubling/transposition/hyphenation/substitution/TLD-swap) of the owner's own domain, checked against the real crt.sh record and reported only when a certificate is already issued for the exact candidate — never on name similarity alone. Deliberately crt.sh, not dnstwist: dnstwist's value is live DNS resolution, which this session's sandbox couldn't verify (its DNS egress is restricted even for domains that definitely exist), where crt.sh is the same already-proven data source attack-surface monitoring already depends on. Full sweeps are throttled to once every 7 days per domain and skipped for non-alerting accounts, since each one costs real external queries |
| SSRF out-of-band testing | `nuclei.ts`'s baseline `-tags` now includes `ssrf`/`oast` — real nuclei templates that inject `{{interactsh-url}}` and confirm a vulnerability only on a genuine callback, never a response-body guess (confirmed against the real nuclei-templates repo: 215 templates tagged `ssrf`, 601 using the interactsh placeholder). Needed no new infrastructure: nuclei already defaults `-iserver` to the free public interactsh collaborator pool (`oast.pro`/`oast.live`/etc., the same ProjectDiscovery infrastructure nuclei/subfinder/httpx already run on) — confirmed live that nuclei attempts those exact connections once an OAST-tagged template loads. This resolves the "Not doing: SSRF callbacks" line above without hosting anything |
| RSS/Atom feed for the blog | `GET /feed.xml` (`src/app/feed.xml/route.ts`) — hand-rolled RSS 2.0, no dependency, listing both daily and weekly posts newest-first from the same `blog_posts` query `sitemap.ts` already uses. Discoverable via `layout.tsx`'s `alternates.types` autodiscovery link and a small link on `/blog` |
| Scheduled/future-dated blog publishing | A genuine new `blog_posts.status = 'scheduled'` value (migration 054) rather than a future `published_at` on `status='published'` — the latter would leak immediately, since no public query or RLS policy checks the date boundary (confirmed by inspection, not assumed). `.github/workflows/publish-scheduled-posts.yml` (hourly) runs `blogSchedule.ts`'s `publishDuePosts()` to flip due rows to `'published'`. Admin editor gets a third status option + a `datetime-local` input, both API routes validate a required future `published_at` |
| Admin: usage/scan-cap visibility near plan limits | `GET /api/admin/customers/[id]` now also returns the three real, enforced ceilings — monitored-targets-per-plan (existing `monitored_targets_cap()` RPC), team members vs. the flat 25, and free-tier scans used (only while no subscription is active) — flagged near/at cap by `usageCapStatus.ts`'s pure `capStatus()`. Deliberately doesn't invent a scans-per-month cap: no such limit exists in enforcement or pricing copy, only cadence (weekly/daily) does |
| Admin: real MRR/revenue/churn | `revenueMetrics.ts` + `GET /api/admin/metrics`: paying MRR from real subscription rows × this product's published prices (no live Stripe call — prices are fixed/published and the rows are webhook-synced), with admin comps (£0) and bespoke Tier A (no fixed price) counted separately instead of inflating the headline — the old flat sum both missed `tier_a` and counted comps. New/cancelled subs over 30 days come from the webhook-synced `audit_logs` (the only history kept), feeding `churnRatePct()`. Admin Overview gains a revenue & churn panel; MRR card now reads paying-only |
| Admin: structured audit-log filtering | `auditFilters.ts` + `GET /api/admin/audit`: on top of the existing action/actor free-text search, a category dropdown (`LIKE '<resource>.%'` over the stable `<resource>.<verb>` action vocabulary, options = `AUDIT_CATEGORIES`) and a from/to date range (`dateRangeBounds()` → inclusive start/end-of-day UTC `created_at` bounds, null-safe on bad input). Pure helpers, unit-tested; route applies what they return |
| Admin: per-tool kill switch | `toolKillSwitch.ts` + `tool_kill_switches` (migration 055, service-role-only) + `GET`/`PATCH /api/admin/tool-flags` + a new "Tools" admin tab. An admin disables an extended-scan tool globally; the worker applies `applyKillSwitch()` right after `resolveToolConfig` so it stops running on every scan, no deploy. Only ever forces a tool off (never enables), best-effort read (missing table/error = nothing disabled), unknown tool names ignored. Toggles audited (`admin.tool_disabled`/`.tool_enabled`) |
| Admin: GDPR erasure queue view | `summarizeDeletionQueue()` (`accountErasure.ts`) + `GET /api/admin/deletion-requests` + a new "Erasure" admin tab: read-only list of pending `deletion_requests` (migration 048) soonest-deadline-first, each tagged overdue with `deadlineWording()`, plus an overdue count and owner email. Erasure stays the deliberate `npm run account:erase` operator step, never a web button (irreversible, cross-table). Pure helper unit-tested |
| Admin: email deliverability monitoring | `emailEvents.ts` + `email_events` (migration 056, service-role-only) + `GET /api/admin/email-health` + a new "Email" admin tab. `sendEmail()` records one row per real send attempt (recipient domain only, PII-minimised), best-effort and gated on the service-role env so it no-ops in tests/dev. `summarizeEmailHealth()` (pure, unit-tested) gives a 24h send count, failure rate (null when nothing sent) and the latest failures. Known gap noted: the SendGrid welcome email in `webhook.ts` is outside this choke point |
| Admin: `scans.error_detail` surfaced in the UI | `GET /api/admin/scans` selected `error_detail` from the DB but dropped it when building the response — the column (migration 058) was captured but never reached the admin panel. Now returned as `errorDetail`; the Scans tab shows it as a small red line under the target URL for a failed scan |
| Sign-up page + password reset + auto-provisioned profiles | `/signup`, `/forgot-password`, `/reset-password` (P1-2 from `PRODUCT-REVIEW-2026-10.md`). Found and fixed the real gap behind "no sign-up page": nothing ever created a `public.users` row for a real sign-up (only `seed-users.ts` did) — migration 059's `handle_new_user()` trigger now does it automatically on every `auth.users` insert, reading `company_name` out of sign-up metadata, plus a backfill for existing accounts. `signInWithMagicLink()` gained an optional `metadata` param; new `requestPasswordReset()`/`updatePassword()`. Login ⇄ signup cross-links added; pricing's "sign in first" copy now also offers signup |
| Risk score weighted by CVSS / KEV / EPSS | `scanners/riskScore.ts`'s `findingPenalty()` replaces the flat severity tally: raised to at least the CVSS band's penalty, ×1.5 for CISA KEV (×2 ransomware), ×1.4/×1.2 for EPSS ≥ 0.5/≥ 0.1, ×0.75 only for a measured EPSS < 0.01 on a non-KEV finding, capped at 45 per finding. No CVSS/intel = exactly the old flat penalty, so most scores are unchanged; stored scores aren't rewritten (review finding 6) |
| Customer secrets encrypted at rest, everywhere | The AES-256-GCM encryption that only covered cloud credentials (S-1) now covers Jira/Linear/ServiceNow/GitHub tokens, PagerDuty/Opsgenie keys and authenticated-scan cookies/Basic Auth passwords too (`encryptSecret`/`sealSecrets`/`revealSecrets`). Writes fail closed (503) with no key; reads skip an undecryptable value rather than use ciphertext; legacy plaintext still works until rewritten by `npm run secrets:encrypt-existing` / the "Encrypt stored secrets" workflow. Also fixed: `CREDENTIALS_ENC_KEY` was never passed to the scan workers (see CLAUDE.md "Secrets at rest") |

Coverage floor (`vitest.config.mts`): **75 / 67 / 75 / 76** (statements /
branches / functions / lines) — raised after adding tests for
`lockfileSyntax.ts`, `authenticatedCheck.ts` and `apiKeys.ts` (previously
untested). Lint: 0 errors (38 known warnings).

**Dependency scanning of this repo (2026-10-14).** `npm audit` found 18 vulnerabilities, including a critical in Next.js 16.3.1 (three RCE advisories — Windows servers, the image-optimizer with AVIF, `next/og` — plus an image-optimizer SSRF and cache-poisoning issues; we don't call `next/og` or `next/image`, but Next serves `/_next/image` regardless, so it was treated as exposed). `npm audit fix` took production dependencies to **0** (Next 16.4.1; build, 3127 unit tests and 35 e2e tests pass on it). New `.github/workflows/dependency-audit.yml` fails on high/critical in production dependencies (on PRs that touch the lockfile, pushes to master, and a weekly run for newly published advisories) and lists dev-dependency advisories in the job summary without failing; it is separate from `deploy.yml` so a new advisory can't block unrelated PRs or the deploy of its own fix. Dependabot now covers npm as well as Actions (weekly, minor/patch grouped, majors held back). The 10 advisories left are build-time only (`tailwindcss`, `@tailwindcss/typography`, `eslint-config-next` and their glob/chokidar chains — ReDoS-type issues that need attacker-controlled input to a build tool) and need major bumps, notably Tailwind 3 → 4, which is a deliberate migration rather than a drive-by; npm's own suggested `eslint-config-next@14` is a downgrade and should be ignored.

## Rules that kept biting — follow these

1. **Gate = four commands, check exit codes, not summary lines.** From
   `hebridescyber-app/`: `npm run lint` (0 errors), `npx tsc --noEmit` (no
   output), `npm run test:unit:coverage`, `npm test`. Vitest prints
   "N passed" even when an *unhandled error* fails the run — a line
   `Errors  1 error` means failure. CI type-checks PRs merged into master,
   so rebase onto the latest master before trusting a local pass.
2. **Never return a value from a `beforeEach`/`afterEach` arrow.**
   `beforeEach(() => mock.mockReset())` returns the mock, and Vitest runs a
   returned function as a cleanup hook — it called the mock with no
   arguments and failed CI. Use a block body.
3. **Windows line endings.** Many files are CRLF; string-replace scripts that
   assume `\n` silently miss. Use the Edit tool, and avoid passing `\n`
   escapes through shell heredocs (they get mangled).
4. **Evidence discipline.** A failed lookup is `status: "error"`, never an
   empty "checked" — `findingLifecycle.ts` would otherwise mark last scan's
   findings fixed and close their tickets. New base-suite checkId prefixes
   that don't normalise to their `ScanResults` key need a `BASE_ALIASES`
   entry; extended tools need `TOOL_ALIASES` (see CLAUDE.md).
5. **Coverage floor only goes up**, to the measured value, after merging.
6. **Generate `www` URLs** (`process.env.NEXT_PUBLIC_SITE_URL ??
   "https://www.hebridescyber.co.uk"`); the bare domain only redirects.
7. **One build at a time.** Parallel subagents exhausted the usage limit
   three times; local and cloud sessions share the same allowance. Give any
   scratch file a unique name — two builds overwrote each other's PR body.
8. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`;
   PR bodies end with the Claude Code attribution line. Draft PR, wait for
   CI, squash-merge, watch the `Deploy` run.

## Follow-ups on shipped features

Short notes on what each shipped feature still doesn't cover; the design of
each lives in CLAUDE.md and the module's header.

- **Crawler (E-70):** login recording for the signed-in crawl (slice 1 uses a saved cookie/Basic credential, see `docs/AUTHENTICATED-CRAWL.md`); JS-rendered link discovery beyond the Next.js build manifest on passive scans (scheduled scans now get it from katana, E-77, as `katana.*` findings); per-page SRI/cookies for pages behind forms.
- **PR dependency checks (E-71):** lockfile-less PRs (manifest-only changes); a GitHub App for comments on fork PRs; pinning a finding to the changed line.
- **Benchmark (E-73):** DNS, ports, recon and the extended tools are not benchmarked; `knownIssues` lists the tracked defects.
- **Cross-site findings (E-74):** no authenticated e2e yet.
- **Duplicates:** `EQUIVALENCES` covers only confident id mappings; extend it as real nuclei/ZAP output confirms more. Injection findings need url+parameter evidence in their checkIds before they can be matched.
- **SAST (E-69):** Koa `ctx`, FastAPI typed params, more languages.
- **Emerging threats:** WordPress plugin matching; re-alert when "possibly affected" becomes "affected".
- **RLS tests:** extend the matrix to ticket_integrations, sla_policies, organisations/RBAC, report_shares.
- **e2e:** `/account`, `/admin`, `/dashboard/assets|sla|integrations`, the Fix Wizard and `/diff` are not covered signed-in.
- **WhatWaf (2026-10-27):** fixed a fabricated finding. Output whatwaf.ts couldn't read (empty, a crash, a format change) became a medium `whatwaf.no-waf`; it is now `error` (not-run, so lifecycle leaves last scan's WAF finding alone), and `no-waf` needs WhatWaf's own final verdict. The old parser expected JSON on stdout (`firewall_name`/`is_protected`) that WhatWaf never prints: `-J/--json` writes a file under `~/.whatwaf` (v1.9 `lib/settings.py`), so the flag is dropped and the parser reads v1.9's stdout verdict lines, taken from its source (see `whatwaf.ts`'s header). `--skip` added: the bypass analysis fired tamper payloads at the target for results we discarded. The hardcoded "confidence" (85/90%, flagged in `PRODUCT-REVIEW-2026-10.md`) is gone from the result, the finding and the dashboard card: WhatWaf reports none. Still open: no recorded run. Capture real v1.9 output into `fixtures/whatwaf/` and add `whatwaf.integration.test.ts`, as for dalfox; the install pin (WhatWaf isn't on PyPI, so `pip3 install whatwaf` never installed it) is the supply-chain hardening PR's. Confirmed by the real-binary integration run (2026-10-28): unknown-firewall and "behind some kind of protection" runs end in an interactive "create an issue?" prompt with no flag to skip it, so with stdin closed WhatWaf exits non-zero after printing its verdict. `runWhatWaf` now keeps a WAF verdict from a failed exit's stdout (never "no WAF": that needs a clean exit), and runs `--throttle 1` with a 120s limit (a run took ~88s at `--throttle 3`). A plain local test server comes back as "Unidentified WAF", so that verdict can be a false positive; it is an info finding quoting WhatWaf's line. Check that against the real binary.

## Plan (2026-10-06): DeepSeek/Copilot strategic review, checked against the code

Both reviews worked from older docs. Already done in code: crawler (E-70), PR
dependency checks (E-71), cross-site findings (E-74), sqlmap fix + xsser
retirement (E-72), benchmark (E-73), auto-migration and post-deploy health
check (E-56/57, they run once their secrets exist), executive summary/PDF,
Subfinder install, signed-in crawl slice 1, confirmed-exploitable findings.
No public page claims an unwired enterprise feature (SSO, SCIM, RBAC, MSP
portal are either absent from marketing or labelled "not available yet").

In order, one PR each, merged on green CI:

1. ~~**Domain fix**~~ done (PR #15): the Action's default API URL, `docs/API.md` and `security.txt` pointed at the never-registered `hebridescyber.com` (customers' API keys would have gone to whoever registers it).
2. ~~**CI templates that work:**~~ done: `public/ci/hebrides-scan.sh` (POSIX sh + curl + jq, the Action's exact gate: new, untriaged, at or above `HEBRIDES_FAIL_ON`; JUnit output; tested under dash and bash against a mock API) and templates for GitLab, Jenkins, Azure DevOps, Bitbucket and GitHub Actions, served from the site with a `/docs/ci` page. Replaces `sdk/`, whose templates sent `targetUrl` and parsed `scanId` (the API uses `target_url`/`scan_id`) and so never started a scan. Needed because the repo is private: customers cannot `uses:` the packaged Action.
3. ~~**Plan gates honour subscription status (E-02):**~~ done: seven hand-rolled gates (`connect-repo`, `target-auth`, `branding-logo`, `team`, `team/members`, `partner-portal`, `cloud-credentials`) read `plan` and ignore `status`; Stripe sets `past_due`/`cancelled` without changing `plan`, so a cancelled Pro/Agency account keeps paid features. Move them onto `planAccess.ts` helpers (active only, admins exempt); gate fix PRs at PR time (Pro covers "Dependency & CI/CD scanning"). Customer-facing text when Stripe isn't configured instead of the env-var name; read `?checkout=cancelled` on /pricing.
4. ~~**NCSC Web Check / Mail Check replacement surface:**~~ done (`/cyber-essentials`, footer "Resources", home strip, sitemap, `sql/seed/002_ncsc_web_check_retirement_post.sql`, `marketing/16-ncsc-replacement-campaign.md`; the SBOM page's stale "five ecosystems from manifests" copy corrected): link `/web-check-alternative` and `/ai-threats` from header/footer/home (nothing links to either today); add `/ai-threats`, `/sample-reports`, `/sbom` to the sitemap; a Cyber Essentials readiness landing page; an evergreen NCSC-retirement blog post (seed); campaign copy drafts (email, LinkedIn, ads keywords) in `marketing/`.
5. ~~**Account erasure within 30 days:**~~ done (migration 048 `deletion_requests`, `src/lib/accountErasure.ts`, `check-deletion-requests.ts` + `deletion-requests.yml` daily at 06:47 UTC, erase script takes email or user id and cancels Stripe by default; the account page shows the deadline): the privacy policy promises it; today a request only writes an audit row and emails the operator, and nothing tracks the deadline. `deletion_requests` ledger (migration 048), a daily job that alerts the operator before day 30, erase logic as a library function (cancel the Stripe subscription too), fix the script's lookup (the alert suggests a user id, the script only accepts an email).
6. ~~**Onboarding and verification friction**~~ done. Verification (PR #20): a failed check says what each method found (`ownership.ts` `verifyDomain` → `dns`/`file` status, `verificationHints`), the file fetch refuses private/reserved hosts, start and check have separate rate-limit buckets (20 and 30 an hour), the panel lists your domains with copy buttons and no dev jargon, and Run scan warns when the typed host isn't verified (pointing out a verified www/apex twin). Checklist: `onboardingFlags.ts` decides what counts (a refused `pending` scan is not a first scan; any working alert channel, including a paid plan's emails and on-call, completes "Set up alerts"), with an e2e case. Not done on purpose: regrouping Trends/SLAs under "Compliance" (the nav is already short and flat, and Trends isn't a compliance feature); the sidebar's "New scan" button already is the quick action.
7. ~~**Continuous monitoring**~~ done: after each scan, alerts for hostnames whose first certificate is recent and for NS/MX/SPF/DMARC changes (migration 049, `attackSurfaceMonitor.ts`, see CLAUDE.md "Attack-surface change alerts"). Its review also found that the scan workers never had `RESEND_API_KEY`, so no post-scan email (critical findings, scan complete, SLA) had ever been sent; both worker steps now pass it (needs the `RESEND_API_KEY` repository secret, which `emerging-threats.yml` already uses). Follow-up from the review, done: `scanners/registrableDomain.ts` was a hand-picked suffix list, so every scanner looked at the wrong zone for `*.sch.uk` schools (the county's) and unlisted ccSLDs such as `co.ke` (the registry's), and enumeration on a platform domain took in every site on it. It now uses the full Public Suffix List (`tldts`): `registrableDomain` for registry-level checks, `ownerDomain` (private suffixes included) for scoping hostnames. `easmDiscovery.ts` is now wired in too (2026-10-12): crt.sh on every scan, DNS brute-force gated behind the Tier A offensive profile (item 11 below) — see CLAUDE.md "EASM discovery". No "hostname removed" alerts (certificate logs are append-only and passive sources vary between runs, so they would be noise).
8. ~~**Portfolio report**~~ done: `GET /api/portfolio-report` + dashboard button (Agency), see CLAUDE.md "Portfolio report". Not stored, so it needs no retention or erasure handling.
9. **Hardening:** release installs in `scheduled-scans.yml` SHA-256-pinned (nuclei, subfinder, gitleaks, trivy 0.75.0). **gospider and kiterunner now install and are verified** (v1.1.6 / v1.0.2, pinned; parsers rewritten against real captured output; real-binary `*.integration.test.ts` in `tool-integration.yml`). Kiterunner uses our curated `src/worker/tools/wordlists/api-routes.txt` compiled to `.kite`. **httpx added** (v1.6.10, pinned + SHA-256, `src/lib/scanners/hostProbe.ts`): after Subfinder enumerates subdomains, httpx probes the target and each discovered host for a live HTTP service (status/title/tech/TLS) — closing the "subdomains found but never probed" gap and feeding `http-probe.live:<host>` inventory findings that ride the new/fixed diff. One GET per host, read-only, full+osint profiles; from the Copilot-40 tool review (the one new tool that fit posture — the rest were brute-force/exploitation/internal-network/cloud-credential tools declined or deferred; see the plan). **Latent bug fixed:** every wrapper used `promisify(execFile)` with stdin left open, so nuclei and gospider (which read targets from stdin) hung until killed — every scheduled scan's nuclei produced nothing. All wrappers now use `src/lib/execTool.ts` (closes stdin). **Still open — strix and cairn:** autonomous AI exploit agents (pip `strix-agent` v1.7.0; Cairn v0.2.1 AGPL) that need a live LLM key, Docker and a real target to verify, and running them means real PoC exploitation — a product-posture / "no destructive payloads" / cost / AGPL decision for the owner before enabling the (currently unselectable) `ai-pentest` profile; wrappers to be rewritten against their real CLIs in a separate PR and kept `not_configured` until then. Also still to do: tests for `dockerBaseImage.ts`, `subdomains.ts`, `waybackDiscovery.ts`, `nmap.ts`, `nuclei.ts`, `zap.ts`; refresh `BACKUP-RESTORE.md` (still says `supabase db push`).

11. **Tier A — opt-in offensive readiness testing (owner asked for all four anti-features behind a new top tier).** New `tier_a` plan (`planAccess.ts`, Stripe `STRIPE_PRICE_TIER_A`, pricing card) and an `offensive` scan profile holding the `OFFENSIVE_ONLY_TOOLS` (excluded from `full`). Runtime-gated in `run-queued-scan-jobs.ts` on Tier A + a per-target `offensive_scan_authorizations` record (migration 051, consent route `POST /api/account/offensive-authorization`) + a verified domain, else downgraded to safe + audited. Reverses the §6 "no destructive payloads" promise for Tier A only — **owner action: customer contracts/ToS must authorise real attack traffic before the destructive tools are enabled.** Shipped verified: `contentDiscovery` (ffuf v2.1.0, bounded directory/path discovery, pinned+fixture+integration test) and stronger credential-defence detection (CAPTCHA/rate-limit signals in `businessLogic.ts`). Shipped gated + `not_configured` + **UNVERIFIED** (no real target in CI, enable post-ToS): `credentialSpray` (hydra, interlocked to a customer-designated sacrificial test account) and real exploitation (the strix/cairn engines, now under the same Tier A gate — supersedes the item-9 strix/cairn note).
10. Then: login recorder, DOM-based XSS validation, remediation packs.

Not doing: MFA bypass, JWT forging, CSRF bypass, gRPC fuzzing (attacks, not scanning). SSRF callbacks were listed here pending an owner decision on hosting an out-of-band endpoint — resolved without hosting anything: nuclei's `ssrf`/`oast` tags (now in its baseline, see the shipped-list row below) use the free public interactsh collaborator pool nuclei already defaults to.

**Owner decisions needed:** whether AI fix, API keys, share links and tickets should be paid-only (no page promises them for a tier, so gating them is new policy).

**Done, 2026-10-13:** the six still-unwired library modules (`rbac.ts`, `scimProvisioning.ts`, `mspPortal.ts`, `customScanPolicies.ts`, `riskScoring.ts`, `graphqlApi.ts`) deleted from `src/` entirely, along with their tests — none had a live importer. Coverage floor lowered to the measured value after removing their tests.

**Migrations `034_organizations.sql`/`035_rbac.sql`/`036_sso_providers.sql`/`037_ip_allowlist.sql` build the schema these modules would have used** (`organizations`, `org_members`, `rbac_permissions`, `sso_providers`, `ip_allowlist` — the last is a different table from the live per-API-key `ipAllowlist.ts`/`api_keys.allowed_cidrs`, despite the name). None of the four tables are referenced anywhere in `src/` or `tests/db/`, so the feature itself was never wired — but **the owner has confirmed 034-037 are applied to the real Supabase project**, so unlike `ssoSaml.ts`/`orgModel.ts`/`cicdSdk.ts` the migration files stay. They document real, already-applied schema; only the application code that would have used it was dead.

**Detection queue (2026-10-18), one PR each with tests, a benchmark case, green CI and a deploy:** finish E-77 (badsecrets, katana, more CMS fingerprints), then the five competitor-gap features in `.claude/plans/proud-spinning-nygaard.md`: website malware/injected-content detection, a Cyber Essentials self-assessment assistant, network exposure (naabu top-1000 + nmap + nuclei network), live-site JS secret/endpoint scanning (check what `backendExposure.ts` already covers first), dependency licence compliance (deps.dev).

**Malware detection status (2026-10-19, PR 66):** injected-content detection is wired into scans; its benchmark case and docs entries (SCANNER-INVENTORY, USER-GUIDE) are NOT added yet. Remaining competitor-gap features, one PR each: (1) Cyber Essentials self-assessment assistant, (2) network exposure (naabu top-1000 + nmap + nuclei network), (3) live-site JS secret/endpoint scanning (check `backendExposure.ts` coverage first), (4) dependency licence compliance (deps.dev), (5) malware benchmark case and docs follow-up.

**Launch blockers and acceptance criteria:** see `docs/LAUNCH-PRIORITY.md` (payments, reliability baseline, evidence on findings E-75, SSO E-76, detection proof).

## Owner actions pending (not code)

**The tracked list is now [`OWNER-TODO.md`](OWNER-TODO.md)** (IDs, how-to, raised and actioned dates, verified status as of 2026-10-27). The list below is the original context it was built from; add new owner steps there, not here.

In order of impact:

0. **Turn on secret encryption (do this first, in this order).** Until `CREDENTIALS_ENC_KEY` is set, saving a Jira/Linear/ServiceNow/GitHub token, a PagerDuty/Opsgenie key, an authenticated-scan login or cloud credentials returns 503 by design. (1) Generate a key — `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` — and keep a copy in a password manager. (2) Set it as `CREDENTIALS_ENC_KEY` in the Azure Static Web App's configuration **and** as a GitHub repository secret of the same name, with the **same value**. (3) Run Actions → "Encrypt stored secrets" once as a dry run, then again with "confirm" ticked, to encrypt what's already saved. (4) Rotate the Supabase database password (it was pasted into a chat on 2026-10-14) and update `DATABASE_URL`.
1. **Stripe price IDs (E-07)**: paid sign-up is impossible until `STRIPE_PRICE_*` are set; `/api/health` stays "degraded".
2. **Sentry DSN (E-03)**: failed scans are invisible in production without it.
3. **Restore drill (E-13 / LIVE-4)**: restore a backup into a scratch Supabase project and record the result in `BACKUP-RESTORE.md`; consider Supabase Pro for point-in-time recovery.
4. **Deploy secrets**: `DATABASE_URL` is set and the one-time `baseline_up_to=047` run is done — migrations now auto-apply on every deploy (see the migrations note at the top). `SITE_URL` is set (bare domain), and since 2026-10-27 the post-deploy health check follows the redirect to `www`, so it checks real health. (The `DATABASE_URL` password was pasted into a chat during setup on 2026-10-14 — rotate it in Supabase and re-save the secret.)
5. **Publish the GitHub Action** from a public repository (this repo is private, so customers cannot `uses:` it); until then the CI templates in item 2 are the supported route.
6. **Domains**: register `hebridescyber.com` defensively; optionally a `security@hebridescyber.co.uk` alias for `security.txt`.
7. **ToS solicitor review** (BETA-B1).
8. **NCSC replacement campaign**: run `sql/seed/002_ncsc_web_check_retirement_post.sql` in the Supabase SQL editor (publishes the blog post), then send/post the drafts in `marketing/16-ncsc-replacement-campaign.md` (email sequence, LinkedIn, Google Ads, agency outreach).
9. DNS **CAA** record at GoDaddy (`0 issue "digicert.com"`), then replay the own-site scan; optional `NVD_API_KEY`; staging Supabase; branch protection (needs GitHub Pro).

## Deferred from the Burp-parity review (2026-10-22)

- **Dalfox** (XSS depth): **done 2026-10-23.** Wired with a pinned, SHA-256-verified `v3.2.4` binary and a parser built from a real run's output (`src/worker/tools/dalfox.ts`, `dalfoxOutput.ts`, fixtures in `fixtures/dalfox/`), plus a `tool-integration.yml` job running the real binary. See `docs/BURP-PARITY.md` for the exit-code bug this caught.
- **strix / cairn / credentialSpray**: **owner decision made 2026-10-23 — leave `not_configured`, do not market.** Pinning real versions and verifying in CI is deferred again: strix needs Docker + an LLM key and real spend per run; cairn needs its AGPL subprocess-isolation review actually carried out, not just planned; credentialSpray needs a real sacrificial login target. Re-pin `strix.ts`/`cairn.ts` to real existing tags (`v1.x` / `v0.2.1`, not the nonexistent `v0.5.0`/`v1.0.0`) before any future attempt. See `docs/BURP-PARITY.md`.
- **Triage benchmark**: **harness built 2026-10-23**, still manual. `npm run bench:triage` (`bench/triage/`) runs the real triage pipeline against a labeled fixture set and reports precision/recall; not wired into CI yet (needs a model credential there). See `docs/AI-TRIAGE-DESIGN.md`.
- **Own-probe OOB**: a native interactsh client (RSA key exchange, AES polling) so `replayProbe` can confirm blind SSRF. Still not started.
- **OAuth/MFA flows, two-session IDOR, further logic checks**: design against real test targets first. Still not started.

## Deferred from uptime monitoring

- **Native Hebrides monitoring (Phase 2):** own checker so it is a sellable product (HTTP, latency, TLS expiry, 1 to 5 minute interval, incident history) behind the same `UptimeProvider` interface; needs a reliable scheduler (Azure Container Apps scheduled job or `pg_cron`), SSRF validation and an uptime-commitment wording review first.
- **Recreate a monitor deleted in UptimeRobot** without disconnecting: the card marks it "Not found", but `createMonitorsForTargets` still treats the stored row as existing.
- **Real-account verification** of the UptimeRobot v3 client (see above).

