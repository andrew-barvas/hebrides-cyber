# Next steps — session handoff

**Last updated: 2026-10-06.** Read this first in any new session (local or
cloud), after `CLAUDE.md` and `docs/SCANNER-CONVENTIONS.md`. It says where
things stand, the rules that kept biting, the plan in order, and what only
the owner can do.

To resume in a cloud session: open the repo `andrew-barvas/hebrides-cyber`,
branch from `master`, and prompt *"Read hebridescyber-app/docs/NEXT-STEPS.md
and implement plan item N."* Do one item per session.

## Where things stand

Everything below is merged to `master`, passed CI, and is deployed.
Database migrations: files exist through **050**; the next free number is **051**. **Apply 050 first, today:** until it is, `scans.status` rejects `queued`, so every dashboard scan stays "not started" and every `POST /api/v1/scans` fails (it is one `ALTER TABLE`, safe to paste into the Supabase SQL editor on its own). Deploys now apply pending files through `src/scripts/apply-migrations.ts` (ledger table `schema_migrations`, checksum drift check). **One-time step:** production was migrated by hand, so run the Deploy workflow manually (workflow_dispatch) with `baseline_up_to` = `047` before the next push to master, otherwise the migration job refuses the unrecorded database and blocks the deploy (048 to 050 are then applied by the normal migration step; until they are, deletion requests fall back to the audit row and email, and attack-surface alerts do nothing).

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
| GitHub Actions workflow security scanning | `src/worker/tools/workflowSecurity.ts` wraps the real zizmor tool (PyPI, pinned `1.30.1`) over the connected repo's `.github/workflows/` — script injection, insecure `pull_request_target`, unpinned actions, excessive permissions, secret exposure. `workflowSecurityCatalog.ts` maps all 40 real audit idents to 7 categories; full + osint profiles, same repo gating as `sast.ts` |

Coverage floor (`vitest.config.mts`): **71 / 64 / 73 / 72** (statements /
branches / functions / lines). Lint: 0 errors (36 known warnings).

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

- **Crawler (E-70):** login recording for the signed-in crawl (slice 1 uses a saved cookie/Basic credential, see `docs/AUTHENTICATED-CRAWL.md`); JS-rendered link discovery beyond the Next.js build manifest; per-page SRI/cookies for pages behind forms.
- **PR dependency checks (E-71):** lockfile-less PRs (manifest-only changes); a GitHub App for comments on fork PRs; pinning a finding to the changed line.
- **Benchmark (E-73):** DNS, ports, recon and the extended tools are not benchmarked; `knownIssues` lists the tracked defects.
- **Cross-site findings (E-74):** no authenticated e2e yet.
- **Duplicates:** `EQUIVALENCES` covers only confident id mappings; extend it as real nuclei/ZAP output confirms more. Injection findings need url+parameter evidence in their checkIds before they can be matched.
- **SAST (E-69):** Koa `ctx`, FastAPI typed params, more languages.
- **Emerging threats:** WordPress plugin matching; re-alert when "possibly affected" becomes "affected".
- **RLS tests:** extend the matrix to ticket_integrations, sla_policies, organisations/RBAC, report_shares.
- **e2e:** `/account`, `/admin`, `/dashboard/assets|sla|integrations`, the Fix Wizard and `/diff` are not covered signed-in.

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

Not doing: MFA bypass, JWT forging, CSRF bypass, gRPC fuzzing (attacks, not scanning); SSRF callbacks (needs an owner decision on hosting an out-of-band endpoint).

**Owner decisions needed:** whether AI fix, API keys, share links and tickets should be paid-only (no page promises them for a tier, so gating them is new policy).

**Done, 2026-10-13:** the six still-unwired library modules (`rbac.ts`, `scimProvisioning.ts`, `mspPortal.ts`, `customScanPolicies.ts`, `riskScoring.ts`, `graphqlApi.ts`) deleted from `src/` entirely, along with their tests — none had a live importer. Coverage floor lowered to the measured value after removing their tests.

**Migrations `034_organizations.sql`/`035_rbac.sql`/`036_sso_providers.sql`/`037_ip_allowlist.sql` build the schema these modules would have used** (`organizations`, `org_members`, `rbac_permissions`, `sso_providers`, `ip_allowlist` — the last is a different table from the live per-API-key `ipAllowlist.ts`/`api_keys.allowed_cidrs`, despite the name). None of the four tables are referenced anywhere in `src/` or `tests/db/`, so the feature itself was never wired — but **the owner has confirmed 034-037 are applied to the real Supabase project**, so unlike `ssoSaml.ts`/`orgModel.ts`/`cicdSdk.ts` the migration files stay. They document real, already-applied schema; only the application code that would have used it was dead.

## Owner actions pending (not code)

In order of impact:

1. **Stripe price IDs (E-07)**: paid sign-up is impossible until `STRIPE_PRICE_*` are set; `/api/health` stays "degraded".
2. **Sentry DSN (E-03)**: failed scans are invisible in production without it.
3. **Restore drill (E-13 / LIVE-4)**: restore a backup into a scratch Supabase project and record the result in `BACKUP-RESTORE.md`; consider Supabase Pro for point-in-time recovery.
4. **Deploy secrets**: `DATABASE_URL` (then run Deploy via workflow_dispatch with `baseline_up_to=047` once) and `SITE_URL` = `https://www.hebridescyber.co.uk`, so migrations and the post-deploy health check actually run.
5. **Publish the GitHub Action** from a public repository (this repo is private, so customers cannot `uses:` it); until then the CI templates in item 2 are the supported route.
6. **Domains**: register `hebridescyber.com` defensively; optionally a `security@hebridescyber.co.uk` alias for `security.txt`.
7. **ToS solicitor review** (BETA-B1).
8. **NCSC replacement campaign**: run `sql/seed/002_ncsc_web_check_retirement_post.sql` in the Supabase SQL editor (publishes the blog post), then send/post the drafts in `marketing/16-ncsc-replacement-campaign.md` (email sequence, LinkedIn, Google Ads, agency outreach).
9. DNS **CAA** record at GoDaddy (`0 issue "digicert.com"`), then replay the own-site scan; optional `NVD_API_KEY`; staging Supabase; branch protection (needs GitHub Pro).
