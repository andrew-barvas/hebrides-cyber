# Post-merge integrity and future-proofing audit (2026-11-02)

Scope: the scanner, Lookout (managed exposure review) and Exploit (P-07), after
the wave of merges from 2026-10-30 to 2026-11-02 (#140 to #178). Audited at
master `2bf9cd4`. This was a read-and-report pass. The only code-adjacent change
is in this PR: `SCANNER-INVENTORY.md`'s stale pins and its wrong migration
number. Everything else is listed below with a suggested fix.

Open work that this audit allows for, so it is not reported as missing:
#152 (ZAP passive), #155 (custom nuclei, migration 066), #179 (fix-first list,
067), the P1-4 M365 worktree (068), P1-3 service CVE (069, PR not yet open),
#181 (Lookout deep TLS and metadata).

## What checked out

- **Tool wiring.** Every `EXTENDED_TOOL_NAMES` entry has a checkId prefix in
  `EXTENDED_TOOL_PREFIXES` (or an alias: `http-probe` for httpx, `crawl.auth.`
  for authCheck), with one exception (finding H3). `full` is derived and
  excludes `OFFENSIVE_ONLY_TOOLS` and `EXCLUDED_FROM_FULL`. A bundle over
  `exposure` cannot add a tool (`resolveToolConfig`).
- **Map keys.** All 104 `attackMap.ts`, 178 `compliance.ts` and 175
  `fixDifficulty.ts` keys match a checkId that some check emits, directly or
  through a template (`malware.${rule}`, `dependency-manifest.${slug}`,
  `jwt-analysis.${type}` and others). The one dead key is L3.
- **Pins.** `scheduled-scans.yml` and `tool-integration.yml` carry identical
  versions and SHA-256s for every release asset, and the ZAP image digest and
  the cmsmap commit match too.
- **Exploit gate.** `run-queued-scan-jobs.ts:254` gates on
  `enablesOffensiveTools()` (derived from the resolved tool map, so it covers
  `ai-pentest` and bundle overrides), requires Tier A through `planAccess.ts`
  plus a current `offensive_scan_authorizations` row, runs after domain
  verification, fails closed on any read error, downgrades to `safe` and
  audits `offensive_scan.refused`/`.ran`. The consent route requires a session
  (not an API key), a monitored target and Tier A.
- **Lookout no-payload promise.** nuclei's non-intrusive mode (`-etags` with 24
  excluded categories, `-ni`) and `isNonIntrusiveProfile` turning off
  proof-of-exploit re-checks match the plan. The base suite's five
  dummy-credential login POSTs (`businessLogic.ts:476`) are disclosed in the
  copy (`marketing/17-…md:59,117`) and tracked as OT-43.
- **Orphans.** No module in `src/lib`, `src/worker`, `src/scripts` or
  `src/components` is imported only by its own test. No duplicate of a
  scanner module was left behind by the merges.
- **Migration 065.** It widens all three `scan_profile` CHECKs idempotently,
  and the values match the `ScanProfile` union.

## Findings, by severity

### High

**H1. `softwareCveDb` reports an NVD or WPScan failure as a clean "checked"**
(CLAUDE.md rule 7).
`src/lib/scanners/softwareCveDb.ts:63,141,157` return `null` on failure;
`:89` and `:179` turn `null` into `[]`; `:293` returns `status: "checked"`.
`:86` also returns `[]` when `WPSCAN_API_TOKEN` is unset.
- **Why it matters:** an NVD 403/429/503 (common: these calls send no API key)
  makes every `softwareCveDb.*` finding for PHP, Apache and WordPress core
  disappear. `findingLifecycle` then marks them fixed and closes their
  tickets. They reopen on the next good lookup, which flaps SLA alerts.
- **Fix:** have the fetchers return `"failed"` distinct from `[]`. When any
  lookup failed, return `status: "error"` (or `"partial"`, which
  `BASE_NOT_RUN` already treats as not-run). Return `not_configured` when the
  token is missing. Pass `NVD_API_KEY` to the scanner (see L7). Longer term,
  route these lookups through P1-3's local CPE index (`cveIndex.ts`), which
  removes the live NVD dependency from scans entirely.

**H2. A Shodan InternetDB failure resolves `recon.shodan-cves`.**
`src/lib/scanners/recon.ts:66-84` folds "404, no data" and "5xx or timeout"
into `null`, and `:170` still returns `status: "checked"`.
`src/lib/scanners/index.ts:655-665` then emits no `recon.shodan-cves`.
- **Why it matters:** this is the same false-fixed path as H1, for the
  finding Lookout leans on for "known CVEs on exposed IPs".
- **Fix:** return a `shodanLookupFailed` flag, as crt.sh already does with
  `ctLookupFailed`. Let `scanCoverage` treat `recon` as partial for
  `recon.shodan-cves` when it is set. A per-check incomplete list, like P1-3's
  `incompleteChecks` mechanism for extended tools, generalises this to base
  checks.

**H3. API-spec injection findings are not recognised as extended-tool findings.**
`checkApiSpecInjection` (extended tool `apiSpecInjection`) emits
`api-spec.sqli`, `api-spec.sqli-path` and `api-spec.xss`
(`src/lib/scanners/apiSpec.ts:465,492,518`). The base `checkApiSpecPassive`
uses the same `api-spec.` prefix, and `api-spec` is not in
`EXTENDED_TOOL_PREFIXES` (`src/lib/extendedToolCheckIds.ts:17-56`).
- **Why it matters:** `isExtendedToolFinding("api-spec.sqli:…")` is false.
  So `canDetectFromResults` (`findingLifecycle.ts:125`), which drives the
  dashboard and report diffs (`scanReport.ts:146`, `dashboard/page.tsx:83`,
  `DiffView.tsx:84`), shows a SQL injection as **fixed** after any on-demand
  `safe` scan. `ScanReportView.tsx:721` also offers a retest, which
  `retest-finding.ts:78` accepts and which can only ever say "fixed". The
  stored lifecycle row is correct, because `findingLifecycle.ts:357` uses the
  real origin. The existing test (`findingLifecycle.test.ts:65`) passes
  `fromExtended=true` by hand, so it never exercises this path.
- **Fix:** add a check-level list beside the prefix list, such as
  `EXTENDED_CHECK_BASES = ["api-spec.sqli", "api-spec.sqli-path", "api-spec.xss"]`,
  and match it in `isExtendedToolFinding`. Do not rename the checkIds, which
  would break continuity. Add a test asserting every `EXTENDED_TOOL_NAMES`
  entry maps to at least one recognised prefix or base.

**H4. The scanner-tool auto-update workflow cannot push.**
The only run of `scanner-tool-updates.yml`
([run 41363615029](https://github.com/andrew-barvas/hebrides-cyber/actions/runs/41363615029),
2026-11-01) failed on all 10 update jobs at `git push`, with "Invalid username
or token". #170 to #178 were opened by hand. The badsecrets and postgrest bumps
were never opened. `report-errors` (`scanner-tool-updates.yml:147-150`) runs
only on lookup errors, so a push failure raises no issue.
- **Why it matters:** pin freshness, the main future-proofing mechanism for
  the tool suite, is not running. The next cron run (Tuesday 05:41 UTC) will
  fail the same way.
- **Fix:** owner rotates `GH_PAT` with `contents:write` and
  `pull-requests:write` on this repo (OT candidate). Extend `report-errors`'s
  condition to `needs.update.result == 'failure'`.

### Medium

**M1. Six tool bumps merged together and have not run together on master.**
nuclei v3.3.9 → v3.11.1, httpx v1.6.10 → v1.12.0, subfinder, trivy, opengrep
and zizmor merged within 40 s at 22:57 on 2026-11-02. Each PR's
`integration` job passed on its own, but the last master
`tool-integration.yml` run (12:19) and the last scheduled scan (10:51) both
predate the merges.
- **Fix:** dispatch `tool-integration.yml` on master now, and check the next
  scheduled scan's verification artifact. nuclei's eight-minor jump is the one
  to watch, because the `exposure` profile's safety depends on `-etags`/`-ni`
  behaving the same.

**M2. Binary-backed tools in `full` that have no real-binary integration test**
(rule 15): subfinder (`subdomains`), testssl.sh (`deepTls`), gitleaks
(`secretScan`), trivy (`trivyImage`/`trivyConfig`), opengrep (`sast`), zizmor
(`workflowSecurity`) and prowler.
`tool-integration.yml:335-383` only checks the installed version for most of
these. opengrep has no install check there at all (`sast-rules.yml` tests the
rules, not the pinned binary). The zizmor check (`:374`) prints the version but
never asserts it.
- **Fix:** add a hermetic fixture repository (a planted test secret, a
  Dockerfile on an old base, a workflow with an injection pattern, a vulnerable
  `package-lock.json`) and run gitleaks, trivy, opengrep and zizmor against it
  in `tool-integration.yml`. Give testssl.sh and subfinder the local test app
  and a recorded fixture. Until then, list them in `EXCLUDED_FROM_FULL` or
  record the exception in SCANNER-CONVENTIONS.

**M3. Wayback CDX failure resolves `wayback-discovery.live-path:*` findings.**
The design is documented at `src/lib/scanners/waybackDiscovery.ts:24-29`
("degrades to a clean checked"), but it contradicts rule 7 for findings
already open.
- **Fix:** return `status: "partial"` when the CDX call fails and earlier
  results exist, or always on failure. `BASE_NOT_RUN` already protects open
  findings in that case.

**M4. Static "risky version" thresholds are stale and gate the CVE lookup.**
`src/lib/scanners/fingerprint.ts:157-162` hard-codes major versions: PHP < 8
(8.0 and 8.1 are end-of-life too), Angular < 15 (anything below 19 is now out
of support), WordPress < 6. `softwareCveDb` only runs for software on this
list (`softwareCveDb.ts:262-270`), so PHP 8.1 never gets an NVD lookup.
- **Fix:** derive "risky" from `endOfLife.ts`'s endoflife.date results, or
  from the P1-3 CVE index, rather than a hand-set major. Failing that, add a
  dated test that fails when the table is more than six months old.

**M5. Exploit authorisations never expire by default.**
`src/pages/api/account/offensive-authorization.ts:25,83` and
`src/lib/offensiveAuthorization.ts:111` default `expires_at` to `null`, and a
date in the past is accepted. `EXPLOIT-PRODUCT-PLAN.md:155` requires the
authorisation to expire with the engagement window. The Tier A path is live
today.
- **Fix:** require `expiresAt`, in the future and at most N days out (for
  example 30), when recording. Show the expiry in the UI. Consider a one-off
  backfill that gives existing null rows an expiry.

**M6. Lookout: findings from tools outside a target's current profile never resolve.**
`isCovered` (`findingLifecycle.ts:111`) needs the source tool to have
completed. A target moved from `full` to `exposure` keeps its ZAP, gospider,
sqlmap and similar findings open forever. Those findings feed the fix-first
list (#179) and the Lookout report, which promises only exposure-profile
checks.
- **Fix:** in `estatePriority`/`loadFixFirstList` and the Lookout report, flag
  or exclude findings whose source is not in `resolveToolConfig(currentProfile)`
  as "not re-checked by this service". Alternatively, add an explicit "retire
  on profile change" lifecycle event, recorded as bookkeeping like the
  consolidation merge, not as a fix.

**M7. Migration numbering is fragile.**
Master ends at 065. 066 is #155 (draft), 067 is #179 (draft), 068 exists only
in the uncommitted `p1-m365-posture` worktree (no branch pushed), and 069 is
P1-3. `tests/db/migrations.db.test.ts:24` allows only gap 23, so 067 or 069
landing first fails db-tests ("migration 66 is missing"). Rule 24 says
`KNOWN_GAPS` may only shrink, so a temporary gap entry is not an option.
- **Fix:** merge in numeric order, or have whichever lands first take the next
  free number at merge time (the `/migration` skill already says "take the
  next free number"). Push the 068 work to a branch so it cannot be lost.

**M8. Lookout plan and docs are stale after #144 merged.**
`docs/DEFENSIVE-ASSESSMENT-PLAN.md` still calls #144 a draft at lines 7, 164,
168, 323-325, 398 and 489, and so does `docs/OWNER-TODO.md:668`. Line 164 says
migration 064 (it is 065). Line 69 cites `scheduled-scans.yml:489` for ZAP (now
`:541`). Line 197 says `full` includes injection testers "until Q1b lands";
Q1b landed in #137. The copy's `[VERIFY]` markers at
`marketing/17-…md:40,45` are now satisfied.
- **Fix:** do one docs pass after #152 and #181 settle, since both edit the
  same rows. It is left out of this PR to avoid conflicts with them.

**M9. Node version drift.**
`package.json` engines say `>=22`, and `.nvmrc`, every workflow and the
Dockerfile use 22. The local machine this audit ran on has Node 20.19, which
reached end of life on 2026-04-30. Node 22 itself leaves maintenance on
2027-04-30.
- **Fix:** upgrade local machines to 22 now (OT candidate). Plan the move to
  Node 24 before April 2027: `.nvmrc`, `engines`, `node-version:` in each
  workflow, the Dockerfile, and the Azure SWA Functions runtime setting.

### Low

- **L1. `SCANNER-INVENTORY.md` pins went stale with the auto-bumps.** nuclei,
  subfinder, trivy and opengrep are **fixed in this PR**.
  `scannerToolUpdates.ts:173` (`applyUpdate`) rewrites only workflows. Either
  have it rewrite the inventory's "pinned `x`" too, or have the inventory point
  at the workflow instead of repeating versions.
- **L2.** `SCANNER-INVENTORY.md:34` said `exposure` was storable since
  migration 064. **Fixed in this PR** (065).
- **L3. Dead map key:** `whatwaf.waf-bypass` (`compliance.ts:371`,
  `fixDifficulty.ts:208`) is never emitted. Remove it, or note that it is
  reserved.
- **L4. Fix-first reads the WAF name from display text (#179).**
  `estatePriority.ts` splits the WAF name out of the finding title
  `[WhatWaf] WAF detected: X` (`scanExecution.ts:601`). Renaming the title
  silently drops the WAF factor. Store the name in a structured field (H4
  evidence) and read that.
- **L5. ATT&CK is pinned to v17** (`attackMap.ts:17`), and the "re-check
  quarterly" step is manual. Newer Enterprise releases have shipped since.
  Add a scheduled job that diffs `ATTACK_TECHNIQUE_IDS` against MITRE's STIX
  bundle and flags revoked or deprecated IDs.
- **L6. endoflife.date legacy API.** `endOfLife.ts:60` and
  `dockerBaseImage.ts:49` use `/api/<product>.json`, while upstream now
  documents `/api/v1/`. Failures already surface as `status: "error"`. Migrate,
  and add a recorded-fixture contract test.
- **L7. No NVD API key on scanner calls.** `cvssEnrich.ts:27` and
  `softwareCveDb.ts:28` send none, and `scheduled-scans.yml` does not pass
  `NVD_API_KEY`. Only `emerging-threats.yml` uses it, which feeds H1.
- **L8.** `NOT_AUTOMATED` (`scannerToolUpdates.ts:94`) omits cmsmap's
  git-commit pin, so nothing reports it as unwatched.
- **L9. Stale comment.** `scanProfiles.ts:213` says `ai-pentest` is "gated to
  Agency tier". It in fact needs Tier A plus an authorisation, through
  `enablesOffensiveTools`, which is stricter.
- **L10. Majors are never proposed.** Dependabot ignores every semver-major npm
  bump (`.github/dependabot.yml`), so majors (Next, TypeScript, Vitest, the
  Stripe SDK and its pinned `apiVersion: "2024-06-20"` in `stripeClient.ts:19`)
  pile up unseen. Add a quarterly "majors review" issue, or a scheduled
  `npm outdated` report.

## Third-party data sources

| Source | Used by | Fallback | Failure surfaced? |
|---|---|---|---|
| NVD CVE API 2.0 | `softwareCveDb`, `cvssEnrich`, emerging threats, newsletter; P1-3 nightly index | None. P1-3's local index will be one | **No for `softwareCveDb` (H1)**. CVSS enrichment is absent-when-failed (correct). Emerging threats use `ok:false` (correct) |
| CISA KEV | `threatIntel.ts` | 6 h in-process cache only | Absent means unknown, never "not exploited" (correct). Not reported to the operator, so the fix-first ranking quietly drops the KEV factor during an outage |
| FIRST EPSS | `threatIntel.ts` | None | Same as KEV |
| endoflife.date | `endOfLife.ts`, `dockerBaseImage.ts` | None | Yes (`status: "error"`), but on the legacy API (L6) |
| OSV.dev | `dependencyManifest` (`queryOsvBatch`), `webapp` (`lookupNpmCveIds`), fix PRs | None | Yes for manifests. `webapp` uses it for CVE-ID enrichment only, and returns `[]` on failure (acceptable) |
| WPScan API | `wpvdb.ts`, `softwareCveDb` WordPress core | None | Yes for `wpvdb` (`error` / `not_configured`). **No for WordPress core (H1)** |
| crt.sh | `recon`, `subdomains`, EASM sweep, lookalike monitor | One retry on 502/503 | Yes (`ctLookupFailed`, `ok:false`), and takeover checks skip on failure |
| Shodan InternetDB | `recon` | None | **No (H2)** |
| Wayback CDX | `waybackDiscovery` | None | **No, by design (M3)** |

Every source above is free and keyless (except WPScan and NVD's optional key),
and none has a contract test with a recorded response. One recorded-fixture
test per source would catch a schema change before customers do.

## Top 5 future-proofing investments

1. **One "lookup failed" contract for every third-party source.** Fix H1, H2
   and M3, and extend P1-3's `incompleteChecks` mechanism to base checks, so
   that "the API was down" can never resolve a finding. Add a lint-style test
   that fails when a scanner module returns `"checked"` from a code path that
   caught a fetch error.
2. **Move CVE matching off live NVD.** Finish P1-3's local CPE index and
   route `softwareCveDb`, Shodan CPEs and fingerprint versions through it.
   Drive "risky version" from endoflife.date plus the index instead of
   `KNOWN_RISKY` (M4).
3. **Make tool-pin automation self-healing.** Fix the token (H4). Have
   `tools:update` also rewrite `SCANNER-INVENTORY.md` (L1). Run a combined
   `tool-integration.yml` on master after any batch of bump merges (M1).
   Report push and update failures as an issue.
4. **A hermetic fixture repository for the repo-scanning tools** (M2), so
   that every binary in `full` has a real-binary test in CI and rule 15 holds
   without exceptions.
5. **A scheduled freshness job for the slow-ageing tables.** ATT&CK technique
   IDs against MITRE's STIX bundle (L5), `KNOWN_RISKY`/`CPE_ALIASES` age,
   endoflife.date API version, Node end-of-life dates (M9) and Dependabot's
   held majors (L10). It should open one issue a quarter, listing what is
   stale.

## Owner-only steps (OT candidates; not added to OWNER-TODO.md)

- **Rotate `GH_PAT`** with `contents:write` and `pull-requests:write` on
  `andrew-barvas/hebrides-cyber`, then re-run `scanner-tool-updates.yml` (H4).
  Check whether the Azure `GITHUB_PAT` app setting is the same token, since
  that one dispatches `on-demand-scan.yml`.
- **Add `NVD_API_KEY` as a repo secret** if it is not already one, and pass it
  to `scheduled-scans.yml` (L7, H1). Request a key from NVD if none exists.
- **Upgrade local machines to Node 22** (M9), and decide when to move
  production to Node 24 (the SWA runtime setting is owner-only).
- **Decide the default expiry for Tier A offensive authorisations** (M5),
  and whether existing open-ended rows get one.
- **Decide how Lookout treats findings from tools outside the `exposure`
  profile** on migrated targets: hide them, label them, or retire them (M6).
- **Dispatch `tool-integration.yml` on master** after the 2026-11-02 bump
  batch, and check the next scheduled scan's verification artifact (M1).
  Anyone with Actions access can do this.
