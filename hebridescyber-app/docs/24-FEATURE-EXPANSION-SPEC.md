# 24-feature expansion spec

Design for the 24 features requested across Platform / Scanning / Reporting /
UX / Business / Community. Strictly additive to the existing architecture —
Next.js API routes, the `scan_jobs` + `claim_scan_job()` Postgres queue,
GitHub Actions runners, the `Finding` type, the `checkId` taxonomy,
`scoreFromFindings()`, and `compliance.ts`. No Azure Functions, no
Redis/BullMQ, no second queue/orchestrator, no parallel scanning pipeline.

This is a design document, not a build order — nothing here has been
implemented. Treat it the way `docs/ENHANCEMENTS.md` entries are treated:
scope to reference when deciding what to build next, not a commitment.

## Relationship to the tool-integration discussion earlier in this session

This spec was requested immediately after designing the integration of
Gospider, Kiterunner, Arjun, Dalfox, Gitleaks, WPScan, WhatWaf, Photon,
CMSmap, and extended nuclei template packs. Rather than re-litigate that as
a separate plan, its tool work is folded into the features below that
actually need it:

- **#3/#4 (Scan Profiles/Bundles)** carry the per-tool enable/timeout/depth
  config and the safe-vs-full gating logic that work needed anyway.
- **#5 (API Schema Import)** is where Kiterunner, Arjun, and Dalfox attach.
- **#7 (CMS Targeted Scanning)** is where WPScan (CLI) and CMSmap attach.
- **#8 (OSINT Report)** is where Gospider and Photon attach.
- Nuclei template-pack expansion and WhatWaf's WAF-presence signal are
  folded into #6/#14 rather than getting their own numbered feature.
- **Gitleaks needs no new integration** — `src/lib/scanners/secretScan.ts`
  already wraps it. The real, pre-existing gap is that
  `.github/workflows/scheduled-scans.yml` never actually installs the
  `gitleaks` binary or `testssl.sh` despite `CLAUDE.md` and
  `docs/architecture.md` claiming it does, so `secretScan.ts` and
  `deepTls.ts` silently return `not_configured` on every real scheduled
  scan today. That's a bug fix, not a feature — worth doing in the Q1
  CI-plumbing pass regardless of which numbered feature ships first.
- **Correction on the stated tool inventory**: "Trivy" is listed in this
  task's premise as already integrated. It isn't — grepped the whole repo;
  the closest thing is `dockerBaseImage.ts`/`dependencyManifest.ts` using
  OSV.dev + endoflife.date, not Trivy. None of the 24 features below
  depend on Trivy specifically, so this doesn't change any design, but the
  premise is worth correcting rather than quietly building on a false
  assumption.

## Cross-cutting changes (shared by multiple features below)

Introduced once, referenced by number from the features that use them.

| Change | What | Used by |
|---|---|---|
| `Finding.fixDifficulty?` | New optional field: `"trivial" \| "easy" \| "moderate" \| "hard"` | #10, #15 |
| `Finding.estimatedFixMinutes?` | New optional field: `number` | #11, #13, #15 |
| `ComplianceFramework` union | Grows from `"cyber-essentials" \| "owasp-top-10" \| "cis-controls-v8"` to add `"iso-27001" \| "pci-dss" \| "nis2" \| "dora"` | #12, #20 |
| `src/lib/scanProfiles.ts` (new) | `ScanProfile = "safe" \| "full" \| "api" \| "cms" \| "osint"`, a config table of which extended tools each profile runs, and `resolveToolConfig({ profile, bundleOverrides })` | #3, #4, #5, #6, #7, #8 |
| `ExecuteScanOptions` | `runExtendedTools?: boolean` replaced by `profile?: ScanProfile` (back-compat: `true` → `"full"`, `false`/absent → `"safe"`) | #3 |
| `claim_scan_job()` | Extended a third time (same "drop, recreate" pattern as `010_claim_scan_job_scan_id.sql`) to also return `scan_profile` | #3 |
| `CATEGORY_LABELS` (`ComplianceTrend.tsx`) | New entries: `wpscan`, `cmsmap`, `gospider`, `photon`, `kiterunner`, `arjun`, `dalfox`, `osint`, `openapi`, `asset-inventory` | #5, #7, #8, #1 |
| New migrations (numbered from `020_`, actual numbers depend on what's landed first) | `020_scan_profiles`, `021_scan_bundles`, `022_api_specs`, `023_asset_inventory`, `024_team_roles_extended`, `025_managed_review_requests`, `026_partner_clients`, `027_charity_verification`, `028_workshops`, `029_cyber_index_snapshots` | listed per-feature below |

All new tables follow the repo's existing conventions: RLS enabled,
service-role-only writes where the data is security/billing-sensitive
(mirroring `ticket_integrations`/`repo_connections`), owner-scoped SELECT
policies extended for team members using the same `caller_team_ids()` /
`is_caller_team_owner()` SECURITY-DEFINER pattern `007_teams.sql` already
established to avoid RLS recursion.

---

## PART 1 — Platform Features

### 1. Asset Inventory (domains, subdomains, CMS type, cloud hints)

**A. Backend**
- Migration `023_asset_inventory.sql`: table `asset_inventory` (`id`, `owner uuid`, `target_url text`, `hostname text`, `kind text check in ('domain','subdomain')`, `cms_type text nullable`, `cloud_hints jsonb default '[]'`, `first_seen_at`, `last_seen_at`, unique `(owner, hostname)`). RLS: owner + team-member SELECT (same pattern as `monitored_targets`), service-role write only.
- Populated as a side effect at the end of `executeScan()`'s existing Phase 1.5 (report-build phase, already wrapped so a failure there can't flip scan status) — upsert from `results.subdomains.subdomains` (Subfinder, when it ran), `results.fingerprint.technologies` (CMS + cloud/CDN hints — `fingerprint.ts` already tags `category: "CDN"` entries like Cloudflare/Fastly/Azure CDN), and `results.recon` as fallback when Subfinder didn't run. No new GitHub Actions logic — it's a write inside the worker process that's already running.
- New `GET /api/asset-inventory` (session auth via `authenticateApiRequest`, RLS-scoped read).

**B. Frontend**
- New `AssetInventory.tsx` + `/dashboard/assets` page: hostnames grouped by parent target, CMS badge, cloud/CDN chips. Summary tile on `dashboard/page.tsx`. Mobile: table collapses to stacked cards under 640px, matching `FleetOverview.tsx`'s existing responsive pattern.

**C. CI/CD** — none new; runs inside the existing `npm run queue:run-worker` step.

**D. Score & Compliance**
- No effect on `scoreFromFindings` (inventory is metadata, not a vulnerability).
- One new low-severity, info-adjacent finding: `asset-inventory.new-subdomain:<host>` when a hostname appears for the first time — maps to a new `CIS_1` constant (`compliance.ts` currently starts at CIS Control 3; add `CIS_1: { framework: "cis-controls-v8", control: "CIS Control 1 – Inventory and Control of Enterprise Assets" }`).

### 2. Security Score Timeline (trend graph, deltas)

Mostly exists already: `ScoreTrend.tsx` + `clientScanHistory.ts` already chart `scan_results.score` over time, and `dashboard/page.tsx` already shows a score-delta tile. Scope this narrowly rather than rebuilding it:

**A. Backend** — none. `scan_results.score` + `created_at` already has everything needed.

**B. Frontend**
- New `/dashboard/scans/history` page: full history beyond `ScoreTrend.tsx`'s current ~20-point cap, with a date-range picker.
- CSV export of score history, reusing `export.ts`'s CSV-building pattern.
- Per-category sparkline breakdown reusing `ComplianceTrend.tsx`'s `categoryOf()`/`CATEGORY_LABELS` grouping, generalized to a small line per category rather than the current single bar list.

**C/D** — none; read-only view over existing data.

### 3. Scan Profiles (safe, full, API, CMS, OSINT)

The plumbing feature most others depend on.

**A. Backend**
- Migration `020_scan_profiles.sql`: `monitored_targets` gets `scan_profile text not null default 'full' check (scan_profile in ('safe','full','api','cms','osint'))`. `scan_jobs` gets nullable `scan_profile text` (an explicit override at enqueue time; null inherits from the target, or resolves to `'safe'` for on-demand jobs with no `monitored_targets` row, preserving today's passive-only on-demand behaviour by default).
- `claim_scan_job()` extended again to return `scan_profile` (same "drop function, recreate" approach `010_claim_scan_job_scan_id.sql` used, since `RETURNS TABLE` can't be widened with `CREATE OR REPLACE`).
- New `src/lib/scanProfiles.ts`:
  ```ts
  export type ScanProfile = "safe" | "full" | "api" | "cms" | "osint";
  export const SCAN_PROFILES: Record<ScanProfile, { tools: Record<string, boolean> }> = {
    safe:  { tools: {} },                          // base passive suite only
    full:  { tools: { /* every extended tool: true */ } },
    api:   { tools: { kiterunner: true, arjun: true, dalfox: true, zap: true, nuclei: true } },
    cms:   { tools: { wpscan: true, cmsmap: true, nuclei: true } },
    osint: { tools: { gospider: true, photon: true, subdomains: true } },
  };
  export function resolveToolConfig(profile: ScanProfile, bundleOverrides?: Record<string, boolean>) { ... }
  ```
- `ExecuteScanOptions.runExtendedTools?: boolean` → `profile?: ScanProfile`. `run-queued-scan-jobs.ts`'s `runOne()` computes `profile = job.scan_profile ?? (job.scan_id ? "safe" : "full")` instead of today's `!scanId`. `runExtendedTools()` in `scanExecution.ts` gates each entry in its `Promise.allSettled` array behind `resolveToolConfig(profile).tools.<name>` instead of running all 12 unconditionally.

**B. Frontend**
- Profile dropdown on `MonitoredTargets.tsx`'s add-target form and the "Run scan" flow.
- Profile badge on `ScanList.tsx`/`FleetOverview.tsx` rows.

**C. CI/CD** — `scheduled-scans.yml` still installs every binary unconditionally (cheap relative to a once-a-day run); `scanProfiles.ts` decides at runtime whether to invoke each one. `on-demand-scan.yml` is unaffected (`safe` profile, same as today).

**D. Score & Compliance** — no change to `scoreFromFindings` (profile only changes which findings *can* exist). Compliance coverage % naturally reflects a `safe`-profile scan's narrower surface; worth a UI note ("coverage reflects this scan's profile") rather than any scoring change.

### 4. Scan Bundles (combined scan types)

**A. Backend**
- Migration `021_scan_bundles.sql`: `scan_bundles` (`id`, `owner`, `name`, `base_profile text`, `tool_overrides jsonb default '{}'`, `created_at`) — owner-only RLS, service-role write (mirrors `repo_connections`). `monitored_targets` gets nullable `scan_bundle_id uuid references scan_bundles(id) on delete set null`; when set, it wins over the plain `scan_profile` column.
- `resolveToolConfig()` (from #3) merges a canned profile with `tool_overrides` (e.g. `{"sqlmap": false, "kiterunner": true}`).
- `GET/POST/DELETE /api/account/scan-bundles`.

**B. Frontend** — `ScanBundleEditor.tsx`: checklist of tool toggles seeded from a base profile, save-as-named-bundle; bundle picker next to the profile dropdown from #3.

**C/D** — same as #3 (bundles only gate which findings can occur, no scoring/compliance change).

---

## PART 2 — Scanning Features

### 5. API Schema Import (OpenAPI, Postman)

This is `docs/ENHANCEMENTS.md` E-33, made concrete.

**A. Backend**
- Migration `022_api_specs.sql`: `api_specs` (`id`, `owner`, `monitored_target_id uuid nullable`, `spec_format text check in ('openapi','postman')`, `source_url text nullable`, `raw_spec jsonb`, `uploaded_at`) — same "customer points us at a resource" shape as `repo_connections`.
- `POST /api/account/api-spec`: validates the upload parses as OpenAPI 3.x or Postman Collection v2.1 before saving (same verify-before-save precedent as `connect-repo.ts`/`ticket-integration.ts`).
- New `src/lib/scanners/apiSpec.ts` flattens the stored spec into `{ method, path, params, requestBodySchema }[]` — the seed URL/parameter list fed to Kiterunner, Arjun, Dalfox, and ZAP's active scan instead of relying solely on crawler discovery.
- `src/worker/tools/kiterunner.ts` (`kr scan <target> -w <routes-wordlist-from-spec> -x 20 -j`), `arjun.ts` (`arjun -u <target> -oJ <tmpfile>` per discovered endpoint), `dalfox.ts` (`dalfox url <target> --format json` per endpoint/param). All three follow the existing `execFile` + `AbortSignal`/`timeout` + ENOENT→`not_configured` contract from `SCANNER-CONVENTIONS.md`.
- checkId namespace: `openapi.<check-name>:<operationId>` (E-33's own proposed shape) for spec-vs-live mismatches (e.g. `openapi.missing-auth:<operationId>` when a spec declares `security` but the live endpoint returns 200 unauthenticated); `kiterunner.route-found:<path>`, `arjun.param-found:<path>:<param>`, `dalfox.xss:<url>` for the tool-native findings.
- Gated by `profile === "api"` (or a bundle override) via `scanProfiles.ts`.

**B. Frontend** — `ApiSpecUpload.tsx` in account settings (file upload or URL field); endpoint-count/auth-scheme summary on the scan report.

**C. CI/CD** — `apiSpec.ts` is a pure Node parser, no binary; Kiterunner/Arjun/Dalfox get install steps in `scheduled-scans.yml` (Kiterunner: download release binary; Arjun: `pip install arjun`; Dalfox: download release binary — all three follow the same install-unconditionally-gate-at-runtime approach as #3).

**D. Score & Compliance** — normal severity-based scoring. `openapi.missing-auth` → `OWASP_A01`; extend with PCI/ISO refs once #12 lands (`PCI_REQ8` — authenticate access to system components).

### 6. CMS Fingerprinting (WordPress, Joomla, Drupal, etc.)

Mostly exists (`fingerprint.ts` + `webapp.ts`'s CMS deep scan + `wpvdb.ts`). The new increment is making CMS identity a first-class routing signal rather than an implicit side effect.

**A. Backend**
- New `getCmsType(technologies): "wordpress" | "joomla" | "drupal" | "magento" | "ghost" | null` exported from `fingerprint.ts`, consumed by `scanExecution.ts` to decide whether WPScan/CMSmap (#7) run at all — skip entirely on a non-CMS target rather than running a CMS scanner against a target with no CMS.
- No schema change — `results.fingerprint.technologies` already carries the raw signal; this is a derived helper.

**B. Frontend** — CMS badge on `ScanList.tsx`/`FleetOverview.tsx` rows and a CMS status dashboard card (#14).

**D. Score & Compliance** — detection only, no new findings; feeds routing, not scoring.

### 7. CMS Targeted Scanning (WPScan, CMSmap)

**A. Backend**
- `src/worker/tools/wpscan.ts`: `execFile("wpscan", ["--url", target, "--format", "json", "--no-banner", "--api-token", process.env.WPSCAN_API_TOKEN])` — reuses the `WPSCAN_API_TOKEN` secret already wired into both workflows for `wpvdb.ts`. `cmsmap.ts`: git-clone-based install + `execFile("python3", ["cmsmap.py", "-t", target])`, same pattern as `commix.ts`'s no-official-package handling.
- Both gated: only invoked when `getCmsType()` (#6) is non-null, matches the tool's own scope (WPScan → WordPress only; CMSmap → any of the three), and `profile` is `cms` or `full`.
- checkIds: `wpscan.<finding-slug>:<key>`, `cmsmap.<finding-slug>:<key>`. WPScan's JSON `vulnerabilities` array (per plugin/theme/core) feeds `Finding.cveIds` directly.
- **Dedup with `wpvdb.ts`**: when WPScan CLI and `wpvdb.ts`'s API-based plugin-CVE match both fire for the same plugin, keep the WPScan finding (live-confirmed, richer) and suppress the `wpvdb.*` one — the same `supersedesReconSubdomains`-style filter `scanExecution.ts` already uses for Subfinder vs. `recon.ts`.

**B. Frontend** — no new page; findings flow through `FindingCard` as usual. Add `wpscan: "WordPress (WPScan)"` and `cmsmap: "CMS (CMSmap)"` to `CATEGORY_LABELS`.

**C. CI/CD** — install steps in `scheduled-scans.yml` (`gem install wpscan` or the `wpscanteam/wpscan` Docker image; git-clone CMSmap). Installed unconditionally per-run (cheap); gated at runtime by CMS detection + profile, so a `not_configured`/skipped result on a non-CMS target is expected, not wasted spend.

**D. Score & Compliance** — standard severity scoring; map to `OWASP_A06` (Vulnerable/Outdated Components), `CE_PATCHING`, `CIS_7`.

### 8. OSINT Report (Photon, Gospider)

**A. Backend**
- `src/worker/tools/gospider.ts` (`gospider -s <target> -c 5 -d 2 --json`, depth/concurrency from the profile's tool config) and `photon.ts` (git-clone install, `python3 photon.py -u <target> --json`), both discovery-only.
- Rather than one Finding per discovered URL (noisy, and would distort the additive score), raw output is stored as `results.extended.osint = { urls, emails, jsFiles, forms }` — the same "raw data lives in `extended`, only risk *signals* become Findings" split `nmap.ts`'s port list already uses. A small number of genuine findings come out of that data: `osint.exposed-endpoint:<url>` (a discovered URL matches a sensitive-path pattern `exposure.ts` didn't already catch), `osint.email-harvested:<email>` (info severity).
- Gated behind `profile === "osint"` or `"full"` — deliberately not on `safe`, since a deep crawl is slower/noisier than what a safe-profile customer should expect by default.

**B. Frontend** — new "Attack Surface" panel on the scan report: collapsible list of discovered assets, CSV-exportable (reuses `export.ts`'s pattern).

**D. Score & Compliance** — only the flagged risk-signal findings affect score. `osint.exposed-endpoint` → `CE_SECURE_CONFIG`/`OWASP_A05`, matching `exposure.exposed-file`'s existing mapping.

### 9. Critical Path Analysis (simple attack chain mapping)

Pure derived logic — no new scanner, no schema change (`ScanReport` is already a computed-on-read shape built by `buildScanReport()` in `scanReport.ts`, not its own table).

**A. Backend**
- New `src/lib/attackPathAnalysis.ts`: `computeCriticalPaths(findings: Finding[]): CriticalPath[]` where `CriticalPath = { title, narrative, findingCheckIds: string[], severity }`. A small hand-curated rule table matches *combinations* of checkId bases (e.g. `exposure.exposed-file:.git` + any `secretScan.*` → "an exposed `.git` directory could leak the credentials secret-scanning found"; `wpscan.vulnerable-plugin:*` + `headers.missing-critical` → "a vulnerable plugin combined with missing security headers increases exploit reliability"). Called once from `buildScanReport()` alongside the existing diff, stored as an additive `ScanReport.critical_paths` field.

**B. Frontend** — "Attack Chains" section on `ScanReportView.tsx`, rendered as a simple finding→finding→impact list (no diagramming library needed).

**D. Score & Compliance** — informational only for v1; deliberately **not** feeding an extra penalty into `scoreFromFindings` (the underlying findings are already scored individually — compounding would need real calibration, noted as a v2 idea in the roadmap, not built speculatively now). Chains surface each finding's *existing* compliance refs together; no new mapping needed.

---

## PART 3 — Reporting Features

### 10. Fix Difficulty Rating

**A. Backend** — `Finding.fixDifficulty?: "trivial" | "easy" | "moderate" | "hard"` (additive, same optionality precedent as `remediation`/`cveIds`). New `src/lib/scanners/fixDifficulty.ts`: `FIX_DIFFICULTY_MAP` keyed by checkId base, identical shape to `compliance.ts` (e.g. `"tls.hsts-missing": "trivial"`, `"headers.csp-absent": "moderate"`, `"sqlmap.sqli": "hard"`, `"secretScan.*": "moderate"`). Applied as the same kind of final pass as `getComplianceRefs()` — two more lines beside the existing compliance-pass call sites in `summariseResults()` and `scanExecution.ts`.

**B. Frontend** — a difficulty pill next to severity on `FindingCard`; a difficulty filter alongside the existing All/New/Fixed filter.

**D. Score & Compliance** — no effect on either; difficulty is about remediation effort, not risk.

### 11. Time-to-Fix Estimates

**A. Backend** — `Finding.estimatedFixMinutes?: number`, derived from `fixDifficulty` via a fixed lookup (`trivial→15, easy→60, moderate→240, hard→960`) rather than a second hand-maintained map — cheaper to keep consistent, and honest given these are rough estimates regardless.

**B. Frontend** — "~15 min" next to the difficulty pill; a per-scan "Est. total remediation time" stat (client-side sum over open findings, no new API).

**D.** — no effect on score/compliance.

### 12. Compliance Mapping extension (Cyber Essentials, ISO 27001, PCI DSS, NIS2, DORA)

Direct extension of `src/lib/scanners/compliance.ts`.

**A. Backend**
- `ComplianceFramework` grows from 3 to 7 values. New curated control constants, same non-exhaustive philosophy as the existing file: `ISO_A8` (Asset Management), `ISO_A9` (Access Control), `ISO_A12` (Operations Security), `ISO_A13` (Communications Security); `PCI_REQ4` (encrypt transmission of cardholder data — maps to TLS checks), `PCI_REQ6` (secure systems/applications), `PCI_REQ8` (authenticate access); `NIS2_ART21` (cybersecurity risk-management measures); `DORA_ART9` (ICT risk protection and prevention).
- `COMPLIANCE_MAP` entries get additional array elements (e.g. `"tls.no-https": [CE_SECURE_CONFIG, OWASP_A02, CIS_3, PCI_REQ4, ISO_A8, NIS2_ART21]`) — purely additive, no restructuring. `COMPLIANCE_FRAMEWORK_LABELS` and `ALL_CONTROLS_BY_FRAMEWORK` already derive from the map/union, so both update automatically.

**B. Frontend** — `ComplianceSummary` (`ScanReportView.tsx`) currently hardcodes the Cyber-Essentials-specific 5-theme breakdown; add a framework tab selector (CE / OWASP / CIS / ISO 27001 / PCI DSS / NIS2 / DORA), each new tab reusing `ComplianceTrend.tsx`'s already-generic `coverageForFindings()` (framework-parameterised, confirmed from the existing code). CSV export (`export.ts`'s `compliance_refs` column) needs no code change — it already serialises whatever's in `Finding.complianceRefs`.

**D. Score & Compliance** — compliance is a read over findings, never a scoring input; unaffected.

### 13. Executive Summary Mode

**A. Backend** — none new. `generate-report.ts` gets a `?mode=executive` query param producing a shorter `renderExecutiveReportHtml()` alongside the existing `renderReportHtml()`. A small `EXEC_IMPACT_MAP` (keyed by checkId base, same shape as the other curated maps) supplies one-line business-impact text for top findings, falling back to a generic severity-based line when unmapped.

**B. Frontend** — `ExecutiveSummaryView.tsx`: score, top 3 critical/high findings with business-impact text (no raw evidence/reproduction steps), the CE 5-theme snapshot, and the #11 total-remediation-time estimate. "Technical" / "Executive" tab on `scans/[id]/page.tsx`, sharing the already-fetched `ScanReport` — pure client-side view switch.

**D.** — display-only; no change to underlying values.

---

## PART 4 — UX & UI Features

### 14. Dashboard Cards (TLS grade, header compliance, CMS status, API health, cloud posture)

No TLS letter grade exists today (confirmed: only CSP has a grade in `headers.ts`). Define one for **display only**:

**A. Backend** — `computeTlsGrade(tls: TlsResult): "A" | "B" | "C" | "F"` in `tls.ts` (A: HTTPS + modern protocol + valid cert + adequate HSTS; F: not HTTPS; B/C in between). **Deliberately not fed into `scoreFromFindings`** — the same underlying facts are already penalised directly by existing `tls.*` findings, so treating the grade as a second scoring input would double-count and add a sixth inconsistent colour ramp to a codebase that already has five (`ScoreGauge`, `ScanList`'s `ScoreBadge`, `FleetOverview`'s `scoreColor`, `ProductPreview`'s `scoreColor`, admin's inline thresholds) disagreeing on their score bands. "Header compliance" reuses `headers.owasp` present/missing counts; "CMS status" reuses #6's `getCmsType()`; "API health" reuses #5's spec endpoint count + Kiterunner/Dalfox finding counts (only rendered when an API spec is connected); "Cloud posture" reuses the already-collected `cloudMisconfig.ts` public-bucket findings (not the CSPM cloud-*account*-access idea from `docs/ENHANCEMENTS.md` E-32, which is a structurally different, much larger product surface — out of scope here).

**B. Frontend** — `DashboardCard.tsx` primitive (icon, label, value, status colour), reused 5× on `dashboard/page.tsx` and `scans/[id]/page.tsx`. Mobile: horizontal scroll-snap row under 640px, consistent with the dashboard's existing responsive conventions.

**C/D** — none new; pure aggregation of already-collected data.

### 15. Fix Wizard (step-by-step remediation)

**A. Backend** — none. Groups a scan's open findings by `remediation` text + `fixDifficulty` (#10), ordered easiest/highest-impact first.

**B. Frontend** — `FixWizard.tsx`, a `?wizard=1` mode on the scan report. Each step reuses the existing `RemediationBody` renderer, `RetestFindingButton`, and `CreateTicketButton` — pure composition, no new endpoints. Mobile: single-column, swipe/tap next-previous.

**C/D** — none; wraps existing data and existing action buttons.

### 16. Scan Replay ("rerun with same settings")

**A. Backend** — `POST /api/scans/[id]/replay`: reads the original scan's `target_url` and (once #3 lands) its `scan_profile`/`scan_bundle_id`, then inserts a `scans` row + `scan_jobs` row exactly like `retest-finding.ts` already does structurally, for the whole scan rather than one checkId. Reuses `authenticateApiRequest`, `rateLimit.ts` (new `"scan-replay"` namespace), `validateNoSsrf`, `isDomainVerified` — the same guard stack `run-scan.ts` step 2 already has.

**B. Frontend** — "Replay this scan" button on `scans/[id]/page.tsx`, polling the same queued→running→completed states the dashboard already renders.

**C. CI/CD** — flows through the existing on-demand/scheduled dispatch paths unchanged.

**D.** — unaffected; it's just another scan.

### 17. Diff View (new vs fixed findings)

Already exists in narrow form (`FindingsFilter`, `findingsDiff.ts`, New/Fixed tiles on the dashboard). The new increment: comparing any two *arbitrary* past scans, not just latest-vs-previous.

**A. Backend** — none. `diffFindings(current, previous)` already operates on any two `Finding[]` arrays; only the caller needs to pick an arbitrary pair (via `clientScanHistory.ts`'s already RLS-scoped scan list) instead of always "latest vs previous."

**B. Frontend** — `DiffView.tsx`: scan-picker dropdown + side-by-side (stacked on mobile) comparison, either a modal from the report or a `/dashboard/scans/[id]/diff` page.

**D.** — read-only comparison; no new scoring logic.

---

## PART 5 — Business Features

### 18. Team Accounts (admin, developer, auditor)

Extends `teams`/`team_members` (`007_teams.sql`) rather than building new infrastructure. Today, team members are **strictly read-only by design** ("This does NOT touch how scans are created" — the migration's own header) — this feature is a deliberate, explicit widening of that scope for two of the three new roles.

**A. Backend**
- Migration `024_team_roles_extended.sql`: widen `team_members.role`'s check constraint from `('admin','member')` to `('admin','developer','auditor','member')`; `'member'` stays the default for existing rows, no backfill needed.
- New `caller_can_act_for(target_owner uuid) returns boolean`, a SECURITY DEFINER function mirroring `is_caller_team_owner()`'s RLS-recursion-safe pattern: true when `target_owner = auth.uid()` or the caller is a `team_members` row for that owner's team with `role IN ('admin','developer')`.
- `developer`: may call `POST /api/scans/[id]/replay` (#16) and `POST /api/scans/[id]/retest-finding` and create tickets on the owner's targets — each of those routes adds one extra check via `caller_can_act_for()`. May not touch billing, API keys, webhooks, or team membership.
- `auditor`: read-only like today's `member`, plus access to Executive Summary (#13) and Compliance exports (#12) without raw technical evidence — a `viewMode` flag threaded through the existing report-fetch, not a new endpoint.
- `admin`: unchanged (invite/remove members).

**B. Frontend** — extend `TeamSection.tsx`'s role dropdown to the four roles; gate the replay/retest/ticket buttons in `ScanReportView.tsx` on the caller's server-resolved role (never trust a client-only check — the API routes enforce independently regardless).

**D.** — pure access control; no scoring/compliance effect.

### 19. Managed Security Add-on (manual review workflow)

A human-in-the-loop layer, shaped like `ticket_integrations`/`ticket_links` — no new scanning. Deliberately minimal: this is a **solo-operator** feature (per `docs/ENHANCEMENTS.md`'s own "solo-blocked" category), so the workflow is a status field and a notes field, not case-management tooling.

**A. Backend**
- Migration `025_managed_review_requests.sql`: `managed_review_requests` (`id`, `owner`, `scan_id`, `status text check in ('requested','in_review','completed')`, `requested_at`, `assigned_analyst text nullable`, `completed_at`, `analyst_notes text nullable`, `delivered_report_url text nullable`).
- `POST /api/account/managed-review` (customer-facing, Agency-tier-gated the same way `MonitoredTargets.tsx` gates today per E-01). `PATCH /api/admin/managed-review/[id]` (operator-only, reuses `requireAdmin`).

**B. Frontend** — "Request expert review" button on the scan report (Agency-tier only, mirrors `hasTicketIntegration`-style gating), status badge; new admin-panel tab listing open requests.

**C/D** — no scanner involvement, no scoring/compliance effect, deliberately.

### 20. Security Certification Pack (CE readiness, ISO gap analysis, PCI web compliance)

Built entirely on #12 — no new scanning logic.

**A. Backend** — `POST /api/scans/[id]/certification-pack` (Agency-gated), same Playwright-`chromium` PDF pattern as `generate-report.ts`. One section per framework (CE/ISO/PCI), each showing coverage % and per-control pass/fail from `getComplianceRefs()`/`ALL_CONTROLS_BY_FRAMEWORK` (#12) directly — zero new compliance logic. Readiness verdict banded from coverage % (≥90% "Ready", 70–89% "Minor gaps", <70% "Significant gaps"), worded as an automated indicator, matching `ComplianceSummary`'s existing "never a certification claim" framing.

**B. Frontend** — "Download Certification Pack" button next to the existing PDF/CSV export, Agency-gated.

**D.** — consumes, doesn't extend, #12's mapping; no scoring effect.

### 21. Partner Portal (agencies managing multiple client sites)

Reuses the Agency plan's existing multi-target `monitored_targets` capability — the partner remains the sole `owner` of every target/scan, avoiding a second ownership hierarchy (which would be real architectural churn).

**A. Backend**
- Migration `026_partner_clients.sql`: `monitored_targets` gets nullable `client_label text` (free-text grouping); new `partner_clients` (`id`, `owner`, `client_label`, `contact_email text nullable`, `created_at`) for the portal's own client-directory UI. Matched by label value, not FK'd — a partner may label a target before formally adding a client record.
- `GET /api/account/partner-clients` (groups the partner's own targets/scans/scores by `client_label`); `POST/PATCH/DELETE` for the directory rows.

**B. Frontend** — `/dashboard/partner`: `FleetOverview.tsx` reused, grouped by `client_label` instead of one flat list; per-client score/finding-count summary; contact directory sidebar. Agency-tier only.

**D.** — same scans, same scoring; just regrouped in the UI.

---

## PART 6 — Community & Funding Features

### 22. Free Scans for Charities (limited profile)

Extends `freeTier.ts`, which today has exactly one bypass (`is_admin`).

**A. Backend**
- Migration `027_charity_verification.sql`: `users` gets nullable `charity_verified_at timestamptz`, set manually by an admin after off-platform verification (deliberately manual, same solo-operator reasoning as #19 — not an automated eligibility API).
- `isFreeTierExhausted()` gets a second bypass: `if (user?.charity_verified_at) return false`, but `run-scan.ts`/`v1/scans.ts` force `scan_profile: "safe"` (#3) on any `scan_jobs` insert for a charity-verified caller with no active subscription — so the exemption can't be used to get full active-tool scanning for free.

**B. Frontend** — "Register as a charity" link on `/pricing` (a contact-style form reusing `contact.ts`'s pattern, not self-serve); admin-panel action to set `charity_verified_at`.

**D.** — unaffected.

### 23. Local Cyber Workshops (content + scheduling)

`blog_posts` isn't the right fit — no scheduling/location/capacity fields, and mixing events into the blog table blurs two different read patterns.

**A. Backend**
- Migration `028_workshops.sql`: `workshops` (`id`, `slug unique`, `title`, `description_markdown`, `location`, `starts_at`, `capacity int nullable`, `signup_url text nullable`, `created_at`). `signup_url` points at an external form/Eventbrite-style tool rather than building RSVP/attendee management in-house — same "don't build tooling a one-person team doesn't need yet" reasoning as #19. Public read policy; writes via `POST/PATCH /api/admin/workshops` (`requireAdmin`).

**B. Frontend** — `/workshops` public page (upcoming/past split, same styling as `/blog`), cross-linked to #22's charity offer.

**C/D** — none; pure content, no scanner involvement.

### 24. Hebrides Cyber Index (anonymised regional statistics)

Aggregation over this operator's own already-collected customer scan history — not third-party data collection, so no new privacy surface beyond the existing ToS/Privacy policy (worth actually checking `/privacy` before shipping — a "money/time"-category dependency in `docs/ENHANCEMENTS.md`'s own vocabulary, not a code task).

**A. Backend**
- New `src/scripts/generate-cyber-index.ts` (same shape as `generate-daily-blog.ts` — a script run directly against Supabase by a scheduled workflow, matching the app's now-consistent "GitHub Actions running a script directly, no HTTP hop" pattern). Aggregates average score by month, most common open-finding categories (reuses `categoryOf()`'s checkId-prefix logic server-side), % of scanned targets missing HTTPS/critical headers, etc. — **k-anonymised**: only publishes a bucket when it covers at least a hardcoded minimum cohort size, never a single target's data.
- Migration `029_cyber_index_snapshots.sql`: `cyber_index_snapshots` (`period text`, `metrics jsonb`, `published_at`) — one row per period, not recomputed live on every page view.

**B. Frontend** — `/cyber-index` public page: stat cards + a trend chart (generalising `ScoreTrend.tsx`'s SVG approach to an arbitrary series), positioned alongside `/tourism`, `/churches`, `/local-trades` as a marketing/community-trust page.

**C. CI/CD** — new `.github/workflows/cyber-index.yml`, monthly cron, Node 22 + npm cache, `SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY` only.

**D.** — read-only aggregate reporting; no scoring/compliance effect.

---

## E. Minimal 12-month roadmap

No new infrastructure, no parallel pipelines, at any point. Each quarter is independently shippable and deployable on its own.

### Q1 — Foundation
- Fix the pre-existing `gitleaks`/`testssl.sh` install gap in `scheduled-scans.yml` (bug fix, not a feature, but blocks #7/#8/#12 from having real data to work with).
- **#3 Scan Profiles** + **#4 Scan Bundles** — the plumbing everything else in Q2–Q3 gates on.
- **#12 Compliance Mapping extension** (data layer only: new frameworks + `COMPLIANCE_MAP` entries; UI tabs can follow in Q2).
- **#10 Fix Difficulty** + **#11 Time-to-Fix** — cheap additive fields, no dependencies.
- **#6 CMS Fingerprinting** broadening (`getCmsType()`) — cheap, unblocks #7.

### Q2 — Scanning depth
- **#7 CMS Targeted Scanning** (WPScan CLI, CMSmap).
- **#5 API Schema Import** (spec parsing + Kiterunner/Arjun/Dalfox).
- **#1 Asset Inventory**.
- **#14 Dashboard Cards** (TLS grade display, CMS status, API health — all now have real data behind them).

### Q3 — Reporting & OSINT
- **#8 OSINT Report** (Gospider, Photon).
- **#9 Critical Path Analysis**.
- **#12 Compliance Mapping** UI (framework tabs on `ComplianceSummary`).
- **#13 Executive Summary Mode**.
- **#2 Security Score Timeline** (dedicated history page).
- **#17 Diff View** (arbitrary-pair comparison).

### Q4 — UX polish & business features
- **#15 Fix Wizard**, **#16 Scan Replay** — pure UI/thin-API composition over everything shipped so far.
- **#18 Team Accounts** role extension (admin/developer/auditor).
- **#20 Security Certification Pack** (built on Q1–Q3's compliance work).
- **#19 Managed Security Add-on**, **#21 Partner Portal** — business features, lower urgency than the scanning/reporting work above but no remaining technical dependency once #18 lands.

### Ongoing / opportunistic (no fixed quarter)
- **#22 Free Scans for Charities**, **#23 Local Cyber Workshops**, **#24 Hebrides Cyber Index** — community/marketing features, independent of the scanning roadmap; sequence whenever there's founder time, not engineering-blocked by anything above.

### Explicitly deferred ideas surfaced while designing this (not part of the 24, don't build speculatively)
- Compounding a Critical-Path-Analysis (#9) chain into an extra score penalty — needs real calibration against actual scan data first.
- Automated charity-eligibility verification for #22 — manual admin approval is the right amount of process at current scale.
- Attendee/RSVP management for #23 — an external signup link is sufficient until workshop volume justifies more.
