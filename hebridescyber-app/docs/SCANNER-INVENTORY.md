# Scanner inventory: products, services and checks

Derived from the code on 2026-10-05 (not from marketing copy). Where `docs/FUNCTIONALITY-MATRIX.md` or `src/app/what-we-check/page.tsx` disagree with the code, the code wins; see "Discrepancies noticed" at the end. Paths are relative to `hebridescyber-app/` unless prefixed `../`.

## 0. How a scan is structured

| Tier | Entry point | Runs when |
|---|---|---|
| Base passive suite | `runAllChecks()` + `summariseResults()` in `src/lib/scanners/index.ts` | Every scan: on-demand, API, scheduled. Needs no binaries except Chromium (Playwright). |
| Extended active-tool suite | `runExtendedTools()` in `src/lib/scanExecution.ts` (plus `runCloudPostureChecks()`), gated per tool by `resolveToolConfig()` in `src/lib/scanProfiles.ts` | Only when the resolved scan profile is not `safe`. On-demand jobs (job has `scan_id`) are always `safe`; scheduled jobs use the target's `scan_profile` (column default `full`) or its `scan_bundle_id`. Binaries are installed only in `../.github/workflows/scheduled-scans.yml`. |

Final passes (all in `executeScan()` / `summariseResults()`), in order:

1. `meta.no-issues` info finding if nothing else was found.
2. Compliance mapping (`compliance.ts`: Cyber Essentials, OWASP Top 10, CIS Controls v8, ISO 27001, PCI DSS, NIS2, DORA, SOC 2, HIPAA; the last two derived by a crosswalk) and fix difficulty / minutes estimate (`fixDifficulty.ts`: trivial/easy/moderate/hard), keyed on `checkId`. Applied to base findings in `summariseResults()` and again to extended findings, cloud-posture findings in `executeScan()`.
3. Drop `recon.subdomains-found` if Subfinder returned results.
4. Cross-tool consolidation (`findingConsolidation.ts`): extended-tool duplicates are folded into one canonical finding with `corroboratedBy`. Own base checks always win; only extended-tool findings are dropped.
5. CVSS v3.1 enrichment from NVD (`cvssEnrich.ts`), best-effort.
6. Threat intel (`threatIntel.ts`): CISA KEV membership/ransomware flag and FIRST EPSS, best-effort; absent = unknown.
7. False-positive triage exclusion, then AI summary (Azure OpenAI if configured, else templated), then `scoreFromFindings()`: 100 minus critical 30 / high 15 / medium 7 / low 2 / info 0, floored at 0.
8. After completion: finding lifecycle, asset inventory sync, alerts and webhooks (not scanner checks).

Scan profiles (`src/lib/scanProfiles.ts`, 28 extended tool keys):

| Profile | Tools enabled |
|---|---|
| `safe` | none |
| `full` | all 28 except `strix`, `cairn` (26) |
| `api` | nuclei, zap, sqlmap, commix, authCheck, whatwaf, zapAjaxSpider, kiterunner, arjun, sessionCheck, apiSpecInjection |
| `cms` | nuclei, zap, authCheck, whatwaf, wpscan, cmsmap, zapAjaxSpider |
| `osint` | subdomains, deepTls, nmap, secretScan, dependencyManifest, dockerBaseImage, trivyImage, trivyConfig, sast, photon, gospider, metadataLeak, cloudPosture |
| `ai-pentest` | all 28, including `strix` and `cairn` (see Discrepancies: not selectable in practice) |

Plan gating that exists in code (the tools themselves are not plan-gated): repo-backed tools need a connected repo (`account/connect-repo.ts`: Pro or Agency to connect); `authCheck` needs a saved credential (`account/target-auth.ts`: Agency to save); `cloudPosture` needs stored cloud credentials (`account/cloud-credentials.ts`: Agency to save). Cadence: Basic weekly, Pro/Agency daily (`scanCadence.ts`).

---

## Part A: Products and services used

### A(a) Open-source binaries and daemons run by the scanner

All are invoked as separate processes (`execFile`) or over HTTP (ZAP). Every wrapper returns `not_configured` (or `not_applicable`) rather than failing the scan when the binary is missing. All installs are in `../.github/workflows/scheduled-scans.yml` (job `work`) unless stated. `on-demand-scan.yml` installs none of them (only Playwright Chromium).

| Product | Used for | Wrapper | How installed / pinned in CI | Profiles | Licence stated in repo |
|---|---|---|---|---|---|
| Nuclei (ProjectDiscovery) | Template-based vulnerability scan, `-tags` scoped to detected technologies plus baseline tags | `src/worker/tools/nuclei.ts` | Release zip, pinned `v3.3.9` + SHA-256; `nuclei -update-templates` at job start (templates unpinned) | full, api, cms | not stated |
| OWASP ZAP | Spider + active scan; AJAX spider | `zap.ts`, `zapAjaxSpider.ts`; also `checkZap()` in `index.ts` | `docker run ghcr.io/zaproxy/zaproxy:stable` (floating tag), daemon on :8090, API key `changeme` hard-coded in the workflow | full, api, cms (spider-start in the base suite whenever `ZAP_API_URL` is set) | not stated |
| sqlmap | SQL injection confirmation (crawl depth 2, batch mode) | `sqlmap.ts`, `sqlmapOutput.ts` | `pip3 install sqlmap`, unpinned (also in `tool-integration.yml`) | full, api | not stated |
| commix | OS command injection confirmation | `commix.ts`, `commixOutput.ts` | `git clone --depth 1` of default branch to `/opt/commix`, symlinked; unpinned | full, api | not stated |
| nmap | Service/version detection (`-sV`, TCP connect) on 13 fixed ports | `nmap.ts` | `apt-get install nmap`, unpinned | full, osint | not stated |
| Subfinder (ProjectDiscovery) | Passive subdomain enumeration (no brute-force, no `-active`); queries its own third-party passive sources | `src/lib/scanners/subdomains.ts` | Release zip, pinned `v2.16.0` + SHA-256 | full, osint | not stated |
| testssl.sh | Deep TLS: protocols, cipher categories, forward secrecy, named vulnerabilities | `deepTls.ts` | `git clone --depth 1`, unpinned; path via `TESTSSL_PATH=/opt/testssl.sh/testssl.sh` | full, osint | not stated |
| Gitleaks | Secret scanning of the connected repo's git history (`--redact`) | `secretScan.ts` | Release tarball, pinned `8.21.2` + SHA-256 | full, osint (repo) | not stated |
| Trivy (Aqua) | `trivy image` (base-image package CVEs, HIGH/CRITICAL) and `trivy config` (IaC misconfig, MEDIUM+) | `trivyScan.ts` | Release tarball, pinned `0.75.0` + SHA-256 (0.58.1's assets were removed upstream, so it had never installed); output checked against a captured 0.75.0 run | full, osint (repo) | not stated |
| Opengrep | SAST engine, with the project's own 34-rule pack in `sast-rules/` (JS/TS 11, PHP 10, Python 13) | `src/worker/tools/sast.ts` | Release binary pinned `1.30.0`, SHA-256 verified; rule tests in `../.github/workflows/sast-rules.yml` | full, osint (repo) | Opengrep LGPL-2.1 (per `sast.ts`); rules MIT, written in-house |
| WPScan CLI | WordPress themes, config backups, DB exports, TimThumb | `wpscan.ts` | `gem install wpscan`, unpinned | full, cms (only if WordPress detected) | not stated |
| CMSmap | WordPress/Joomla/Drupal checks | `cmsmap.ts` | `pip3 install cmsmap`, unpinned | full, cms (only if a CMS detected) | not stated |
| WhatWaf | WAF detection | `whatwaf.ts` | `pip3 install whatwaf`, unpinned | full, api, cms | not stated |
| Photon | OSINT crawl: URLs, emails, JS endpoints | `photon.ts` | `pip3 install photon`, unpinned | full, osint | not stated |
| Gospider | Crawl and JS endpoint / S3 reference discovery | `gospider.ts` | Release zip, pinned **v1.1.6 + SHA-256** (asset `…_linux_x86_64.zip`, binary in a folder). Parser rewritten against real v1.1.6 `--json` output (`fixtures/gospider/`); `gospider.integration.test.ts` runs the real binary in CI | full, osint | not stated |
| Kiterunner (`kr`) | API route discovery with a curated wordlist | `kiterunner.ts` | Release tarball, pinned **v1.0.2 + SHA-256**. Wordlist is our own `src/worker/tools/wordlists/api-routes.txt`, compiled to `.kite` in the install step; `KITERUNNER_WORDLIST` points the wrapper at it (no-ops without it). Parser rewritten against real v1.0.2 `-o json` output (`fixtures/kiterunner/`); `kiterunner.integration.test.ts` runs the real binary in CI | full, api | not stated |
| Arjun | Hidden HTTP parameter discovery | `arjun.ts` | `pip3 install arjun`, unpinned | full, api | not stated |
| Strix | LLM-driven pentest agent with proof-of-concept exploits (`--mode deep`); needs Docker and an LLM key; about $2-5 per scan per `strix.ts` | `strix.ts` | **Never installed**: `v0.5.0` doesn't exist (tags are `v1.x`); the CLI flags in `strix.ts` were never run against a real binary | ai-pentest only | Apache 2.0 (per `strix.ts`) |
| Cairn | Autonomous exploitation engine, run as an isolated subprocess | `cairn.ts` | **Never installed**: `v1.0.0` doesn't exist in `oritera/Cairn` (latest `v0.2.1`); CLI flags unverified | ai-pentest only | AGPL-3.0 (per `cairn.ts`; subprocess isolation rationale in that file) |

### A(b) Third-party APIs and data sources called

"No key" means the code sends no credential. Every call carries `AbortSignal.timeout()`; failures degrade to `error`/`not_configured`, never a failed scan.

| Service | Module(s) | Used for | Key / env var | Without it |
|---|---|---|---|---|
| Shodan InternetDB (`internetdb.shodan.io`) | `recon.ts` | CVEs/ports/tags associated with the target IP | none | n/a |
| Cloudflare DNS-over-HTTPS (`cloudflare-dns.com/dns-query`) | `recon.ts` | Resolve target hostname to an IP for the Shodan lookup | none | n/a (the only DoH use; other DNS uses Node's resolver) |
| crt.sh (Certificate Transparency) | `recon.ts` | Subdomain list; feeds `takeover.ts` and `subdomainCerts.ts` | none | `ctLookupFailed`: takeover and subdomain-cert checks report `error`, not "clean" |
| Google Safe Browsing v4 | `safeBrowsing.ts` | Malware/phishing/unwanted-software listing | `GOOGLE_SAFE_BROWSING_API_KEY` | `not_configured`, no findings |
| HaveIBeenPwned v3 (domain search) | `hibp.ts` | Breaches affecting the domain | `HIBP_API_KEY` (paid); the domain must also be verified in HIBP's own dashboard | `not_configured`; with a key but unverified domain: `not_verified` |
| WPScan Vulnerability API v3 (`wpscan.com/api/v3`) | `wpvdb.ts` (plugins), `softwareCveDb.ts` (WordPress core), `wpscan.ts` CLI | WordPress plugin/core vulnerability data | `WPSCAN_API_TOKEN` (free tier 25 req/day per code comment) | `not_configured`; plain "plugin detected" finding still fires |
| NVD CVE API 2.0 (`services.nvd.nist.gov`) | `softwareCveDb.ts` (PHP/Apache by CPE), `cvssEnrich.ts` (CVSS by CVE id) | CVE matches, CVSS v3.1 scores | none (unauthenticated; no NVD key is read anywhere) | No CVE or CVSS data; findings unaffected |
| OSV.dev (`api.osv.dev/v1`) | `osv.ts` (webapp JS libs), `dependencyManifest.ts` (querybatch + vuln details), `dockerBaseImage.ts` | CVE ids, advisories, fixed versions | none | JS libs: finding still fires, fewer CVE ids. Dependency scan: `error`, never "no vulns" |
| CISA KEV JSON feed (`cisa.gov/.../known_exploited_vulnerabilities.json`) | `threatIntel.ts` | Known-exploited flag, ransomware use | none | `threatIntel` field omitted |
| FIRST EPSS (`api.first.org/data/v1/epss`) | `threatIntel.ts` | 30-day exploitation probability | none | field omitted |
| endoflife.date (`/api/<product>.json`) | `endOfLife.ts`, `dockerBaseImage.ts` | End-of-life dates | none | `error` if a lookup fails, never "nothing is EOL" |
| IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`) + registry RDAP servers | `domainRegistration.ts` | Domain expiry, transfer lock | none | `not_applicable`/`error`, never a finding |
| Wayback Machine CDX (`web.archive.org/cdx`) | `waybackDiscovery.ts` | Historical URLs, then live-probed on the target | none | n/a |
| GitHub API / git over HTTPS (`api.github.com`, `github.com`) | `secretScan.ts`, `dependencyManifest.ts`, `dockerBaseImage.ts`, `trivyScan.ts`, `sast.ts` via `repoClone.ts`, `githubApp.ts` | Read connected repo (clone and contents) | GitHub App (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`) preferred, else `GITHUB_PAT` (workflow secrets `GH_APP_ID`, `GH_APP_PRIVATE_KEY`, `GH_PAT`) | `not_configured`; no repo connected: `not_applicable` |
| AWS (S3) | `cloudMisconfig.ts` (unauthenticated bucket listing for buckets named in the target's own page); `cloudPosture.ts` (SigV4-signed ListBuckets, public-access block, bucket policy status with customer credentials) | Public bucket detection / account posture | Customer credentials in `cloud_credentials` table (cloudPosture only) | cloudPosture: `not_configured` "No cloud credentials stored" |
| Azure (Blob public listing; Entra token endpoint; Azure Management API) | `cloudMisconfig.ts`, `cloudPosture.ts` | Public containers; storage account public access, HTTP traffic, weak TLS | Customer credentials (tenant/subscription), as above | as above |
| Google Cloud (GCS listing; `oauth2.googleapis.com`; Storage JSON API) | `cloudMisconfig.ts`, `cloudPosture.ts` | Public buckets; public-access prevention, uniform access | Customer service account, as above | as above |
| Supabase REST API of the target's own project (`<ref>.supabase.co`) | `backendExposure.ts` | Count-only (`limit=0`) read of tables the page's code queries, using the anon key the page already ships | none | `not_applicable` when the page has no Supabase |
| Supabase Storage API of the same project | `backendExposure.ts` | List one object name (`limit: 1`, read-only POST) from buckets the page's code names via `.storage.from("x")`, with the page's anon key | none | only when the page names a bucket |
| Firebase (`*.firebaseio.com` / `*.firebasedatabase.app`, `firebasestorage.googleapis.com`, `firestore.googleapis.com`) | `firebaseExposure.ts` (via `backendExposure.ts`) | Unauthenticated GETs: RTDB shallow root read (key names only), Storage list `maxResults=1`, Firestore `pageSize=1` with a `__name__` mask, for the databases/bucket/project in the site's own Firebase config | none | only when the page carries a Firebase config |
| Azure OpenAI | `generateAiSummary()` in `index.ts`; `src/lib/aiRemediation.ts` (per-finding AI fix, `pages/api/scans/[id]/ai-fix.ts`) | Plain-English scan summary; AI remediation | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_KEY`, `AZURE_OPENAI_DEPLOYMENT` | Templated summary; AI fix unavailable |
| LLM provider behind Strix (provider not named in the code) | `strix.ts` | Strix agent inference | `STRIX_LLM_API_KEY` (passed to the CLI as `STRIX_API_KEY`) | `not_configured` |

Not called, despite appearing in comments or docs: Amass (explicitly not wired), crates.io index (appears only as a Cargo.lock source marker), NVD API key (rate limit comment only).

### A(c) Libraries and runtime pieces that matter for scanning

| Piece | Used by | Notes |
|---|---|---|
| Playwright `^1.46.0` + Chromium | `playwright.ts` (page load, mixed content, console errors, runtime script capture for `scriptInventory.ts`); `xssConfirm.ts` DOM verifier (unwired) | Chromium installed by `npx playwright install --with-deps chromium` in both scan workflows (cached per lockfile). Failure: check returns `error`. |
| Node `tls` | `tls.ts`, `subdomainCerts.ts` | Handshake with `rejectUnauthorized: false`, reads Node's own verdict; cannot probe TLS 1.0/1.1 server support (that is testssl.sh's job). |
| Node `dns/promises` (`Resolver`) | `dns.ts`, `takeover.ts`, `subdomains.ts` | SPF/DKIM/DMARC/CAA/MX/DNSSEC, CNAME/NXDOMAIN evidence. |
| Node `net` | `ports.ts` | Direct TCP connect (2 s timeout) to 30 fixed ports. No nmap, no Shodan involved. |
| Node `fetch`, `crypto`, `child_process` | everywhere | HTTP probing, hashing for stable checkIds, subprocess execution. |
| `git` CLI | `repoClone.ts` | Shallow clone of the connected repo with an installation token. |
| Docker | scheduled workflow | Runs the ZAP daemon; Strix needs it per its workflow comment. |
| Own pattern tables | `fingerprint.ts` (56 patterns), `webapp.ts` (7 JS libs, 20 WP plugin slugs), `exposure.ts` (41 paths), `ports.ts` (30 ports), `directoryListing.ts` (18 paths), `takeover.ts` (15 providers) | No Wappalyzer or other third-party fingerprint library is used. |

---

## Part B: Checks performed against a target

Severity shown is what the code assigns (or the range). "Needs" lists non-default prerequisites.

### B1. Base passive suite (every scan)

Wired in `runAllChecks()`; findings derived in `summariseResults()` unless noted.

| Area | What it does | checkId prefixes emitted | Typical severity | Needs |
|---|---|---|---|---|
| TLS (`tls.ts`) | Reads certificate and negotiated session on 443 | `tls.no-https`, `tls.weak-protocol`, `tls.cert-expired`, `tls.cert-expiring` (<21 days), `tls.self-signed`, `tls.cert-name-mismatch`, `tls.cert-chain-incomplete`, `tls.cert-untrusted`, `tls.hsts-missing`, `tls.hsts-short` (<180 days) | critical to low | none |
| Security headers (`headers.ts`) | 10-header OWASP list, CSP grade A-F, cookie flags, CORS wildcard, info disclosure | `headers.missing-critical`, `headers.missing-recommended`, `headers.csp-absent`, `headers.csp-weak`, `headers.cookie-flags:<cookie>`, `headers.cors-wildcard`, `headers.info-disclosure` | high / medium / low | none |
| DNS and email auth (`dns.ts`) | SPF, DKIM (default selectors only), DMARC, CAA, DNSSEC signal, MTA-STS and TLS-RPT when MX exists | `dns.spf-missing`, `dns.spf-issues`, `dns.dkim-issues`, `dns.dkim-not-detected`, `dns.dmarc-missing`, `dns.dmarc-none`, `dns.caa-missing`, `dns.dnssec-missing`, `dns.mta-sts-missing`, `dns.mta-sts-issues`, `dns.tls-rpt-missing`, `dns.tls-rpt-issues` | high to info | none |
| Sensitive files (`exposure.ts`) | 41 probed paths (.git, .env, backups, debug pages, logs) with catch-all/masking hardening (`httpProbe.ts`); `security.txt` | `exposure.exposed-file:<path>`, `exposure.no-security-txt` | per file, up to critical; info | none |
| Directory listing (`directoryListing.ts`) | Genuine autoindex pages on 18 paths | `directory-listing.open-directory:<path>` | medium | none |
| Cloud storage in page (`cloudMisconfig.ts`) | Tests only buckets referenced in the page for public listing (S3, Azure Blob, GCS) | `cloud-misconfig.public-bucket:<provider>:<id>` | high | none |
| Fingerprinting (`fingerprint.ts`) | Passive tech detection; flags old majors of jQuery, Bootstrap, WordPress, Angular, PHP, Apache | `fingerprint.risky-library:<name>`, `fingerprint.tech-detected` | high / info | none |
| Ports (`ports.ts`) | TCP connect to 30 fixed ports | `ports.risky-port:<port>` | per port: critical to info | none |
| Page health (`playwright.ts`) | Headless load: status, mixed content, console errors | `playwright.unhealthy-status`, `playwright.mixed-content`, `playwright.console-errors` | medium / high / low | Chromium |
| Recon (`recon.ts`) | Shodan InternetDB CVEs; crt.sh subdomains | `recon.shodan-cves`, `recon.subdomains-found` | high; info | none |
| Web app (`webapp.ts`) | robots.txt, dangerous methods, error disclosure, CORS reflection, vulnerable JS libs (+OSV), SRI | `webapp.robots-sensitive-paths`, `webapp.dangerous-methods`, `webapp.error-disclosure`, `webapp.cors-reflected-creds`, `webapp.cors-reflected`, `webapp.vulnerable-js-lib:<lib>`, `webapp.missing-sri:<kind>:<url>` | info to critical | none |
| WordPress deep scan (`webapp.ts`) | Runs only when WordPress detected | `webapp.wp-xmlrpc`, `webapp.wp-user-enum`, `webapp.wp-debug-log`, `webapp.wp-readme`, `webapp.wp-cron`, `webapp.wp-plugin-detected:<slug>` (20 candidate slugs) | info to high | WordPress detected |
| Joomla deep scan | Runs only when Joomla detected | `webapp.joomla-version-disclosed`, `webapp.joomla-install-files` | low | Joomla detected |
| Drupal deep scan | Runs only when Drupal detected | `webapp.drupal-version-disclosed`, `webapp.drupal-update-php`, `webapp.drupal-jsonapi-exposed`, `webapp.drupal-uid1-enumerable` | info to medium | Drupal detected |
| WP plugin CVEs (`wpvdb.ts`) | WPScan VDB lookup of detected plugin versions | `wpvdb.plugin-vulnerability:<slug>:<id>` | critical (SQLi/RCE/privesc/auth bypass) else high | `WPSCAN_API_TOKEN` |
| WP core / PHP / Apache CVEs (`softwareCveDb.ts`) | WPScan (core) and NVD CPE (PHP, Apache) for `riskySoftware` | `softwareCveDb.wordpressCore:<id>`, `softwareCveDb.nvdCpe:<vendor>-<product>:<version>` | from CVSS / WPScan type | `WPSCAN_API_TOKEN` for core |
| Safe Browsing (`safeBrowsing.ts`) | Google threat list lookup | `safe-browsing.flagged` | critical | `GOOGLE_SAFE_BROWSING_API_KEY` |
| Wayback (`waybackDiscovery.ts`) | CDX history, up to 40 prioritised paths live-probed | `wayback-discovery.live-path:<hash>` | by keyword (admin/backup/.env/config) | none |
| Breaches (`hibp.ts`) | Domain breach search | `hibp.domain-breach:<breach>` | high if passwords or sensitive data, else medium/low | `HIBP_API_KEY` + HIBP domain verification |
| Business logic (`businessLogic.ts`) | Forms and links read passively; one active step: 5 POSTs with dummy credentials to login-like paths to detect rate limiting | `business-logic.csrf-missing`, `business-logic.external-form-action:<domain>`, `business-logic.autocomplete-sensitive:<field>`, `business-logic.sequential-url`, `business-logic.predictable-ids`, `business-logic.open-redirect:<param>`, `business-logic.no-rate-limit` | info to high | none |
| API spec, passive (`apiSpec.ts` `checkApiSpecPassive`) | Stored spec (`api_specs`) or auto-discovery (`/openapi.json`, `/swagger.json`, ...); up to 20 endpoints per check; no attack payloads | `api-spec.auth-bypass:<m>:<path>`, `api-spec.method-confusion:<m>:<path>`, `api-spec.schema-violation:<m>:<path>`, `api-spec.excessive-data:<path>`, `api-spec.undocumented-fields:<path>` | high / medium / low | spec stored or discoverable, else `not_configured` |
| Subdomain certificates (`subdomainCerts.ts`) | Expiry on up to 20 CT-listed hosts, one finding per certificate | `subdomain-certs.expired:<cert>`, `subdomain-certs.expiring:<cert>` | medium / low | crt.sh success |
| Dangling DNS (`takeover.ts`) | CNAME to one of 15 providers plus NXDOMAIN or provider's unclaimed page | `takeover.dangling-cname:<host>` | high (medium for lower-confidence providers) | crt.sh success |
| End-of-life (`endOfLife.ts`) | PHP, nginx, Apache, Drupal, Joomla, Angular, jQuery, Bootstrap vs endoflife.date; 90-day heads-up; distro-packaged versions downgraded | `eol.unsupported:<product>`, `eol.approaching:<product>` | high/medium/low by kind and age; info | none |
| Domain registration (`domainRegistration.ts`) | RDAP expiry (<=30 days / expired) and gTLD transfer lock | `domain.expired`, `domain.expiring`, `domain.transfer-lock-missing` | high / high or medium (14-day split) / low | none |
| Script inventory (`scriptInventory.ts`) | External script origins from HTML and browser runtime capture; PCI DSS 6.4.3/11.6.1 | `script-inventory.unreviewed:<origin>` | info; low on payment pages | Chromium for runtime capture (else `partial`) |
| Supabase / Firebase exposure (`backendExposure.ts`, `firebaseExposure.ts`) | service_role key in client code; anon-readable tables (count-only); anon-listable storage buckets; Firebase RTDB readable at the root, Storage listable, Firestore collections readable without auth | `backend-exposure.service-key:<ref>`, `backend-exposure.open-table:<ref>:<table>`, `backend-exposure.storage-bucket:<ref>:<bucket>`, `backend-exposure.firebase-rtdb:<host>`, `backend-exposure.firebase-storage:<bucket>`, `backend-exposure.firestore:<project>:<collection>` | critical; high; medium; high; medium; high | Supabase or a Firebase config on the page |
| Site crawl (`crawler.ts`, `crawlFindings.ts`) | Anonymous BFS crawl: max 50 pages, depth 3, 4 concurrent, 45 s, robots.txt honoured, GET only, seeded from Wayback | `crawl.header-gap:<header>`, `crawl.cookie-flags:<name>`, `crawl.mixed-content:<path>`, `crawl.insecure-form:<path>`, `crawl.error-disclosure:<path>`, `crawl.missing-sri` | medium / low / high | none |
| ZAP spider start (`checkZap` in `index.ts`) | Starts an async spider; emits no findings | none | n/a | `ZAP_API_URL` |
| Meta | Fallback when nothing found | `meta.no-issues` | info | none |

### B2. Extended active-tool suite

Findings are built in `runExtendedTools()` (`src/lib/scanExecution.ts`) unless the module builds `Finding[]` itself. Profiles: F=full, A=api, C=cms, O=osint, P=ai-pentest (P includes all tools). Retest of any of these on an on-demand scan is blocked by `src/lib/extendedToolCheckIds.ts`.

| Tool key | What it does | checkId prefixes | Typical severity | Profiles | Needs |
|---|---|---|---|---|---|
| `nuclei` | Tech-scoped templates + baseline tags (cve, exposure, misconfig, default-login, takeover) | `nuclei.finding:<templateId>` | template's own severity | F A C P | binary |
| `zap` | Spider + active scan | `zap.alert:<alert name>` | ZAP risk mapped | F A C P | `ZAP_API_URL`, `ZAP_API_KEY` |
| `zapAjaxSpider` | JS-aware crawl for extra endpoints | `zapAjaxSpider.hidden-endpoint` | info | F A C P | ZAP |
| `sqlmap` | SQL injection confirmation | `sqlmap.sqli:<param>[:<place>]` | critical | F A P | binary |
| `commix` | OS command injection confirmation | `commix.command-injection:<param>[:<place>]` | critical | F A P | binary (output format verified only on a negative run) |
| `nmap` | `-sV` on 21,22,23,25,3306,5432,6379,27017,9200,2375,2376,8500,2379; only 2375/2376/6379/9200/27017/2379 produce findings | `nmap.dangerous-port:<port>` | critical | F O P | binary |
| `subdomains` | Subfinder passive enumeration, takeover candidates, sensitive-looking hosts | `subdomains.takeover-candidate:<host>`, `subdomains.sensitive-host:<host>`, `subdomains.discovered:<host>`, `subdomains.discovered-additional` | high / low / info | F O P | binary |
| `deepTls` | testssl.sh protocols, ciphers, forward secrecy, named vulnerabilities | `deep-tls.weak-cipher-suites`, `deep-tls.finding:<id>` | from testssl severity | F O P | `TESTSSL_PATH` |
| `secretScan` | Gitleaks over repo history, redacted | `secretScan.exposed-secret:<rule>-<hash>` | by rule/path heuristic | F O P | connected repo, GitHub access |
| `dependencyManifest` | Lockfiles (npm/pnpm/Yarn, Poetry/Pipfile, Composer, go.sum, Gradle, Bundler, Cargo, NuGet) or manifest-range fallback, via OSV; builds SBOM inventory | `dependency-manifest.<ecosystem>:<package>`, `dependency-manifest.additional-vulnerable:<ecosystem>` | from OSV advisory; info for the roll-up | F O P | connected repo |
| `dockerBaseImage` | Dockerfile base image unpinned tag / past end-of-life | `docker-base-image.unpinned-tag:<image>`, `docker-base-image.outdated-base:<image>` | low; medium/high by stage and age | F O P | connected repo |
| `trivyImage` | Base-image package CVEs (HIGH/CRITICAL) | `trivy-image.vulnerable-package:<cve>:<pkg>` | from Trivy | F O P | connected repo, binary |
| `trivyConfig` | IaC misconfiguration (Terraform, Kubernetes, Dockerfile; MEDIUM+) | `trivy-config.misconfiguration:<id>:<target>` | from Trivy | F O P | connected repo, binary |
| `sast` | Opengrep with 34 in-house rules (injection, eval, shell, deserialisation, include, open redirect, TLS verify off, debug on, JWT unverified) | `sast.<ruleId>:<hash>` | per rule | F O P | connected repo, binary, `sast-rules/` |
| `authCheck` | Headers, session cookies, CSP, CORS on a request carrying the saved cookie or Basic credential; then a signed-in crawl | `auth-check.missing-headers`, `auth-check.csp-absent`, `auth-check.session-cookie-insecure:<cookie>`, `auth-check.cors-wildcard`; crawl results as `crawl.auth.*` (same suffixes as `crawl.*`, titles suffixed "(signed in)") | as base equivalents (cookies graded higher) | F A C P | saved credential on a monitored target (Agency to save) |
| `whatwaf` | WAF detection | `whatwaf.waf-detected`, `whatwaf.no-waf` | info; medium | F A C P | binary |
| `wpscan` | WordPress themes, config backups, DB exports, TimThumb | `wpscan.theme-vulnerability:<slug>`, `wpscan.config-backup:<slug>`, `wpscan.db-export:<slug>`, `wpscan.timthumb:<slug>` | from tool | F C P | binary, WordPress detected, `WPSCAN_API_TOKEN` optional |
| `cmsmap` | CMS vulnerabilities and misconfigurations | `cmsmap.vulnerability:<name>`, `cmsmap.misconfiguration:<name>` | from tool | F C P | binary, CMS detected |
| `photon` | Emails and JS endpoints | `photon.emails-discovered`, `photon.js-endpoints-discovered` | info | F O P | binary |
| `gospider` | JS endpoints, S3 references | `gospider.js-endpoints-discovered`, `gospider.aws-s3-reference` | info; low | F O P | binary |
| `metadataLeak` | PDF/Office/image metadata of URLs found by Photon/Gospider (email, internal IP, paths, author, software) | `metadataLeak.<type>:<url>` | medium (internal IP), low (email), info | F O P | Photon or Gospider output; no binary |
| `kiterunner` | Wordlist brute-force of API routes | `kiterunner.hidden-api-endpoint` | medium | F A P | binary |
| `arjun` | Hidden GET/POST parameters | `arjun.hidden-parameter:<url>` | low | F A P | binary |
| `sessionCheck` | Login rate-limit, session fixation, IDOR indicator (HTTP only) | `sessionCheck.no-rate-limit:<url>`, `sessionCheck.session-fixation:<url>`, `sessionCheck.idor-indicator:<url>`; type `session-no-rotation` exists in the module but has no dedicated mapping in `scanExecution.ts` | medium; high; high | F A P | none |
| `cloudPosture` | Public-access posture of the customer's own AWS/Azure/GCP storage using stored read-only credentials | `cloudPosture.awsPublicS3:<bucket>`, `cloudPosture.awsPublicS3Policy:<bucket>`, `cloudPosture.awsAccountPublicAccess`, `cloudPosture.azurePublicBlob:<acct>`, `cloudPosture.azureHttpTraffic:<acct>`, `cloudPosture.azureWeakTls:<acct>`, `cloudPosture.gcpPublicAccessPrevention:<bucket>`, `cloudPosture.gcpUniformAccess:<bucket>`, `cloudPosture.gcpPublicBucket:<bucket>` | per check | F O P | `cloud_credentials` rows (Agency to save); runs outside `runExtendedTools` |
| `apiSpecInjection` | SQLi and XSS probes against spec-documented parameters (`checkApiSpecInjection`) | `api-spec.sqli:<m>:<path>:<param>`, `api-spec.sqli-path:<m>:<path>:<param>`, `api-spec.xss:<m>:<path>:<param>` | critical / high / critical | F A P | stored or discoverable OpenAPI spec |
| `strix` | LLM agent pentest with PoC exploit text in the finding | `strix.finding:<vulnClass>` | agent-reported | P only (or bundle override) | binary, Docker, `STRIX_LLM_API_KEY` |
| `cairn` | Autonomous exploitation with exploit chain and evidence in the finding | `cairn.finding:<vulnClass>` | agent-reported, default high | P only (or bundle override) | binary |

Counts: base suite 31 rows above (including CMS-specific rows and the no-findings ZAP spider start); extended suite 28 tool keys (27 emit findings; `zapAjaxSpider`, `photon`, `gospider`, `kiterunner`, `arjun` emit inventory-style findings, and `metadataLeak` is derived from them).

### B3. Modules present in the repo but not wired into any scan path

Verified by grepping for imports and function calls outside tests.

| Module | Exports | Status |
|---|---|---|
| `src/lib/scanners/graphql.ts` | `runGraphqlChecks()`: introspection, no-auth, no depth limit on `/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`; would emit `graphql.introspection:<endpoint>`, `graphql.no-auth:<endpoint>`, `graphql.no-depth-limit:<endpoint>` | Imported by nothing. Not in `runAllChecks()`, `runExtendedTools()` or any profile. These checkIds are never produced in a real scan. |
| `src/lib/easmDiscovery.ts` | `runEasmDiscovery()` (crt.sh plus DNS brute-force of common prefixes plus HTTP probing) | Imported by nothing. Its header claims it runs as a post-scan step in `scanExecution.ts`; it does not. Its DNS brute-force would conflict with the stated no-brute-force position if wired. |
| `src/lib/scanners/proofOfExploit.ts` | `validateExploit()`, `enrichWithProofOfExploit()` | Not called by any scan or API route. |
| `src/lib/scanners/xssConfirm.ts` | `confirmReflectedXss()`, `playwrightDomVerifier` | Only imported by `proofOfExploit.ts`, so also unwired. |

Related notes: `checkId` families `crawl.auth.*` are produced only through `authCheck` (extended). `metadataLeak` is also listed as a profile key but only yields findings when Photon or Gospider produced URL assets in the same run.

---

## Part C: What is deliberately not done

From `docs/USER-GUIDE.md` section 6 and `docs/COMPETITIVE-ANALYSIS.md` section 9, as stated policy:

- No brute-forcing and no destructive payloads; active tools run only on ownership-verified domains.
- No fabricated findings: a check that cannot evidence something reports nothing (hence `error` / `partial` / `not_applicable` states that never resolve findings as fixed).
- No full crawl-behind-login, no IDOR testing, no multi-step auth (OAuth/MFA) handling.
- No full code review: SAST is pattern-based, about 35 rules, JS/TS, Python, PHP.
- No cloud account-level IAM auditing (ScoutSuite/Prowler style).

Code-level safety rules that are consistent across modules: GET-only crawling, forms never submitted, logout/delete/cart links never followed, subdomain tooling passive only, buckets tested only if referenced by the target's own page, Supabase tables read as counts only, storage and Firebase stores read as one name at most (never a value or file), secrets redacted and never stored.

---

## Discrepancies noticed

**Release installs checked 2026-10-06** (every asset downloaded and hashed): nuclei, subfinder and gitleaks install and are SHA-256-pinned; trivy is 0.75.0 with a checksum. **gospider and kiterunner now install and are verified**: both were pinned by SHA-256 and their parsers rewritten against real captured output, with `*.integration.test.ts` running the real binaries in CI (fixtures in `src/worker/tools/fixtures/`). **A latent bug this uncovered:** every wrapper shelled out with `promisify(execFile)`, which leaves the child's stdin an open pipe; nuclei and gospider read targets from stdin and so hung until killed at their timeout — i.e. **every scheduled scan's nuclei step produced nothing**. All wrappers now use `src/lib/execTool.ts`, which closes stdin. **strix and cairn are still `not_configured`** and are handled separately (autonomous AI exploit agents needing an LLM key, Docker and a real target to verify; see NEXT-STEPS).

1. `docs/FUNCTIONALITY-MATRIX.md` section 3 is stale. It describes the extended suite as gated by `runExtendedTools` set via `const runExtendedTools = !scanId`; the code uses scan profiles (`scanProfiles.ts`, `decideScanConfig()` in `run-queued-scan-jobs.ts`). It says nmap does a "SYN, top-1000 ports, service/OS detect"; the code runs a TCP connect `-sV` on 13 fixed ports (nmap's own header documents this). It names `ajaxSpider.ts`; the file is `zapAjaxSpider.ts`. It says authenticated scanning is a header/cookie recheck; the code also runs a signed-in crawl (`crawl.auth.*`).
2. `src/app/what-we-check/page.tsx` (and `CLAUDE.md`'s `ports.ts` line) say ports are checked "using Shodan's InternetDB, no port-scanning traffic sent to your infrastructure". `ports.ts` makes direct TCP connections to 30 ports; InternetDB is used only in `recon.ts` for CVEs. (Comment in `nmap.ts` repeats the InternetDB claim for `ports.ts`.)
3. The same page has no section for: Wayback discovery, HIBP breach search, Safe Browsing, Supabase backend exposure, site crawl, business-logic checks, API-spec checks, WPScan VDB / software CVE matches, and, in the extended tier, Gitleaks, Trivy, Subfinder, testssl.sh, cloud posture. It says authenticated scanning is "not a full crawl behind login", which no longer matches `authenticatedCrawl.ts`.
4. `docs/USER-GUIDE.md` section 6 and `COMPETITIVE-ANALYSIS.md` section 9 said no crawl-behind-login, no IDOR testing, no brute-forcing, no destructive payloads, no cloud auditing. The code includes a signed-in crawl, `sessionCheck` IDOR indicators, Kiterunner curated-wordlist API-route discovery (now wired; User-Guide §6 reworded to describe it accurately — still no destructive payloads), a 5-request dummy-credential POST probe in the base `business-logic.no-rate-limit` check, and public-access cloud posture checks (not IAM auditing, but credentialed). Strix/Cairn (autonomous exploit agents) remain `not_configured`; if enabled, the "no destructive payloads" promise must be revisited first.
5. `ai-pentest` profile cannot currently be selected: `sql/migrations/020_scan_profiles.sql` and `021_scan_bundles.sql` constrain `scan_profile`/`base_profile` to safe/full/api/cms/osint, and `MonitoredTargets.tsx` offers no such option. No code enforces the "Agency or higher" gate that `strix.ts` and `scanProfiles.ts` mention. Also the profile enables `cairn` as well as `strix` (the comment mentions only Strix).
6. `scanProfiles.ts` header still lists Kiterunner, Arjun, WPScan, CMSmap, Gospider, Photon and WhatWaf as "don't exist yet"; they all exist. `resolveToolConfig()` docstring says "all-14-keys"; there are 28. `executeScan()` hard-codes `BASE_CHECK_NAMES.length + 26` for the progress total, but there are 28 tool keys.
7. `nuclei.ts` and `scheduled-scans.yml` refer to `worker.Dockerfile` pins; no such file exists in the repo. Real pins live only in `scheduled-scans.yml`. Only Opengrep is checksum-verified; nmap, sqlmap, commix, testssl.sh, whatwaf, wpscan, cmsmap, photon, arjun and the ZAP image tag are unpinned, nuclei templates update at run time, and the ZAP API key is the literal `changeme` in the workflow.
8. In the scheduled worker, `ZAP_API_URL` is set for every job, so the base suite's `checkZap()` starts an extra ZAP spider even for `safe`-profile jobs and in addition to `runZap()` for other profiles. On-demand runs never have ZAP.
9. nmap scans 21, 22, 23, 25, 3306, 5432 and 8500 but only six ports (2375, 2376, 6379, 9200, 27017, 2379) can ever become `nmap.dangerous-port` findings.
10. Unwired modules (`graphql.ts`, `easmDiscovery.ts`, `proofOfExploit.ts`, `xssConfirm.ts`) are described in their headers or in `CLAUDE.md`/docs as active; GraphQL and EASM checks therefore do not run today.
