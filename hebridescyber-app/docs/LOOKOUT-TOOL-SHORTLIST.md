# Lookout tool shortlist: 50 candidates, scored for fit

**Date:** 2026-11-02. **Scope:** tools that could feed the `exposure` profile
(Lookout) or an Assured add-on. Versions and licences come from the GitHub API
on this date. For scanner-wide candidates see `TOOL-GAP-ANALYSIS-OSINT-CLOUD.md`,
`STRATEGY-REVIEW-2026-10.md` §"Recon / ASM / DNS" and E-78 (PR #164). For the
licence rules (AGPL unmodified, NPSL, Nikto data) see PR #168 / OT-50.

## What Lookout is, for tool-selection purposes

Lookout is a **managed external attack surface management (EASM) and
vulnerability assessment service**. In Gartner's CTEM terms it covers scoping,
discovery, prioritisation and mobilisation (the engineer's report and the
fix confirmation). It deliberately skips validation by exploitation. An analyst
triages findings before a non-technical owner sees them.

So a tool fits only if it passes all seven gates:

1. **Outside-in, or read-only with the customer's consent.** No foothold, no agent.
2. **Traffic class at most "active, non-intrusive"** (`DEFENSIVE-ASSESSMENT-PLAN.md`
   "Traffic classes"). No test payloads, no credential use, no brute-force guessing.
3. **Headless, JSON output, fits an ephemeral Actions runner.** No persistent server.
4. **The licence allows a hosted commercial service:** MIT, Apache, BSD or MPL,
   or GPL/AGPL run unmodified as a subprocess. Custom or data-feed terms need OT-50 review.
5. **Maintained:** a release in the last ~12 months, and the repo isn't archived.
6. **Hermetically testable in CI** with the real binary (CLAUDE.md rule 15).
7. **Adds coverage** the base suite, httpx, naabu+nmap and restricted nuclei don't already give.

## Recommended, in order

| Rank | Tool | Why it earns a place | Effort |
|---|---|---|---|
| 1 | **Tools we already run**: testssl.sh (`deepTls`), `metadataLeak` | **Done 2026-11-02.** Both are now in `exposure`. deepTls has a real-binary test and runs without its Heartbleed, CCS, Ticketbleed and ROBOT probes, which are intrusive. metadataLeak reads the base crawl's document links, which honour robots.txt, rather than gospider's. Building it found two rule-7 gaps, both fixed: an unreachable TLS host and a run where no file could be fetched used to read as clean. subfinder stays out, because it has no hermetic target. | S |
| 2 | **cdncheck** | Tags IPs that belong to a CDN, cloud provider or WAF before naabu and nmap touch them. Without it, a Cloudflare-fronted customer gets Cloudflare's edge port-scanned, which is not their asset, and Cloudflare's open ports show up as findings. Fixes scope safety and false positives at once, with no traffic (offline ranges). | S |
| 3 | **dnsx** | Bulk resolution of every CT and subfinder name (A, AAAA, CNAME, MX, NS, TXT), wildcard detection and a single AXFR attempt per NS. Gives `takeover.ts` and the analyst a resolved inventory, and catches open zone transfers. | S |
| 4 | **ssh-audit** | One unauthenticated SSH handshake gives weak key exchange, ciphers and MACs, host-key type, and version-matched CVEs, each with a precise fix. SSH on a VPS is common in SME estates and fits Cyber Essentials "secure configuration". | S |
| 5 | **tlsx** | Certificates on every open TLS port, not just 443, across all hosts: expired, self-signed, mismatched, and SANs that reveal hostnames missing from CT. One handshake per port. | S |
| 6 | **Exploit-availability signal** (PoC-in-GitHub, CC0, daily; Exploit-DB CSV) | Adds "public exploit code exists" to CVE findings alongside KEV and EPSS, so analysts rank faster. Offline data, nothing downloaded or run. | S |
| 7 | **Public-repo secret scan** (reuse Gitleaks against the customer's named public GitHub org) | Leaked keys in public repos are a leading SME breach cause, and the check sends no traffic to the customer. Reuses the existing Gitleaks wrapper. TruffleHog would only be added later, with `--no-verification`, because verifying a key means logging in with it. | M |
| 8 | **Web host screenshots** (in-house with our Playwright; gowitness as reference) | The analyst sees forgotten test sites, default pages and login panels at a glance, and the report shows the owner what is exposed. One page load per host. | M |
| 9 | **Prowler `m365` provider** (consented, Assured add-on) | Most UK SMEs run Microsoft 365. Prowler already ships Entra, Exchange, Teams, SharePoint and Defender checks plus CIS M365, using the engine we pin (5.47.0). Needs a read-only app consent. It is not outside-in, so it's sold and scoped separately. | M |
| 10 | **CSP Evaluator** (npm, in-process) | Google's bypass-aware CSP analysis (JSONP allowlisted hosts, `unsafe-inline`, missing `object-src`) on top of `headers.ts`'s parser. No traffic. | S |

**Housekeeping found while checking versions:**
- `attackMap.ts` says "Checked against ATT&CK v17". The current release is **v20.0** (2026-10-13), so the quarterly re-check is due.
- Nuclei is pinned at **v3.3.9**; the latest is **v3.11.1**, and `exposure` depends on it. PRs #170–#172 and #175–#177 bump it along with httpx, subfinder, gitleaks, trivy and opengrep. Merge them before the OT-44 tag review, so the review covers the templates Lookout will actually run.

## All 50, scored

Verdicts: **Add**, **Maybe** (worth it under a stated condition), **Have / in progress**, **Don't**.

### Asset discovery and inventory

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 1 | cdncheck | v1.4.0 (2026-11-01) | MIT | CDN, cloud and WAF tagging before port scanning | **Add** (rank 2) |
| 2 | dnsx | v1.3.1 (2026-08-31) | MIT | Bulk DNS records, wildcard detection, AXFR test | **Add** (rank 3) |
| 3 | tlsx | v1.4.0 (2026-09-07) | MIT | Certificate inventory on all TLS ports | **Add** (rank 5) |
| 4 | asnmap | v1.2.0 (2026-10-26) | MIT; needs a free PDCP API key | ASN to CIDR, to suggest owned ranges at scoping | **Maybe**: analyst scoping aid only. Never auto-adds targets, because ownership must be verified. |
| 5 | alterx | v0.1.0 (2025-12-11) | MIT | Subdomain permutations | **Don't**: brute-force guessing |
| 6 | OWASP Amass | v5.1.3 (2026-10-25) | Apache-2.0 | Deeper passive enumeration | **Don't**: rejected in the plan; v5 needs its own engine and database |
| 7 | BBOT | v3.0.2 (2026-08-24) | AGPL-3.0 | All-in-one recon framework | **Don't**: framework, same reasoning as SpiderFoot in the gap analysis |
| 8 | gau / waymore | v2.2.4 (2024-10-28) / v8.9 (2026-06-11) | MIT | Archived URLs from Common Crawl, OTX and urlscan, on top of our Wayback-only source | **Maybe**, low: small increment over `waybackDiscovery.ts`; gau is stale |
| 9 | Findomain | 10.0.1 (2025-07-28) | GPL-3.0 | Passive subdomains | **Don't**: subfinder does it |
| 10 | uncover | v1.2.1 (2026-05-20) | MIT | Shodan, Censys and FOFA queries | **Don't**: needs paid keys |
| 11 | mapcidr | v1.1.97 (2025-10-28) | MIT | CIDR maths | **Don't**: a few lines of code |

### DNS, email and domain

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 12 | BadDNS | 2.4.0 (2026-06-09) | AGPL-3.0 | Dangling NS, MX, TXT and SPF records, not just CNAMEs (`takeover.ts` checks CNAMEs only) | **Maybe**: run unmodified with an explicit module allowlist (drop NSEC walking), or port the NS/MX cases into `takeover.ts` instead |
| 13 | dnstwist | 20250130 (2025-01-30) | Apache-2.0 | Wider lookalike generation (homoglyph, bitsquat, dictionary) plus MX and page-similarity checks | **Maybe**: extends `lookalikeDomainMonitor.ts`; brand-protection add-on; no release for 21 months |
| 14 | checkdmarc | 6.0.4 (2026-10-13) | Apache-2.0 | SPF, DMARC, MTA-STS, BIMI, DNSSEC, MX STARTTLS | **Test oracle only**: `dns.ts` already does these. Use it in CI to cross-check `dns.ts` against real domains |
| 15 | Zonemaster engine | v9.0.1 (2026-10-01) | BSD-2 | Delegation health, lame delegation | **Maybe**, low: lame NS is a takeover path, but it's a heavy Perl stack |
| 16 | DNSViz | v0.11.2 (2026-10-03) | GPL-2.0 | Full DNSSEC chain validation | **Don't** for now: few SME domains are signed |
| 17 | parsedmarc | 11.2.1 (2026-11-01) | Apache-2.0 | DMARC aggregate parsing | **Have**: `dmarcAggregate.ts`, `dmarcReports.ts` |
| 18 | dnsrecon | 1.6.3 (2026-06-28) | GPL-2.0 | AXFR, record enumeration | **Don't**: dnsx covers AXFR |

### Network services

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 19 | ssh-audit | v3.9.0 (2026-07-04) | MIT | SSH algorithm and CVE audit | **Add** (rank 4) |
| 20 | nerva | v1.84.0 (2026-10-29) | Apache-2.0 | 120+ protocol fingerprints with JSON output; successor to fingerprintx | **Maybe**: the answer if OT-50 rules that parsing Nmap output is an NPSL problem |
| 21 | fingerprintx | v1.1.19 (2026-01-01) | Apache-2.0 | (as nerva) | **Don't**: archived |
| 22 | zgrab2 | v1.0.0 (2025-12-04) | Apache-2.0 / ISC | Banner grabbing | **Don't**: overlaps nmap/nerva |
| 23 | OpenVAS / GVM | scanner v23.52.8, gvmd v26.43.0 (Oct 2026) | GPL-2.0 / AGPL-3.0 | Network vulnerability tests | **In progress**: PR #174 prototype (OT-36) |
| 24 | Nikto | 2.6.1 (2026-07-31) | GPL-2.0 + data-file terms | Web-server misconfiguration | **Planned (Q1)**: noisy; data licence under OT-50 |
| 25 | nmap-vulners | v2.0.2 (2026-08-20) | GPL | CVE lookup from `-sV` | **Don't**: needs the Vulners API under its own terms |
| 26 | vulscan | 2.1 (2020-05-20) | GPL | Offline CVE lookup for nmap | **Don't**: stale data |
| 27 | Masscan | n/a | AGPL-3.0 | Fast port scan | **Don't**: already rejected |
| 28 | IVRE | v0.9.21 (2024-09-25) | GPL-3.0 | Recon framework and database | **Don't**: persistent infrastructure |

### Web exposure and configuration

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 29 | ZAP passive-only | digest-pinned | Apache-2.0 | Passive alerts from a crawl | **In progress**: PR #152 |
| 30 | testssl.sh | v3.2.4 (2026-07-12) | GPL-2.0 | Deep TLS | **Done**: in `exposure`, with its intrusive probes left out (rank 1) |
| 31 | sslyze | 6.3.1 (2026-03-29) | AGPL-3.0 | TLS, faster | **Don't**: one TLS engine is enough |
| 32 | MDN HTTP Observatory | v1.7.2 (2026-10-26) | MPL-2.0 | A local, recognised header grade (npm, runs in Node) | **Maybe**: a report credibility item ("Mozilla grade: B"); duplicates `headers.ts` |
| 33 | CSP Evaluator | v1.1.8 (2026-05-26) | Apache-2.0 | Bypass-aware CSP analysis | **Add** (rank 10) |
| 34 | gowitness | 3.2.2 (2026-10-11) | GPL-3.0 | Screenshots of web hosts | **Add the capability** (rank 8), preferably in-house with Playwright |
| 35 | wafw00f | v2.4.2 (2026-01-26) | BSD-3 | WAF identification | **Don't for Lookout**: it sends attack-like strings to provoke the WAF. cdncheck gives the passive answer |
| 36 | webanalyze / wappalyzergo | v0.4.6 / v0.3.8 | MIT | Technology fingerprints | **Have**: httpx `-tech-detect` uses wappalyzergo |
| 37 | Corsy | 1.0-rc (2021) | GPL-3.0 | CORS checks | **Don't**: stale, and it sends crafted Origins |
| 38 | jsluice / LinkFinder | untagged (2024) | MIT | JS endpoints and secrets | **Don't**: `jsSecrets.ts` covers the useful part |
| 39 | `metadataLeak` (gospider stays out) | no binary | ours | Document and photo metadata | **Done**: in `exposure`, fed by the base crawl, because gospider ignores robots.txt (rank 1) |

### Vulnerability intelligence

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 40 | PoC-in-GitHub | daily (20261101) | CC0-1.0 | Public PoC exists per CVE | **Add** (rank 6). Metadata only; never fetch the PoCs, some are malware |
| 41 | Exploit-DB (now on GitLab) | rolling | GPL-2.0 | Curated exploit-exists flag | **Add** with 40 |
| 42 | vulnx (formerly cvemap) | v2.0.2 (2026-07-09) | MIT; free PDCP key | KEV, EPSS, PoC and template availability in one lookup | **Maybe**: 40+41 give the same signal without a key |
| 43 | cve-search | v6.0.1 (2026-07-05) | AGPL-3.0 | Local CVE database | **Don't**: persistent server |
| 44 | MITRE ATT&CK (`mitre/cti`) | v20.0 (2026-10-13) | ATT&CK terms | Technique map | **Have**: update from v17 |

### Leaks and reputation (third-party data, no traffic to the customer)

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 45 | Gitleaks on public org repos | v8.30.1 (2026-03-21) | MIT | Leaked secrets in the customer's public code | **Add** (rank 7); bump the 8.21.2 pin (PR #175) |
| 46 | TruffleHog | v3.99.8 (2026-11-02) | AGPL-3.0 | 800+ detectors | **Maybe**: only with `--no-verification`; second engine |
| 47 | abuse.ch URLhaus / ThreatFox | API | Free key; commercial use "may require a paid subscription" via Spamhaus | Customer host listed as a malware URL or C2 | **Maybe**: strong compromise signal, but needs OT-50 to confirm the terms first |
| 48 | IPsum / FireHOL blocklists | daily | Unlicense / mixed per list | Customer IP on public blocklists | **Maybe**: IPsum only (clear licence); a hit is a hint to investigate, never a finding on its own |

### Tenant posture (consented, read-only; Assured add-on)

| # | Tool | Latest (released) | Licence | What it would give Lookout | Verdict |
|---|---|---|---|---|---|
| 49 | Prowler `m365` | 5.47.0 (2026-10-29) | Apache-2.0 | Entra, Exchange, Teams, SharePoint and Defender; CIS M365 | **Add** (rank 9): reuses `prowlerIam.ts`'s install |
| 50 | Maester / ScubaGear / ScubaGoggles | 2.3.0 / v2.0.0 / v1.1.0 (Oct 2026) | MIT / CC0 / CC0 | M365 (CISA SCuBA, EIDSCA) and Google Workspace baselines | **Maybe**: ScubaGoggles for Google Workspace customers; Maester only if Prowler's M365 coverage falls short |

**Left out of the 50 on sight:** DefectDojo and Faraday (we already have
`finding_triage`), Steampipe, CloudFox and Kubescape (not outside-in, or few
SMEs run Kubernetes), OSV-Scanner, Grype and Syft (repo-side; E-78), Spamhaus
DNSBL (commercial use is paid), Certstream (needs a persistent connection), and
SigmaHQ (already planned as link-only "what to log" content).

## Tests

Every **Add** follows rule 15: a pinned release with version **and SHA-256**,
a wrapper through `execTool`, a parser unit test against real captured output
in `fixtures/`, and a `*.integration.test.ts` that runs the real binary against
a hermetic target in `tool-integration.yml`. Each one also gets a test in
`scanProfiles.test.ts` that the tool is in `EXPOSURE_TOOLS` and that
`isNonIntrusiveProfile("exposure")` still holds.

| Tool | Hermetic target in CI | What the integration test asserts |
|---|---|---|
| testssl.sh (**built**: `deepTls.integration.test.ts`) | Node TLS server with a throwaway self-signed cert and TLS 1.0/1.1 enabled | Finds the legacy protocols at both full and non-intrusive scope; an unreachable port gives `error` (rule 7) |
| subfinder | Can't be hermetic (it queries third-party sources), so it stays out of `exposure` | — |
| metadataLeak (**built**: `metadataLeak.crawl.test.ts`, unit suite) | Local HTTP site with robots.txt, a linked PDF, a disallowed PDF and an off-site link | Author and software extracted; the disallowed and off-site files are never requested |
| cdncheck | Fixed IPs from its own bundled ranges (offline) | A known Cloudflare IP is tagged; port scanning skips it; the customer's origin IP is not skipped |
| dnsx | CoreDNS container with a test zone: wildcard, dangling CNAME and AXFR allowed | Records, the wildcard flag and the open-AXFR finding each carry a stable `checkId` |
| ssh-audit | `linuxserver/openssh-server` container configured with `diffie-hellman-group1-sha1` and `ssh-rsa` | Weak KEX and host-key findings; a closed port gives `not_applicable` |
| tlsx | Two `openssl s_server` ports: one expired cert, one self-signed with an extra SAN | Expired and self-signed findings; the SAN host goes into the inventory |
| PoC / Exploit-DB | Unit only: a fixture slice of each dataset | A CVE with a PoC gets the flag; a fetch failure omits the field and never says "no exploit" |
| Gitleaks public repos | Local bare git repo (`file://`) with a fake key in the AWS canary format | Finding redacted (`--redact`); a non-existent org gives `error` |
| Screenshots | Existing Playwright plus a local fixture page | PNG stored; a timeout gives `error` |
| Prowler m365 | No hermetic tenant exists, so hold it out of every default profile (like wpscan). Parser test against captured OCSF output; smoke test `prowler m365 --list-checks` | Parser maps check IDs; `not_configured` without consent credentials |
| CSP Evaluator | Unit only | Known bypass host (a JSONP endpoint on an allowlisted CDN) is flagged |

Scanner accuracy: the path-free tools above don't need a bench fixture (rule
14), but dnsx's AXFR and the screenshot step should get a `bench/expectations`
entry so regressions appear in `npm run bench`.

Copy: per OT-14, nothing here goes into `marketing/17` until its integration
test passes in CI. Update "What Lookout sends to your systems" for ssh-audit
(one SSH handshake per host), tlsx (TLS handshakes on open ports) and dnsx
(one zone-transfer request per name server).
