
# Hebrides Cyber — Platform Strategy
*Draft 2026-10-22. Written for a solo founder with limited weekly capacity (hours not stated in the docs). Opinionated by design.*

---

## 1. Executive summary

1. **The product is closer to a platform than it looks.** The scan engine is a library with no Next.js or React dependency in the files checked; a v1 REST API, bearer keys, webhooks, a CI script, a (private) GitHub Action and SBOM/CSV/compliance exports already exist. A thin CLI over the current API is a small job, not a refactor.
2. **But the API is not yet a product.** No OpenAPI spec, no key scopes, no cursor pagination, no machine-readable error codes, one webhook event, no SARIF, and the Action is unusable because the repo is private. These are the real blockers for CLI, SDK and partners, and all of them are cheap.
3. **The scanner is a feature; continuous monitoring is the product.** A point-in-time scan is what free tools and a CI step give away. The thing UK SMEs and MSPs pay for monthly is "tell me when something changes and what to do about it." The data to do that (finding lifecycle, DNS snapshots, asset inventory, lookalike sweeps, DMARC reports) is already in the schema.
4. **There is a time-boxed market gap.** NCSC retired Web Check and Mail Check on 31 March 2026 and points users at commercial products. Landing pages exist; the campaign is drafted but unsent. Paid sign-up is impossible today because `STRIPE_PRICE_*` is unset. Revenue is blocked by configuration, not by missing features.
5. **Distribution beats features.** For a solo founder the highest-leverage moves are a public Action, a `npx hebrides` CLI, and a CI gate, because each puts the product inside a workflow with no sales effort.
6. **Do not build:** desktop app, mobile app, SIEM, EDR, GRC, a generic ticketing system, a password manager, a VPN, bespoke SDKs in three languages, microservices.
7. **What to build next, exactly:** see the final recommendation (§24).

---

## 2. Current state assessment

### 2.1 What exists (verified in code)
| Area | State |
|---|---|
| Scanner | Base passive suite (pure Node: DNS, TLS, headers, exposure, crawl, etc.) plus 36 extended tools (nuclei, ZAP, nmap, sqlmap, katana, SAST via Opengrep, trivy, etc.). Findings carry stable `checkId`s, remediation text, compliance mapping (CE, ISO 27001, PCI, OWASP, CIS v8, NIS2, DORA), KEV/EPSS/CVSS enrichment. |
| Orchestration | `executeScan()` in `src/lib/scanExecution.ts` is the single implementation, run by queue workers on GitHub Actions against a Postgres `scan_jobs` queue (`claim_scan_job`, SKIP LOCKED). Never called from an HTTP request. |
| API | `src/pages/api/v1/*`: create/list scans, scan result (new/unchanged/fixed tagging), export (CSV/JSON), compliance, remediation pack, CycloneDX SBOM, dependency diff, target trend. ~71 routes total under `/api`. `docs/API.md` (587 lines). |
| Auth | Bearer API keys (`hc_live_…`, SHA-256 hashed, optional CIDR allowlist) or Supabase session JWT, both resolving to `{ownerId, via}`. TOTP MFA. Team roles (admin/developer/auditor/member). |
| Tenancy | Everything keyed on `owner`. Teams are one per owner. `organizations`/`org_members`/`sso_providers` tables exist (migrations 034–037) but **no runtime code uses them [unverified beyond grep]**; related modules were deleted as dead code on 2026-10-13. |
| Integrations | Jira, Linear, GitHub Issues, ServiceNow tickets; PagerDuty/Opsgenie; Slack/Teams; generic SIEM webhook; signed webhooks (`scan.completed` only); GitHub App for fix PRs. |
| Reporting | PDF (Playwright), executive report, portfolio report, compliance report, remediation pack, SBOM, CSV, share links, white-label branding. |
| CI | `public/ci/hebrides-scan.sh` (sh+curl+jq, exit codes 0/1/2, JUnit) with GitHub/GitLab/Azure/Bitbucket/Jenkins templates; `action/` (node20, fails only on **new** untriaged findings, dependency mode on PRs). |
| Monitoring-adjacent | `finding_lifecycle` + SLAs, `dns_snapshots` (attack surface monitor), `asset_inventory`, lookalike-domain sweeps, DMARC RUA ingest (`dmarc_reports`), emerging-threat alerts, scheduled scans. |
| Extensibility | Convention-based, not a registry. A new check = export a result type, add to `ScanResults`/`extended`, add `TOOL_ALIASES`, remediation text, compliance map, bench fixture, test. The `/new-scanner-check` skill and `toolWiring.test.ts` guard it. |

### 2.2 Current architecture
```
 Browser ──► Next.js (App Router pages, client-heavy)
   │            │  AppShell/useAppSession ──► Supabase JS (anon, RLS)
   │            ▼
   │      Next.js Pages Router  /api/*  (71 routes, service-role Supabase)
   │            │   authenticateApiRequest ► key | JWT ► {ownerId}
   │            ├─ POST /run-scan, /v1/scans ──► scans row + scan_jobs row ─┐
   │            └─ Stripe, webhooks, tickets, reports, admin               │
   │                                                                        ▼
 CI (curl/Action) ─► /api/v1/*                          Postgres (Supabase) scan_jobs
                                                                           ▲  claim_scan_job()
 GitHub Actions runners (scheduled-scans.yml, on-demand-scan.yml) ─────────┘
   └─ run-queued-scan-jobs.ts ─► executeScan() ─► scanners/* + worker/tools/* (binaries)
                                      └─► findingLifecycle, webhooks, tickets, SIEM, email
 Hosting: Azure Static Web Apps (hybrid) ; alt: Container Apps (manual path)
```

### 2.3 Answer: could we build a CLI against the current system without major refactoring?
**Yes, as a thin client, with about a week of API hardening — not a refactor.**
- The create → poll → export loop already works over `/api/v1`. `hebrides-scan.sh` is already a crude CLI.
- `npm run scan:local` proves the base passive suite runs from a terminal with no database (`runAllChecks(url)`; Supabase optional).
- What blocks a *good* CLI/SDK: no OpenAPI spec, no key scopes (every key is full-account), no cursor pagination (`limit` ≤ 100 only), errors are `{error: string}` with no code, no idempotency key on `POST /scans`, one webhook event that doesn't fire on post-queue failure, no SARIF, no `GET /scans/{id}/findings` as its own resource, and API scans require a **verified domain** so `hebrides scan example.com` for an arbitrary site cannot work via the API.
- What makes *non-web* use awkward: browser-oriented auth (Supabase session), key management is session-only (correct), the extended tool tier needs binaries (nuclei, nmap, ZAP) that don't exist on a user's laptop.

### 2.4 Things that would make non-web clients difficult
1. Verified-domain gate is account-centric (fine for monitoring, wrong for ad-hoc local scans).
2. Extended tier is Docker-shaped, not binary-shaped.
3. `scanExecution.ts` is welded to Supabase, webhooks, tickets, SIEM — the *orchestrator* is not portable, the *checks* are.
4. Unscoped keys: handing a key to a CI system or a third party grants the whole account.
5. Documentation and marketing claim things the code contradicts (stale), eroding trust with developers.

---

## 3. Target platform architecture

**Principle: a modular monolith with a stable contract, not microservices.** A solo founder gains nothing from independently deployed services; the scaling hotspot (scan execution) is *already* separated — it is a queue plus stateless workers.

```
 Clients                         Contract                  Core (one repo, one deploy + workers)
 Web UI ─────────┐
 CLI ────────────┤
 GitHub Action ──┼──► /api/v1  (OpenAPI 3.1, scoped keys,    ┌ scan service (enqueue/read)
 SDKs (generated)┤     cursor pagination, error codes,       ├ findings/lifecycle
 MSP / 3rd party ┤     idempotency, webhooks v2)             ├ assets & monitoring
 Local agent ────┘                                           ├ reporting/exports
                                                             ├ notifications/integrations
                        ▲                                    └ intel (KEV/EPSS/CT/DNS)
                        │                                              │
        packages/scanner-core  (pure checks, no DB) ◄──────────────────┘
        used by: workers, CLI local mode, agent
```
Concrete moves:
1. **Extract `packages/scanner-core`** (base checks + result/finding types + `runChecks(target, options) → Finding[]`, no Supabase). Workers, CLI local mode and the agent all import it. This is the only structural change that unlocks multiple clients.
2. **Service layer**: move route logic into `src/lib/services/*` (scans, findings, assets) that routes call. Web pages that read Supabase directly under RLS stay as they are — do not rewrite the dashboard to go through the API ("web is one client" is a direction, not a migration project).
3. **Contract-first for the public surface only** (`/api/v1`). Internal routes remain internal.

How close are we? **~60%.** Engine separated, queue separated, API exists. Missing: the contract, the package boundary, scoped identity.

---

## 4. API strategy

**Yes — a public API is worth owning, because it is the substrate for CLI, Action, MSP and partners.** Keep it boring.

| Capability | Verdict | Reason |
|---|---|---|
| REST + JSON, `/v1` prefix | **Do** (exists) | Matches the stack. |
| OpenAPI 3.1 spec | **Do now** | Enables docs, SDK generation, contract tests. Generate from zod schemas (zod already used by `parseBody`). |
| Scoped API keys (`scans:read`, `scans:write`, `findings:read`, `assets:read`, `reports:read`) | **Do now** | Biggest safety gap; prerequisite for CI and partners. Default new keys to least privilege; keep legacy keys as `all` until rotated. |
| Machine-readable errors `{error:{code,message,doc_url}}` | **Do now** | Cheap; SDK/CLI need it. |
| Cursor pagination | **Do now** for lists | `limit` cap alone breaks at scale. |
| Idempotency-Key on `POST /scans` | **Do** | CI retries; dedupe by in-flight scan exists, formalise it. |
| Webhooks v2 (events: `scan.completed`, `scan.failed`, `finding.new`, `finding.fixed`, `asset.new`, `monitor.change`) + a delivery queue/retries | **Do next** | One event today; SIEM integration already has the event vocabulary to reuse. |
| Rate-limit headers (`X-RateLimit-*`) + documented numbers | **Do now** | Docs currently say two sentences. |
| New endpoints: `GET /scans/{id}/findings`, `/assets`, `/assets/{id}`, `/findings`, `/posture` | **Do next** | Data exists; mostly projections. |
| `GET /vulnerabilities` (global CVE catalogue) | **Do not** | Not our data; point at NVD/OSV. |
| OAuth2/OIDC for third parties | **Defer** | Needed only when a partner app acts on behalf of customers. Device-code flow for the CLI is the one OAuth piece worth building (below). |
| Service accounts | **Defer** | Scoped keys cover it until orgs are real. |
| SDKs | Generate from OpenAPI (see §10). |
| Versioning | `/v1` stable, additive-only; deprecation header policy; no `/v2` until forced. |
| Audit logging | **Exists** (`logAuditEvent`); add key id to the audit actor. |

---

## 5. CLI strategy

**Build it — as a thin, excellent client first. Local scanning is a differentiator but second.**

### 5.1 Command design (not assuming your names)
```
hebrides auth login            # device-code flow → stores a scoped token in OS keychain
hebrides auth status|logout
hebrides scan <url>            # cloud scan of a verified target; waits; prints summary
  --profile safe|full|api|cms|osint   --fail-on <sev>   --new-only   --baseline <scan|tag>
  --format table|json|sarif|csv|junit|html   --output <file>   --no-wait
hebrides check <url>           # LOCAL passive checks only (headers/tls/dns/email), no account needed
  hebrides check headers|tls|dns|email <host>   # focused subcommands = great demos
hebrides findings list|show|triage   # accept / false-positive / snooze, as in the web UI
hebrides targets add|list|verify|rm      # monitored targets + ownership verification help
hebrides report <scan>         # pdf|html|md|compliance|sbom|remediation-pack
hebrides policy check          # evaluate a policy file (see §7)
hebrides doctor                # connectivity, auth, clock skew, docker/tools present, version
```
### 5.2 Modes
| Mode | Needs account | Where it runs | Use |
|---|---|---|---|
| **Cloud** | yes | our workers | Full suite, history, diffing, tickets. Default for `scan`. |
| **Local passive (`check`)** | **no** | user's machine, `scanner-core` | Anonymous, instant, great top-of-funnel. User is the actor (like `nmap`), so no domain-ownership proof is needed — but ToS wording must say so, and active/intrusive checks stay out. |
| **Local full** | optional | Docker image with tools | Private/internal targets; same engine as the agent. |
| **Hybrid** | yes | local scan, results uploaded | Internal app scanned locally, tracked in the cloud. Later, via the agent. |

### 5.3 Output and CI behaviour
- Exit codes: `0` pass, `1` policy failure (findings at/above threshold, **new-only by default**), `2` could not scan (tool/network/auth error — never green on uncertainty, matching the existing evidence rule), `3` usage error.
- `--format sarif` (SARIF 2.1.0) for GitHub Code Scanning; `junit`; `json` stable schema; `csv`; `html` self-contained report.
- `--quiet` (result only), `-v/-vv` (debug, redacts secrets), `NO_COLOR`, non-TTY auto-plain, `--json` shorthand.
- Config precedence: flags > env (`HEBRIDES_API_KEY`, `HEBRIDES_PROFILE`) > `./hebrides.yml` > `~/.config/hebrides/config`. Profiles (`--profile ci`).
- Secrets: never accept keys as positional args; prefer env/keychain; redact in logs; `hebrides auth login` stores a short-lived refresh token, not the long-lived key.
- Honest scoping: **anonymous local `check` must never print "compliant"/"certified"** — same language rules as the existing Cyber Essentials indicator.

### 5.4 Local vs API split
Local: pure passive checks in `scanner-core`, report rendering, policy evaluation, SARIF/CSV formatting. API: anything needing history (new vs fixed), triage state, ownership verification, extended tools, tickets, notifications, shared reports.

---

## 6. Distribution strategy

### 6.1 Language decision
| Option | For | Against | Verdict |
|---|---|---|---|
| **TypeScript/Node** | The scanner-core is TS; one team of one; `npx hebrides` works with zero install; shares zod/types | Needs Node (or a bundled runtime); larger binaries | **Choose.** |
| Go | Tiny static binaries, best packaging story | Rewrites nothing useful (checks stay in TS); a second language for a solo dev | Revisit *only* for the agent if size/footprint becomes a real complaint. |
| .NET | Good tooling | Zero reuse; no .NET in the stack | No. |
| Rust | Fast, safe | Highest cost; no reuse | No. |
| Python | Familiar to security folk | Zero reuse; packaging pain | No. |

### 6.2 Channels (in order)
1. **npm** `hebrides` (`npx hebrides check example.com`) — zero-friction, matches the audience (web/dev teams). Publish with provenance and 2FA.
2. **Docker image** `ghcr.io/…/hebrides` — the *only* sensible way to ship the extended tool tier (nuclei, nmap, ZAP). Doubles as the agent and the CI container.
3. **GitHub Releases single-file binaries** via Node SEA (or `pkg` successor) for Win/macOS/Linux, with SHA-256 + cosign signatures.
4. **Public GitHub Action** (needs a public repo or marketplace repo) — highest-leverage channel for developers.
5. **Homebrew tap, Scoop, winget** — cheap once binaries exist (manifest PRs). **Chocolatey** is worth doing for UK SME/MSP Windows admins (moderation lag; do after winget).
6. **Do not** do .deb/.rpm/Snap/Flatpak/.NET tool initially.

Signing: Windows code-signing certificate is a real cost (~£/yr) — without it SmartScreen warns; defer binaries-on-Windows behind npm/winget until revenue justifies it.

---

## 7. CI/CD strategy

**Genuinely valuable, and the codebase is already ahead of the docs.** It is the lowest-friction wedge into developer teams and agencies.
- Already good: fail on **new, untriaged** findings only, baseline = previous scan, dependency PR comments, five CI templates.
- Missing, in value order:
  1. **Publish the Action** (blocked on a public repo — an owner action, ~1 hour).
  2. **SARIF output → GitHub Code Scanning** (inline PR annotations, Security tab). Highest ROI single feature.
  3. **PR summary** (job summary markdown) and optional PR comment.
  4. **Named baselines** (`--baseline main`) instead of only "previous scan".
  5. **Policy-as-code** `hebrides.yml`: `fail_on`, `max_age`, per-check overrides, suppressions with expiry and justification (reuse triage states), `policy: cyber-essentials` preset mapping to the existing CE control mapping.
  6. Azure DevOps task / GitLab component wrappers (thin shells over the CLI).
- **Product bloat check:** a *generic* DAST-in-CI product is bloat (Snyk, StackHawk own it). The valuable, defensible slice is: *"your deployed site/domain posture and dependencies gate your pipeline, with UK-friendly compliance mapping."* Keep CI scoped to **deployed-target posture + dependency diff + SBOM/VEX**, not SAST/IaC breadth.

---

## 8. Local / private scanning agent

**Strategically worthwhile — but later, and as a Docker container, not a desktop agent.**
- Why worthwhile: internal sites, dev/staging, intranets and private APIs are invisible to a cloud scanner; it moves us from "website scanner" to "estate scanner" and is a clear paid-tier (Business/Agency) driver.
- Why not now: it is the highest security-risk item on the roadmap. We would be shipping software that runs inside customer networks and executes our job definitions.
- Required design (non-negotiable):
  - **Outbound-only** HTTPS/WSS poll to `/agent/v1/jobs`; no inbound port.
  - **Enrolment token → per-agent keypair**; jobs are **signed by us** and verified by the agent; the agent runs only a fixed allowlist of check types (no arbitrary commands).
  - **Scope allowlist set locally** by the customer (CIDRs/hostnames); the cloud cannot widen it.
  - Runs as a non-root container, read-only FS, no host network by default, resource limits.
  - Results encrypted in transit; credentials for authenticated scans stay local (never uploaded) — big trust win.
  - Per-tenant isolation by agent identity; automatic updates via signed images; kill switch.
- Dependencies: scoped keys, scanner-core, job-signing infrastructure, webhooks v2. **Defer until ≥ ~10 paying customers ask for internal scanning.** Until then the CLI-in-Docker covers the need manually.

---

## 9. Desktop application decision

**Do not build one.** A desktop app delivers nothing the web UI + CLI don't: it can't scan more (no extra network vantage over the CLI), can't monitor continuously (laptops sleep), and adds code-signing, auto-update and three-OS support burden for a solo developer. If a "local" experience is ever wanted, a **PWA** of the existing dashboard (a manifest already exists) is the zero-cost option. Revisit only if the agent needs a GUI for non-technical installers — and even then, prefer a tiny local web UI served by the agent over Electron/Tauri.

---

## 10. SDK strategy

- **Generate, don't hand-write.** From the OpenAPI spec, generate TypeScript first (`openapi-typescript` + a ~100-line fetch wrapper) — it is also what the CLI imports, so it is exercised daily.
- Python second (agency/security-scripting audience) via `openapi-python-client`; **.NET only on demand** (MSPs on Microsoft stacks may ask — UK SME channel is Microsoft-heavy, so keep it on the watch list).
- No bespoke SDK maintenance until a paying customer needs it. Contract tests (spec vs routes) prevent drift.

---

## 11. Extensible scanner architecture

Do **not** build a runtime plugin marketplace. The current convention is fine for first-party checks; formalise it lightly:
```ts
interface Check<R> {
  id: string;                         // "headers", "tls", ... (maps to checkId prefix)
  tier: "passive" | "active" | "offensive";
  requires: { network?: boolean; binary?: string[]; credentials?: boolean };
  run(ctx: ScanContext, signal: AbortSignal): Promise<R | CheckError>;   // error ≠ empty (evidence rule)
  toFindings(result: R): Finding[];   // pure
}
```
- A single `registry.ts` replaces the hand-wiring in `scanners/index.ts`, `scanExecution.ts`, `TOOL_ALIASES`, `BASE_ALIASES`, `scanProfiles.ts`. `toolWiring.test.ts` (now added) becomes the registry's contract test.
- `tier` encodes the existing offensive gate; `requires.binary` lets the CLI/agent report "tool not installed" truthfully.
- **Third-party plugins: no.** Untrusted code in a scanner that holds customer credentials is a security liability. Offer *data* extension instead: custom nuclei templates and custom regex secret rules per account, executed inside the existing sandboxed tools.
- Priority: low. Do it when the CLI/agent make the duplication painful, not before.

---

## 12. Product portfolio opportunities

Scoring uses the matrix in §17. "Verdict" = BUILD / PARTNER / INTEGRATE / IGNORE.

| # | Product | Customer problem | Target | Reuse | Competition | Differentiator | Revenue | Complexity | Risk | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| **B** | **Continuous External Monitoring** (change detection: TLS expiry, DNS, headers, ports, tech, new CVEs, CT events, email posture) | "Tell me when something I own gets worse" | UK SMEs, MSPs, agencies | ~80% (lifecycle, dns_snapshots, schedules, alerts) | Intruder, Detectify, HostedScan, Astra | Price (£20 entry), UK compliance mapping, new/fixed diffing, evidence discipline | **High** (recurring) | Low–med | Low | **BUILD NOW — this is the core proposition.** |
| **A** | **Attack Surface Management** (domains, subdomains, IPs, certs, cloud, tech, shadow IT) | "What do we expose?" | SMEs/MSPs; Web Check refugees | `asset_inventory`, `easmDiscovery`, CT, naabu/nmap | Detectify, Intruder, Censys, Shodan Monitor | "Web Check successor" for UK SMEs | High | Med | Med (scanning unknown assets = authorisation) | **BUILD NEXT** — make discovery continuous and *propose-then-confirm* ownership. Same product as B, sold on a different pain. |
| **D** | **Cyber Essentials readiness** | "Pass CE for a tender" | Trades, charities, suppliers | CE mapping + self-assessment assistant (in progress) | IASME assessors, Vanta-lite tools | UK-native, cheap, honest scope | Med–High (strong acquisition hook) | Low | **Legal wording risk** | **BUILD NOW (finish)** — verifiable / attestable / manual separation (see §12.1). Never claim certification. |
| **H** | **Remediation management** | Finding → owner → fix → verify → closed | Dev teams, MSPs | Tickets, SLAs, retest, fix PRs, lifecycle | Jira itself; Vanta/Drata workflows | Auto-verify via re-scan, fix PRs | Med (retention driver) | Low | Low | **BUILD (finish)** — an *integration* layer, not a ticketing system. |
| **G** | **Reporting / board reporting** | Explain posture to non-technical people | SMEs, MSPs, auditors | PDF, executive report, portfolio, white-label | SecurityScorecard exports | Plain-English + trend + compliance | Med (MSP upsell) | Low | Low | **BUILD NEXT** (monthly digest → board pack). Strong MSP value. |
| **F** | **Brand / domain protection** | Lookalike/phishing domains | Brands, agencies | `lookalikeDomainMonitor`, CT | Bolster, ZeroFox, Netcraft | Cheap, bundled | Med | Low (passive exists) | Low | **BUILD (bundle into B)** — already shipped in basic form. No takedown service. |
| **C** | **Posture score** | One number to track | All | `scoreFromFindings`, riskScore | Everyone | Transparent, decomposed | Supports retention | Low | **Vanity-metric risk** | **KEEP, but constrain** (§12.2). |
| **J** | **AI assistant** | Explain/prioritise/translate | All | `aiRemediation`, findings, history | Everyone claims AI | Grounded in *our evidence only* | Low direct; helps retention | Low | Data-privacy | **BUILD NARROWLY** (§12.3). |
| **I** | **API security** (OpenAPI/Postman ingest) | Test my API | Dev teams | `apiSpec` scanner exists | StackHawk, 42Crunch | — | Med | Med | Med | **INTEGRATE/maintain, don't expand** — already there as a profile; deeper business-logic testing is a rabbit hole. |
| **E** | **Supplier / third-party risk** | Monitor suppliers' posture | Mid-market procurement, public sector | EASM + score | SecurityScorecard, BitSight, UpGuard | UK public-sector lane (founder background) | Med–High | Med | **High** (accuracy, defamation, scanning third parties w/o consent) | **RESEARCH** — only passive, already-public data; opt-in supplier invitations ("claim your profile"); defer until monitoring has volume. |
| — | **MSP multi-tenant console** | Manage many clients | MSPs/agencies | partner portal, white-label | HostedScan, Intruder MSP | Reseller billing + client portals | **High** (multiplier) | Med–High (real tenant model) | Med | **BUILD NEXT-NEXT** — the highest-leverage commercial structure, but needs the tenant model decision (§16). |
| — | **Cyber Index / benchmarking** | "How do I compare?" | Everyone; press | aggregated findings | Few | k-anonymised local-sector benchmarks | Indirect (marketing + flywheel) | Low–med | Privacy | **BUILD LATER** (spec exists; needs consent in privacy policy first). |

### 12.1 Cyber Essentials — what we can and cannot claim
| Verifiable externally | Customer must attest | Needs manual/assessor |
|---|---|---|
| Open ports/firewall exposure (from outside), TLS/patch indicators on exposed services, exposed admin interfaces, outdated public software, malware indicators on public pages | Device inventory, MDM/BYOD policy, MFA on cloud accounts, admin-account separation, patching process, backups, malware protection on endpoints | Boundary firewall rules, internal configuration, scoping, the formal IASME assessment |
Product rule: output is a **readiness indicator + guided self-assessment**, never "compliant". The existing wording ("not a Cyber Essentials certification") is correct and must remain.

### 12.2 Score integrity (avoiding a vanity metric)
- Publish the formula; show **per-category sub-scores** and "what moved the score" every time.
- Never roll "not checked" up as "good": unknown categories show as *unknown*, and the headline score displays coverage ("based on 11 of 14 checks").
- Weight by exploitability evidence (KEV/EPSS already) not finding count; cap one finding's impact (already 45).
- Prove calibration over time: back-test (do low-score sites get breached/compromised more?) before marketing the number; until then sell the *delta and the list*, not the number.
- Don't compare scores across different coverage levels or plan tiers.

### 12.3 AI — only where it earns its place
Legit: explain a finding for a non-expert; tailor remediation to the detected stack (exists); summarise a month for a board; cluster duplicate findings; draft a ticket. Constraints: send only the finding text + tech stack, never credentials/crawled content/customer data; opt-in; EU/UK-region model endpoint; label AI text as generated; **never let a model decide severity or "fixed" status** — those stay deterministic and evidenced. Do not build an "AI pentester" for general customers (Strix/Cairn path: licensing — Cairn is AGPL — and liability).

---

## 13. Ideas we should NOT pursue (and why)
| Idea | Why tempting | Why not | Better |
|---|---|---|---|
| Full **SIEM / SOC platform** | Big market, logs are sticky | Needs ingestion at scale, 24/7 expectations, detection engineering | **Integrate** (SIEM webhook exists); push to Sentinel/Splunk/Wazuh |
| **EDR / antivirus / MDR** | Endpoint is where breaches happen | Enormous R&D, agents on every device, liability | **Partner** (Defender/CrowdStrike resellers) for CE endpoint evidence |
| **Password manager / VPN** | Everyone needs them | Commodity; trust and crypto burden | **Ignore** |
| **Generic ticketing / workflow** | Remediation needs it | Jira/ServiceNow already own it | **Integrate** (exists) |
| **Full GRC platform** (policies, risk register, audits) | Compliance buyers pay well | Vanta/Drata/Sprinto dominate; huge surface | Stay at *evidence from external scanning* feeding their tools; export, don't compete |
| **General pentest platform / managed pentest marketplace** | High ticket | Human delivery, CREST, liability, solo capacity | Keep Tier A narrow; **partner** a CREST firm for referrals |
| **Mobile app** | "Real product" feeling | No unique capability; push notifications work via email/Slack/PWA | **Ignore** |
| **Desktop app** | See §9 | | **Ignore** |
| **Own vulnerability database** | Differentiation | NVD/OSV/KEV/EPSS cover it | **Consume** |
| **Cloud posture (CSPM) breadth** | Growth segment | Wiz/Defender own it; consent + credentials burden | Keep the shipped narrow IAM/storage checks; no expansion |
| **Dark-web credential monitoring** | Scary = sellable | Needs data partnerships | **Partner/resell** HIBP-class data if demanded |
| **Third-party plugin marketplace** | Ecosystem dream | Untrusted code near customer secrets | Data-level extensions only |
| **Takedown service** for lookalike domains | Natural next step | Legal/operations, per-registrar work | **Partner** |

---

## 14. Build vs buy vs partner
| Capability | Decision | Notes |
|---|---|---|
| Scan engine, scoring, lifecycle, reports | **Build** | Core IP |
| Cert transparency, KEV, EPSS, NVD/OSV | **Consume** public feeds | Cache them (currently refetched per scan) |
| Subdomain/port discovery | **Build on** OSS (naabu, nmap, nuclei) | Pin and verify binaries (worker image) |
| Email delivery, billing, auth, DB | **Buy** (Resend, Stripe, Supabase) | Keep portable (plain Postgres) |
| SSO | **Buy/leverage** Supabase SAML | Don't build an IdP; tables exist |
| Code signing, SBOM tooling | **Buy** | Cert + cosign |
| Human pentest / CREST work | **Partner** | Referral model |
| Endpoint, MDR, SIEM | **Partner/integrate** | |
| Dark-web / takedown | **Partner** | |
| AI model | **Buy** (Azure OpenAI, UK/EU region) | Behind an interface; swappable |

---

## 15. Free / paid / enterprise ladder
Current: Free (1 scan ever), Basic £20 (1 site, weekly), Pro £35 (3 sites, daily, CI, Slack), Agency £75 (15 sites, teams, white-label, auth scan), Tier A (offensive, contact us). Paid sign-up is **not live**.

**Recommended restructure** — price on the unit customers feel (monitored domains + who consumes it), not on scan frequency:
| Tier | Who | Core value | Upgrade trigger |
|---|---|---|---|
| **Free** | Anyone | Unlimited **local CLI `check`** + 1 cloud scan + public score badge | Wants history/alerts |
| **Monitor** (£20) | Sole trader, 1 domain | Continuous monitoring, change alerts, email posture, CE readiness | Second domain / wants CI |
| **Team** (£35–45) | Small SaaS/agency | 3–5 domains, CI gate/Action, Slack/Teams, tickets, fix PRs, dependency monitoring | Clients / reporting |
| **MSP** (from £75, per-client packs) | Agencies/IT firms | Client workspaces, white-label reports, consolidated portfolio view, reseller pricing | Scale / compliance |
| **Business/Enterprise** (contact) | Larger/regulated | SSO, scoped keys/service accounts, private agent, audit export, SLA | Procurement |
| **Tier A** (add-on) | Authorised offence testing | Per-target authorised active testing | — |
Natural upgrade levers: domains count, history retention, API/CI access, white-label, agent, SSO. Keep the Western Isles discount as a campaign, not a tier. **Challenge:** the free tier should be *the CLI*, not "1 scan ever" — a finite scan gives no habit; a free local tool does, at near-zero marginal cost.

---

## 16. Product flywheel
```
Free CLI/Action in dev workflows ─► accounts that monitor domains
        ▲                                    │
        │                          history, diffs, asset graph
public score badge/NCSC-gap SEO              │
        │                                    ▼
   MSP resale/white-label ◄── better prioritisation, benchmarks (k-anonymous), fewer false positives
```
Genuine, privacy-safe network effects:
1. **False-positive/triage corpus**: accepted/false-positive decisions per `checkId` improve default severity and confidence for everyone (aggregate counts only, no site data).
2. **Sector benchmarks** ("sites like yours"): k-anonymised (k ≥ 10), opt-in via privacy policy — the Cyber Index.
3. **Time-to-fix data** → realistic SLA defaults and remediation guidance ordering.
4. **Distribution loops**: CI Action and badges expose the brand inside customers' repos and sites; MSP white-label reports expose it to the MSP's clients.
Not defensible: raw "more scans" or vulnerability counts (public data, easily replicated). Be honest that the moat is workflow position and UK-specific trust, not data volume, for the next 2–3 years.

---

## 17. Architecture evolution plan (incremental; the product stays live throughout)
| Step | Why | Unlocks | Depends on | Migration impact | Risk | When |
|---|---|---|---|---|---|---|
| 0. Turn on payments; set Sentry, `CREDENTIALS_ENC_KEY`; restore drill; publish Action repo | Revenue/reliability | Everything | owner actions | none | none | **Now** |
| 1. **OpenAPI + error codes + cursor pagination + rate-limit headers** for `/v1` (additive) | Contract | SDKs, CLI, docs | zod schemas | additive only | low | **Now** |
| 2. **Scoped API keys** (migration; legacy = all) | Safe CI/partners | Action, agent, MSP | 1 | one migration; UI change | low–med | **Now** |
| 3. **Extract `packages/scanner-core`** (base checks, types, no DB) | Reuse | CLI local mode, agent | none | monorepo/workspace move; keep imports via alias | **med** (largest refactor; do behind tests: bench + 3.4k unit tests) | **Next** |
| 4. **CLI (TS) as thin client + local `check`** | Distribution | npm/winget/brew | 1,2,3 | none | low | **Next** |
| 5. **SARIF + policy file + named baselines + public Action** | CI wedge | GitHub Security integration | 1,2 | none | low | **Next** |
| 6. **Service layer** (`lib/services/*`) behind routes | Consistency | cleaner API growth | 1 | internal | low | Opportunistic |
| 7. **Webhooks v2 + delivery queue** | Integrations | partners, SIEM parity | 1 | new table | low–med | Next |
| 8. **Pinned worker image** (Docker) with checksummed tools | Reliability, tool tier for CLI/agent | agent | none | CI change | low | Next |
| 9. **Tenant model decision** (use `organizations` or `client_label` on `monitored_targets`) | MSP product | reseller, client workspaces | product decision | schema | **med–high** | Later (decide now, build when 5+ MSPs ask) |
| 10. **Agent** (signed jobs, outbound-only) | Internal scanning | enterprise | 2,3,8 | new service surface | **high** | Defer |
| 11. Scanner registry/plugin interface | Maintainability | faster checks | 3 | internal | low | Opportunistic |
Challenge to the proposed sequence: **move the public API ahead of "extract core scanner"**, and the *Action + SARIF* ahead of the full CLI — they are cheaper, already half-built, and reach users sooner. Extraction (3) is needed for local mode but not for the thin CLI, so don't block on it.

---

## 18. Prioritised backlog (decision matrix)
Scores 1–5 (5 = best; for complexity/risk columns 5 = *low* burden). Total is unweighted guidance, not arithmetic truth.

| Item | Cust value | Strategic | Differentiation | Revenue | Tech complexity | Ops complexity | Security risk | Reuse | Time to MVP | Defensibility | Class |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Enable payments / fix launch blockers | 5 | 5 | 1 | 5 | 5 | 5 | 5 | 5 | 5 | 1 | **BUILD NOW** |
| OpenAPI, error codes, pagination | 4 | 5 | 2 | 3 | 4 | 5 | 5 | 5 | 4 | 2 | **BUILD NOW** |
| Scoped API keys | 4 | 5 | 2 | 3 | 4 | 5 | 4 | 4 | 4 | 2 | **BUILD NOW** |
| Public Action + SARIF + policy | 5 | 5 | 3 | 4 | 4 | 5 | 5 | 5 | 4 | 3 | **BUILD NOW** |
| Continuous monitoring (change alerts, retention, monthly digest) | 5 | 5 | 4 | 5 | 4 | 4 | 5 | 5 | 3 | 4 | **BUILD NOW** |
| Cyber Essentials assistant (finish) | 5 | 4 | 4 | 4 | 4 | 5 | 3 | 5 | 4 | 3 | **BUILD NOW** |
| CLI thin client + local `check` | 4 | 5 | 4 | 3 | 4 | 4 | 4 | 4 | 3 | 3 | **BUILD NEXT** |
| Extract scanner-core | 3 | 5 | 1 | 2 | 2 | 5 | 5 | 5 | 3 | 1 | **BUILD NEXT** |
| Continuous ASM (discover→propose→confirm) | 5 | 5 | 4 | 4 | 3 | 3 | 3 | 4 | 3 | 4 | **BUILD NEXT** |
| Board/monthly reports | 4 | 4 | 4 | 3 | 4 | 5 | 5 | 5 | 4 | 3 | **BUILD NEXT** |
| Webhooks v2 | 3 | 4 | 1 | 2 | 4 | 4 | 4 | 4 | 4 | 1 | **BUILD NEXT** |
| MSP console (tenant model) | 5 | 5 | 4 | 5 | 2 | 3 | 3 | 3 | 2 | 4 | **BUILD NEXT-NEXT** |
| Cyber Index | 3 | 4 | 4 | 2 | 3 | 4 | 3 | 4 | 3 | 4 | **DEFER** (consent first) |
| Supplier risk | 3 | 3 | 3 | 4 | 2 | 3 | 1 | 3 | 2 | 3 | **RESEARCH** |
| Private agent | 4 | 4 | 3 | 4 | 1 | 2 | 1 | 3 | 1 | 3 | **DEFER** |
| Generated SDKs (TS, Python) | 3 | 3 | 1 | 2 | 5 | 5 | 5 | 5 | 5 | 1 | **BUILD NEXT** (cheap) |
| Registry/plugin interface | 2 | 3 | 1 | 1 | 3 | 5 | 4 | 5 | 3 | 1 | **DEFER** |
| AI explain/summarise (narrow) | 3 | 3 | 2 | 2 | 4 | 4 | 3 | 4 | 4 | 1 | **BUILD (opportunistic)** |
| Desktop / mobile app | 1 | 1 | 1 | 1 | 1 | 1 | 3 | 1 | 1 | 1 | **DO NOT BUILD** |
| SIEM / EDR / GRC / VPN / password manager | 2 | 1 | 1 | 3 | 1 | 1 | 1 | 1 | 1 | 1 | **DO NOT BUILD** |

---

## 19. 12-month roadmap (solo-founder realistic; ~1 meaningful thing per quarter-month)
**Phase 1 — Scanner foundation (now → +1 month):** payments live, Sentry/encryption key/restore drill, CSP deploy verified, worker image with pinned tools, finish the detection queue (CE assistant, network exposure, JS secrets), public Action repo, send the NCSC campaign. *Prereq:* owner actions listed in NEXT-STEPS.
**Phase 2 — Platform foundation (months 1–3):** OpenAPI + errors + pagination, scoped keys, rate-limit docs, key id in audit log, tenant-model decision recorded (ADR), start `scanner-core` extraction behind the bench + unit suites.
**Phase 3 — Developer platform (months 3–5):** CLI (thin + local `check`), SARIF + policy file + named baselines, npm + GHCR image + GitHub Releases, winget/Homebrew manifests, generated TS/Python SDKs, docs site for API/CLI.
**Phase 4 — Continuous security (months 5–8):** change-detection alerts (webhooks v2: `finding.new/fixed`, `monitor.change`), continuous discovery with propose-then-confirm ownership, retention/history UI, monthly digest and board report, lookalike + DMARC bundled into the monitoring tier.
**Phase 5 — Commercial platform (months 8–10):** pricing restructure (Free CLI / Monitor / Team / MSP / Business), MSP client workspaces + reseller pricing, SSO via Supabase SAML, audit export, SLA/uptime page, ToS/PI/CREST items from the HIE plan.
**Phase 6 — Expansion (months 10–12+):** Cyber Index (after consent), supplier-risk research with 5 design partners, agent design + threat model (build only on demand), narrow AI explainers.

---

## 20. 3-year vision
**Conservative (the sustainable lifestyle business):** the default external-posture monitor for UK micro/SME businesses and the small agencies/MSPs that serve them; ~£5–15k MRR; one founder + one contractor; known for honest, plain-English, UK-compliance-mapped monitoring and a great CI gate. Route: monitoring + CE readiness + MSP resale.
**Ambitious (UK SME security platform):** continuous EASM + posture + remediation workflow + MSP console + agent, 1–2 engineers, ~£50–100k MRR, partnerships with Cyber Essentials assessors and insurers (posture data for underwriting). Route: the flywheel in §16 plus MSP channel.
**Moonshot (UK trust layer for small-business cyber risk):** an externally-verifiable posture signal used by insurers, procurement frameworks and supply chains ("Cyber Essentials, continuously, evidenced") — a Credit-Score-for-cyber for SMEs, k-anonymised benchmarks, public-sector supplier assurance. Route: Cyber Index + supplier monitoring + insurer/aggregator partnerships; needs credibility (CREST, ISO 27001, independent score validation) and capital.

---

## 21. Moonshot opportunities
1. **Insurance data feed**: underwriters pay for continuous, consented external posture for SME policies.
2. **Procurement trust badge**: public-sector frameworks accept a continuously monitored posture attestation alongside CE.
3. **Open-source passive engine + commercial cloud** (open-core): building developer trust and distribution; risk is cloning — decide deliberately (§22 decision 5).
4. **Regional resilience programme**: Highlands & Islands SME security network, grant-funded, anonymised sector index.
5. **Agent-delivered "internal" posture** for CE (endpoint evidence attested by the customer, collected by the agent).

---

## 22. Top 10 decisions to make now
1. **What is the core proposition?** Recommend: *continuous external monitoring for UK SMEs/MSPs*, with the scanner as its engine.
2. **Public API as a product commitment** (additive-only `/v1`, OpenAPI as source of truth).
3. **Scoped keys before any new client ships.**
4. **CLI language: TypeScript**, distribution: npm + Docker + GitHub Releases.
5. **Open-core or closed?** Recommend: open-source the *CLI client and the passive check engine* (Apache-2.0) once extracted; keep monitoring, history, intelligence, reporting, integrations and the extended-tier orchestration proprietary. Decide before extraction so licensing is clean. (Counter-risk: easy to fork the passive checks — but they're commodity; the value is history and workflow.)
6. **Tenant model for MSPs:** extend `monitored_targets` with `client_label` (spec feature 21) vs activate `organizations`. Recommend the lighter path unless an enterprise customer demands orgs.
7. **Free tier = local CLI**, not "1 scan ever".
8. **Authorisation model for local scanning** (ToS text: the person running it is responsible; no intrusive checks locally).
9. **Pricing unit = monitored domains**; remove scan-frequency as the main lever.
10. **Scope discipline:** formally adopt the "do not build" list (§13) as policy; every new idea must replace something.

## 23. Top 10 things to deliberately NOT build yet
1. Private agent. 2. Desktop/mobile apps. 3. Supplier-risk product. 4. Plugin marketplace. 5. Bespoke SDKs beyond generated TS/Python. 6. Microservices / separate API deployment. 7. Own vulnerability database. 8. SIEM/EDR/GRC features. 9. AI pentest for general customers. 10. OAuth provider for third parties.

**Stale docs this strategy contradicts (fix after approval):** `docs/24-FEATURE-EXPANSION-SPEC.md` (says nothing implemented), `COMPETITIVE-ANALYSIS.md` §5/§573 (authenticated scanning, lookalike "open candidate"), `docs/API.md` (verify claims vs routes; add rate-limit numbers), marketing 03/05/07/11/16 (per the earlier docs audit).

---

## 24. Final recommendation
**If this were my company and I had limited capacity, I would build — in this exact order:**
1. **Turn on payments and publish the Action repo** (days, not weeks — it is configuration, and without it nothing else matters).
2. **Ship the "monitor" promise before any new client:** change alerts + monthly digest on the engine you already have (finding lifecycle, DNS snapshots, lookalike sweeps, DMARC reports), sold to UK SMEs leaving NCSC Web Check and to agencies.
3. **In parallel, make the API a product (OpenAPI, scoped keys, errors, pagination)** — ~2 weeks, and everything else (CLI, SDK, Action, MSP) is cheap afterwards.
4. **Then a thin `hebrides` CLI with a free local `check` and a SARIF-emitting public Action.** This is the cheapest distribution you can buy: it puts the brand in developers' terminals and pipelines, feeds the free tier, and reuses ~100% of the existing API.

**Why this and not the agent/desktop/SIEM:** each step makes the next cheaper — the monitor needs the data you already have; the API contract makes the CLI, SDKs, Action and MSP console incremental; the CLI/Action create the funnel the monitor monetises. It is also the lane where you are genuinely differentiated (UK-compliance mapping, honest evidence discipline, £20 entry price against $39–$99 competitors) rather than competing head-on with Wiz, Snyk or Intruder.

**Assumptions I challenge:** (a) "downloadable product" ≠ desktop app — it should be a *CLI + container + Action*; (b) a better scanner is not the next product, **change detection is**; (c) the free tier should be a tool people keep using, not one scan; (d) the biggest revenue risk today is a missing Stripe price ID, not a missing feature; (e) the "platform" label is earned by a contract (OpenAPI + scopes), not by splitting services.

