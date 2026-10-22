# Strategy & tooling review — 2026-10-22

A planning pass written while deferring launch ~2–4 weeks to harden the product.
Covers: stale-branch tidy-up, delivery audit of the 5-sprint plan, deferred work
worth doing now, the owner's manual (non-code) TODO list in detail, an updated
roadmap + sprint plan for the runway, competitor gaps, 50 tools not yet wired
(with a keep/skip call each), and spitball ideas.

Source-of-truth note: this is a dated review (like `PRODUCT-REVIEW-2026-10.md`).
Where it proposes changes to near-term ordering they belong in `SPRINT-PLAN.md`,
and stage-gate changes in `ROADMAP.md`, once agreed.

---

## 1. Stale branches — nothing to cherry-pick; prune

Every remote branch without an open PR is already in `master` (verified by file
presence, not just branch names), so there is nothing to resurrect:

| Branch | Feature | Already in master as |
|---|---|---|
| `claude/dedupe-findings` | cross-tool dedup | `src/lib/findingConsolidation.ts` + corroboration tests |
| `claude/e74-findings-view` | cross-site findings view | `src/app/dashboard/findings/` |
| `claude/e2e-authenticated` | signed-in Playwright tests | `tests/e2e/{dashboard,scans,report,triage}-auth.spec.ts` |
| `claude/e73-benchmark` | accuracy benchmark | `bench/` + `benchmark.yml` |
| `claude/postgres-rls-tests` | DB/RLS tests | `tests/db/` + `db-tests.yml` |
| `claude/dependency-audit` | Next 16.4.1 RCE fix | merged |
| `claude/great-maxwell-jr835x` | encryption (reused default branch) | merged |
| `chore/coverage-and-docs` | +241 lines coverage/docs for #72–76 | **not** in master, but overlaps #86 and #88 (both touch `dns.test`/`jsSecrets.test`); stale rebase, low value |

Plus ~25 `feat/*`, `docs/*`, `chore/*`, `fix/*` branches that map 1:1 to merged
PRs (#60–#87).

**Action:** prune all of the above. `chore/coverage-and-docs` is the only one with
unique content, and CI's coverage floor already enforces the bar it was raising,
so let it go unless you specifically want those extra cases (not worth the rebase).

---

## 2. Delivery audit — the 5-sprint plan vs reality

| Sprint | Status | Note |
|---|---|---|
| **1 Payments live & safe** | ❌ not delivered | Blocked on owner config (Stripe price IDs). Code gap stands: `webhook.ts:145/202` still default missing metadata to `"basic"` (silent downgrade). No checkout e2e. |
| **2 Reliability baseline** | ❌ not delivered | Worker (`run-queued-scan-jobs.ts`) still has zero Sentry wiring; no correlation IDs; rate limiting fails open (Upstash unset). |
| **3 Prove scans in prod** | ❌ not delivered | No vulnerable staging target, no CI verification job, POC-1/POC-5 unproven. Credibility nits remain (`BASE_CHECK_NAMES.length + 26`). |
| **4 Evidence & dedup** | 🟡 mostly done | Dedup (`findingConsolidation.ts`) and the E-74 findings view **already shipped**. Remaining: per-finding evidence surfacing (E-75) + two real bugs (CMS SEO fields dropped on save; scheduled-report "PDF" emits only CSV/JSON). |
| **5 Launch readiness** | 🟡 partly done | Signed-in e2e **already exist**. Remaining: plan-gating audit (2 client-only + 6 ungated routes), branch protection (needs GitHub Pro), and the marketing/grant integrity pass (P0-2). |

So Sprints 1–3 are the real work; 4–5 shrink to bug-fixes + hardening + integrity.

### Deferred items worth doing now (given the runway)

- **Decide the offensive tier.** `strix.ts`/`cairn.ts` pin to versions that don't
  exist and have never run; `credentialSpray` (hydra) is unverified end-to-end.
  Either pin real versions and verify in CI, or remove them from the UI/profiles
  and marketing. Leaving non-functional "autonomous AI pen-test" claims live is a
  reputational and (for grants) integrity risk.
- **Fix the two known product bugs** (CMS SEO fields, report-PDF) — small, visible,
  and they undercut trust if a customer hits them.
- **Credibility nits** from `SCANNER-INVENTORY.md`: progress-total undercount, stale
  `scanProfiles`/`resolveToolConfig` docstrings, `workflowSecurityCatalog` count.
- **Restore drill (E-13)** and a status page — cheap reliability signals.

---

## 3. Owner manual TODOs (non-code) — in detail

These cannot be done in code; they need you, in a secure channel. Priority order.

### 🔴 P0 — Rotate the leaked Supabase credentials
- **What:** rotate the Supabase **database password** (the `DATABASE_URL` with the
  Postgres password was pasted into a chat on 2026-10-14), and on the same
  principle the **service-role key** and **Stripe keys**.
- **Why:** anything pasted in plaintext must be treated as compromised. The
  service-role key bypasses all RLS — a leak is a full-database compromise.
- **How:** Supabase dashboard → Settings → Database → reset password; Settings →
  API → roll service-role key; update the secrets in Azure SWA config **and**
  GitHub Actions secrets. Redeploy.
- **Risk if skipped:** total data exposure. This is the single most urgent item.

### 🟠 P1 — Stripe production config (unblocks revenue)
- **What:** set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and the four price IDs
  `STRIPE_PRICE_BASIC/PRO/AGENCY/TIER_A`.
- **Why:** checkout returns 503 and `/api/health` reads "degraded" until these are
  set. No paying customers are possible — the existential launch blocker (E-07).
- **How:** create the products/prices in the Stripe dashboard (live mode), copy the
  `price_…` IDs into Azure + GitHub secrets; register the webhook endpoint
  (`/api/stripe/webhook`) and copy its signing secret. Test in Stripe **test mode**
  first (pairs with the Sprint 1 checkout e2e).
- **Risk if skipped:** cannot bill; POC-B1/POC-3 stay red.

### 🟠 P1 — Sentry DSN (error visibility)
- **What:** set `SENTRY_DSN` and `NEXT_PUBLIC_SENTRY_DSN`.
- **Why:** the Sentry code exists but is a no-op until the DSN is set, so failed
  scans and server errors are invisible in prod (BETA-1). (Note the worker still
  needs code wiring — Sprint 2.)
- **How:** create a Sentry project, copy the DSN into Azure + GitHub secrets.
- **Risk if skipped:** you're blind to production failures.

### 🟠 P1 — Upstash Redis (rate limiting fails open)
- **What:** set `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
- **Why:** rate limiting **fails open** without them — the only cost/abuse control
  on rate-limited routes silently vanishes (security gap A-2, LIVE-1).
- **How:** create an Upstash Redis DB, copy REST URL + token into secrets.
- **Risk if skipped:** scan-abuse / cost blowout, no effective rate limit.

### 🟡 P2 — Operational config
- **`SITE_URL`** = `https://www.hebridescyber.co.uk` — completes the post-deploy
  health check.
- **GitHub branch protection** requiring the CI check job before merge to `master`
  (BETA-5). **Needs GitHub Pro** for a private repo — a paid decision.
- **Restore drill (E-13):** take a backup, restore it to a throwaway project, prove
  it works, document the runbook.

### 🟢 P3 — Reputation / legal / defensive
- **Register `hebridescyber.com`** (and common typos) defensively; add a
  `security@` alias and a basic `/.well-known/security.txt`.
- **CAA DNS record** restricting cert issuance to your CA.
- **ToS solicitor review + PI insurance** before selling any manual pen-testing or
  Tier A offensive scanning (you need signed authorisation to send attack traffic).
- **Integrity pass on marketing/grant copy (P0-2 in the product review):** remove or
  soft-pedal claims about deleted/unwired features — SSO/SAML, RBAC, SCIM, MSP
  portal, "autonomous AI pen-test", and any unsourced stats. This is called out as
  the biggest *non-code* risk.
- **Optional API keys** that unlock checks: `WPSCAN_API_TOKEN`, `HIBP_API_KEY`,
  `GOOGLE_SAFE_BROWSING_API_KEY`, `RESEND_API_KEY`, `AZURE_OPENAI_*`,
  `AZURE_STORAGE_CONNECTION_STRING`, GitHub App/PAT for fix-PRs.

---

## 4. Updated roadmap (≈4-week harden-then-launch)

Reframed around the deferral: fix the blockers, then spend the extra runway on
depth and differentiation, not more breadth.

**Week 1 — Billable & safe**
- Owner: rotate creds (P0), set Stripe + Sentry + Upstash (P1).
- Code: webhook silent-downgrade guard + checkout e2e (Sprint 1); finish/merge #88;
  prune stale branches; fix CMS-SEO + report-PDF bugs; credibility nits.

**Week 2 — Prove & observe**
- Stand up a controlled vulnerable staging target; CI verification job asserting ≥1
  extended-tool finding + installed-binaries/tool-status artifact + alert.
- Wire the worker to Sentry + correlation IDs end-to-end; verify POC-1/POC-5.
- Publish an accuracy/benchmark transparency page (lean into the evidence discipline).

**Week 3 — Differentiate**
- Add high-signal checks: Dalfox (XSS), Corsy (CORS), OSV-Scanner (deps),
  interactsh OOB (blind-vuln accuracy), email hygiene (MTA-STS, TLS-RPT, CAA, DKIM).
- Ticketing push: Jira / GitHub Issues from findings (close the integrations gap).
- Change-triggered + emerging-threat rescans (close the Intruder gap).

**Week 4 — Polish & launch-ready**
- Plan-gating audit (server-enforce the ungated routes); decide offensive tier.
- Editable / white-label report export (agency differentiator).
- Integrity pass on marketing/grant copy; branch protection; restore drill.
- Final POC→Beta checklist green.

---

## 5. Competitor gaps

Grounded in current coverage of Intruder, Detectify, Probely (now Snyk-owned), and
Pentest-Tools.com.

| Gap | They do it | Hebrides today | Worth closing? |
|---|---|---|---|
| **Change-triggered scanning** | Intruder "adaptive" scans fire on detected change | scheduled cron only | ✅ yes — add change-detection trigger |
| **Emerging-threat instant rescan** | Intruder rescans estate on new CVE disclosure | KEV/EPSS enrichment + emerging-threats data, but no auto-rescan | ✅ yes — trigger rescan on KEV add |
| **Ticketing integrations** | Jira / GitHub issue push | Slack/Teams/webhooks only | ✅ yes — Jira + GitHub Issues |
| **Editable / white-label reports** | Pentest-Tools: DOCX + white-label | branded PDF | ✅ yes — agency upsell |
| **Deep authenticated DAST** | Detectify/Probely strength | `authenticatedCrawl` exists, shallow | 🟡 deepen later |
| **WAF detection surfaced** | Intruder returns WAF metadata | `whatwaf` runs but not surfaced | 🟡 cheap — surface it |
| **Scale messaging (100k+ checks)** | Intruder 140k+, Detectify 1500+, Pentest 11k+ | nuclei templates ≈ comparable | marketing only |

**Where Hebrides already wins (lean into these):**
- **Evidence-first findings** — every finding carries proof; most competitors over-report. This is a genuine trust differentiator.
- **Automated remediation PRs** — Hebrides opens real fix PRs (headers, deps). Competitors report; they don't fix. This is close to unique.
- **UK/Cyber-Essentials-native + SMB pricing** — sits in the gap between "too small for a pen test" and enterprise EASM pricing.

---

## 6. Top tools not yet wired — keep / maybe / skip

Legend: ✅ add · 🟡 maybe/later · ❌ skip. Judged against the architecture
(ephemeral GitHub Actions runners, no persistent infra, passive-first on-demand,
evidence discipline, no destructive-by-default, SMB + UK CE focus) and redundancy
with what's already wired.

### Recon / ASM / DNS (have: subfinder, naabu, httpx, katana, nmap, crt.sh EASM)
1. **OWASP Amass** — ✅ deeper passive subdomain enum (many more sources than subfinder); evidence-rich. Passive mode only.
2. **dnsx** (ProjectDiscovery) — ✅ mass DNS resolution, record types, wildcard; cheap, strengthens EASM.
3. **asnmap** — ✅ ASN→CIDR to find owned ranges; real EASM depth.
4. **tlsx** — 🟡 TLS metadata at scale; overlaps testssl.sh but far faster across many hosts.
5. **alterx** — 🟡 permutation wordlists for subdomain brute; pairs with dnsx (noise risk).
6. **dnstwist** — ✅ typosquat/lookalike-domain detection; augments existing lookalike alerts; standalone-product potential.
7. **Shodan API** — 🟡 exposed-service intel with no active scan; great passive signal, but paid.
8. **Censys API** — 🟡 host + cert intel; paid.
9. **SecurityTrails API** — 🟡 historical DNS/subdomains; strong EASM, paid.
10. **uncover** — ❌ Shodan/Censys/FOFA querying; needs paid keys, overlaps intent.
11. **theHarvester** — 🟡 OSINT emails/hosts; noisy, partial overlap.
12. **masscan** — ❌ nmap + naabu already cover ports; overkill/noisy.
13. **WhatWeb** — 🟡 tech fingerprinting breadth; overlaps `fingerprint.ts`.

### DAST / web app (have: ZAP, nuclei, sqlmap, ffuf, arjun, katana, gospider, kiterunner)
14. **Dalfox** — ✅ dedicated XSS scanner (inventory notes you *don't* have it); high-signal, evidence-rich.
15. **Corsy** — ✅ CORS misconfig; cheap, common SMB issue, clear evidence.
16. **interactsh** (self-host) — ✅ out-of-band interaction server for blind SSRF/RCE/XXE via nuclei; big accuracy win.
17. **jwt_tool** — ✅ JWT weaknesses (alg=none, weak secret) for token-based apps.
18. **Nuclei fuzzing + headless templates** — ✅ config, not a new tool: enable param-fuzzing and DOM-XSS templates.
19. **XSStrike** — ❌ dalfox is better maintained; redundant.
20. **CRLFuzz** — 🟡 CRLF injection; niche.
21. **tplmap** — 🟡 SSTI; niche, nuclei covers some.
22. **NoSQLMap** — ❌ niche + destructive.
23. **feroxbuster / dirsearch / gobuster** — ❌ ffuf/kiterunner/contentDiscovery already cover this.
24. **Nikto** — ❌ dated, noisy; nuclei covers the useful checks.
25. **Wapiti** — ❌ overlaps ZAP.
26. **LinkFinder / SecretFinder** — 🟡 JS endpoint/secret extraction; partial overlap with `jsSecrets`.
27. **Burp Suite Pro/DAST** — ❌ commercial, not CI-automatable for this model.

### TLS / email / DNS hygiene (have: testssl.sh, SPF/DMARC/DNSSEC, DMARC aggregate)
28. **MTA-STS check** — ✅ email transport security; CE-adjacent, cheap passive.
29. **TLS-RPT check** — ✅ companion to MTA-STS.
30. **DKIM selector check** — ✅ you have SPF/DMARC; add DKIM presence/validity.
31. **CAA record check** — ✅ cert-issuance control; cheap, CE-adjacent.
32. **sslyze** — 🟡 faster, machine-readable TLS; overlaps testssl.sh.
33. **Mozilla HTTP Observatory API** — 🟡 external header-grade corroboration; you already grade headers/CSP.
34. **BIMI check** — 🟡 brand indicator; low security value.
35. **DANE/TLSA** — 🟡 niche (email).

### Dependency / supply chain (have: trivy, gitleaks, CycloneDX+VEX, deps.dev, retire.js, lockfile)
36. **OSV-Scanner** (Google) — ✅ authoritative OSV matching for lockfiles; complements trivy.
37. **TruffleHog** — 🟡 verified-secret detection; stronger than gitleaks on false-positive rate.
38. **OSSF Scorecard** — 🟡 repo security posture for connected repos (dev tier).
39. **Grype** — 🟡 dep/container vuln; overlaps trivy.
40. **Syft** — ❌ SBOM gen; CycloneDX already covered.
41. **Semgrep** — ❌ you run opengrep (its OSS fork).
42. **Dependency-Track** — ❌ needs a persistent server; violates no-persistent-infra.
43. **Checkov / KICS / tfsec** — ❌ trivy already does IaC misconfig.

### Cloud / CSPM (have: cloudPosture IAM/encryption)
44. **Prowler** — ✅ deep AWS/Azure/GCP CSPM + CIS benchmarks; for a connected-cloud tier.
45. **ScoutSuite** — 🟡 multi-cloud audit; overlaps Prowler.
46. **kube-bench / Trivy-k8s** — 🟡 Kubernetes; few SMB customers run k8s — future.
47. **Pacu** — ❌ offensive AWS exploitation; destructive, authz issues.

### Trust / reputation (not strictly security, but differentiators)
48. **Pa11y / axe-core** — 🟡 WCAG accessibility; UK Equality Act relevance; a "trust profile" upsell.
49. **Lighthouse** — 🟡 perf/SEO/best-practices/PWA; adjacent trust signal.
50. **GitHub org secret-leak search** — ✅ find leaked secrets in public repos tied to the customer's org; high-value, evidence-rich (needs GitHub API).
51. **URLScan.io API** — 🟡 external scan + phishing/lookalike corroboration.

**Highest-ROI additions for the runway (small, high-signal, on-brand):** Dalfox,
Corsy, OSV-Scanner, interactsh, dnsx/asnmap, and the email-hygiene set
(MTA-STS/TLS-RPT/CAA/DKIM). All are passive-or-safe, evidence-friendly, and
CE-relevant.

---

## 7. Spitball — product ideas

- **Change-triggered + emerging-threat rescans** — close the Intruder gap; rescan on
  detected change and on new KEV entries. High perceived value.
- **Jira / GitHub Issues push** — meet dev teams where they work.
- **Editable / white-label DOCX reports** — unlock the agency segment.
- **Public "security scorecard" badge** — customers embed a live badge; reputation
  flywheel + inbound marketing.
- **Trust/accessibility profile** — bundle Pa11y + Lighthouse as a non-security upsell
  that widens the buyer (marketing/ops, not just security).
- **dnstwist typosquat monitoring** — standalone brand-protection alert product.
- **Accuracy transparency page** — publish the benchmark precision/recall; turn the
  evidence discipline into a marketing asset competitors can't easily match.
- **Fix-PR expansion** — you already open header/dep fix PRs; extend to more
  no-regret fixes (cookie flags, redirects, cache headers) — a near-unique hook.
- **Scheduled executive digest** (you have monthly) → add quarterly board-ready PDF.

---

## 8. Immediate next actions

1. Prune the stale branches (§1).
2. Owner: start the P0/P1 manual TODOs (§3) — these gate everything.
3. Begin Week-1 code work (§4): webhook guard + checkout e2e, finish #88, fix the two bugs.
4. Agree which §6 tools to add in Week 3 and fold the chosen ones into `SCANNER-INVENTORY.md` + profiles.
5. Fold §4/§2 into `ROADMAP.md` and `SPRINT-PLAN.md` once agreed.
