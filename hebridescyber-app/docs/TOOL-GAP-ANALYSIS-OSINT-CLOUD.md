# Tool gap analysis: external recon, OSINT and cloud posture

**Date:** 2026-11-01. **Verdict:** no new tool integration is justified.

## Why this exists

An externally generated suggestion listed about 40 security tools as
candidates for Scanner, Lookout and Exploit. Most were out of scope before
any comparison was needed. Exploitation and post-compromise frameworks,
offline password cracking, Active Directory attack-path tools,
internal-network enumeration and wireless/RF tooling all need a foothold
inside the customer's network or on their premises. HebridesCyber assesses
from the outside, from cloud workers, and `EXPLOIT-PRODUCT-PLAN.md` already
excludes that class of tooling.

Two categories could plausibly fit the product: external recon/OSINT and
cloud posture. This file records how each candidate in those categories
compares with what is already built, so the question doesn't need to be
re-derived.

## Method

Each tool was checked against `src/worker/tools/`, `src/lib/scanners/`,
`src/lib/scanProfiles.ts`, `SCANNER-INVENTORY.md`, and earlier evaluations in
`STRATEGY-REVIEW-2026-10.md` and `DEFENSIVE-ASSESSMENT-PLAN.md`.

## Results

| Tool | Already covered by / evaluated in | Verdict | Reason |
|---|---|---|---|
| Masscan | `networkExposure.ts` (naabu, top-1000 ports) + `nmap.ts`; rejected in `DEFENSIVE-ASSESSMENT-PLAN.md` and `STRATEGY-REVIEW-2026-10.md` item 12 | Don't add | Port discovery and service detection are already covered; Masscan would add speed, not coverage, at the cost of noise. |
| theHarvester | Partly by `jsSecrets.ts` (exposed emails), `subdomains.ts` + crt.sh (hosts), `hibp.ts` (breached emails); 🟡 in `STRATEGY-REVIEW-2026-10.md` item 11 | Don't add | Noisy search-engine scraping for a small increment over existing sources. |
| Maltego CE | Not previously evaluated | Don't add | An interactive, GUI-driven link-analysis tool. It doesn't fit a headless, scheduled worker pipeline. |
| Recon-ng | Not previously evaluated | Don't add | A framework of recon modules whose useful parts already exist as purpose-built checks: subfinder (`subdomains.ts`), crt.sh (`recon.ts`), httpx (`hostProbe.ts`), Wayback (`waybackDiscovery.ts`), lookalike-domain monitoring. Wrapping it would duplicate coverage. |
| SpiderFoot | Not previously evaluated | Don't add | Same as Recon-ng: broad footprinting already covered piecemeal, and it would add a second, heavier output format to parse. |
| ScoutSuite | `cloudPosture.ts` + `prowlerIam.ts`; 🟡 "overlaps Prowler" in `STRATEGY-REVIEW-2026-10.md` item 45 | Don't add | Prowler already does the IAM audit ScoutSuite would provide. Extend Prowler rather than add a second engine. |
| Cloudsploit | No repo mentions | Don't add | Functionally redundant with `cloudMisconfig.ts`, `cloudPosture.ts` and Prowler, and less actively maintained than Prowler. |
| S3Scanner | `cloudMisconfig.ts` (buckets the target's own pages reference) + `cloudPosture.ts` (AWS account-level public-access block, bucket policy status) | Don't add | Its distinguishing feature is guessing third-party bucket names, which `cloudMisconfig.ts` excludes by design: we only test what the customer owns or references. |
| Prowler | **Built**: `src/worker/tools/prowlerIam.ts`, PR #158 (Prowler 5.47.0, AWS `iam` service only) | Already done | Open follow-ups: OT-46 (our AWS identity, then a first real-account run) and OT-47 (hash-pin Prowler's Python dependencies). Don't re-propose it. |

## Bottom line

None of these tools fills a real gap. The one gap the suggestion named that
mattered, cloud IAM auditing, is already closed for AWS in code and waits only
on OT-46 and OT-47.

If cloud coverage grows, extend `prowlerIam.ts` to other Prowler services or
to Azure and GCP rather than adding ScoutSuite or Cloudsploit. If an OSINT gap
appears, add the specific source as a purpose-built check (the way
`subdomains.ts` wraps subfinder), not a whole framework.
