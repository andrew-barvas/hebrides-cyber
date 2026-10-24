# Burp Suite parity and the Burp MCP question

Written 2026-10-22. Answers three questions: do we use Burp MCP, have we
replicated Burp's functionality, and where are the gaps.

## Do we use Burp MCP?

No, and it should not become a product dependency.

Burp MCP exposes a person's interactive Burp Suite Professional session (proxy
history, repeater, scanner) to an LLM. Hebrides runs unattended on ephemeral
GitHub Actions runners, so there is no operator session to attach to, and Burp
Pro is licensed per seat and not designed for CI use.

Its proper place is the **owner's workstation**, for an assisted manual pentest
service: Claude Code with Burp MCP and Playwright MCP, a reusable testing skill,
the sandbox on, and only vetted plugins (third-party "pentest agent" repos are
unreviewed code). That is a service line, not a product feature, and needs a
ToS review and professional indemnity cover before it is sold (strategy review
§3, P3).

## Have we replicated Burp's functionality?

Largely for the automated half, not for the interactive half.

| Burp capability | Hebrides equivalent | Status |
|---|---|---|
| Scanner (active and passive) | ZAP spider and active scan (`zap.ts`, `zapAjaxSpider.ts`), nuclei, sqlmap, commix, the base passive suite | Covered, different engines |
| Crawler / site map | katana, gospider, kiterunner, `crawler.ts`, `authenticatedCrawl.ts` | Covered |
| Repeater (craft and replay a request) | `replayProbe.ts`: allowlisted, read-only, budgeted replay, used by `aiTriage.ts`. Plus the fixed validators in `proofOfExploit.ts` / `xssConfirm.ts` | **New (this change)**; deliberately GET/HEAD only |
| Collaborator (out-of-band) | nuclei's `ssrf`/`oast` templates against an interactsh server. The server is now configurable (`INTERACTSH_SERVER`) or can be disabled (`DISABLE_OAST=1`) | Covered for nuclei. **Own-probe OOB is not built** (needs a native interactsh client: RSA key exchange and AES polling) |
| Intruder (fuzz / brute force) | ffuf via `contentDiscovery`, arjun, `credentialSpray` (hydra) | Partial: the offensive tier is unproven end to end (see below) |
| Sequencer (token randomness) | `tokenEntropy.ts` + `sessionCheck.ts`: samples a dozen anonymous sessions and flags counters, repeats, short or low-entropy values. `badsecrets` and `jwtAnalysis` for known-weak secrets | **New (this change)**; an estimate from a small sample, never a proof of strength |
| Proxy / intercept / history | none | Not applicable to a headless pipeline |
| Authenticated flows and macros | `loginRecorder.ts`, `authenticatedCrawl.ts`, cookie or Basic credentials | Partial: no OAuth or MFA flows, no deep IDOR |
| DOM Invader / DOM XSS | `xssConfirm.ts`, `playwright.ts`, Dalfox (`dalfox.ts`, wired 2026-10-23) | Covered |
| Extensions (BApps) | nuclei templates | Equivalent |
| Business-logic testing | `businessLogic.ts`, `workflowSecurity` | Gap. Narrow, and the area where a human still wins |

Correction to an earlier draft of this table: out-of-band testing was listed as
a gap. It is not for nuclei, which already uses interactsh for the SSRF
templates (see `nuclei.ts`'s header). The remaining gap is OOB for our own
probes.

## Differences that matter

Burp is a tester's workbench: interactive, stateful within a session, driven by
a person. Hebrides is a pipeline: unattended, evidence-gated, stateful across
scans (finding lifecycle and diffing), and it opens fix PRs. The valuable gaps
are therefore bounded replay (closed), token analysis (closed), blind-vuln
confirmation for our own probes, multi-step auth and logic.

## Not done, and why

- **Dalfox** (XSS depth): **done 2026-10-23.** Wired with a pinned, SHA-256-
  verified binary (`v3.2.4`) and a parser built from a real captured run
  (`src/worker/tools/fixtures/dalfox/`), with `tool-integration.yml` running
  the real binary in CI. The capture also caught a real bug before it shipped:
  Dalfox exits 1 (not 0) when it finds a vulnerability, which an
  unverified parser would have read as a process failure and silently
  dropped every real finding.
- **strix / cairn / credentialSpray**: owner decision — leave `not_configured`
  and unmarketed rather than rush verification. Each needs a real resource
  this session doesn't have: strix needs Docker + an LLM API key (~$2-5/scan)
  and its pinned tag (`v0.5.0`) doesn't exist upstream (real tags are `v1.x`);
  cairn's pinned tag (`v1.0.0`) doesn't exist either (latest is `v0.2.1`), and
  it's AGPL — enabling it needs the subprocess-isolation review `cairn.ts`'s
  header describes to actually be done, not just planned; credentialSpray
  needs a real designated sacrificial login target to verify hydra's output
  against (not just the parser fixtures already captured). Not advertised in
  product copy (the `/ai-threats` page describes the external attack campaign,
  not our features) and `not_configured` by default, so nothing is claimed
  that does not run. Re-pin to real tags before ever attempting to verify them
  (`docs/SCANNER-INVENTORY.md`).
- **OAuth/MFA, two-session IDOR, more logic checks**: need design with real
  target applications to test against; shipping guesses would add false
  positives.
- **Own-probe OOB client**: see the table.
