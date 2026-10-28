# AI triage of unproven findings

Status: implemented, **off by default** (`AI_TRIAGE=1`). Code: `src/lib/scanners/aiTriage.ts`
and `replayProbe.ts`. Tests: `aiTriage.test.ts`, `aiTriage.http.test.ts` (real local server),
`replayProbe.test.ts`, `proofEvidence.test.ts`, `ScanReportView.test.tsx`.

## Problem

`proofOfExploit.ts` can reproduce only a handful of finding types (open redirect, CORS,
exposed file, reflected XSS). Everything else is reported as "potential", which is where
most false-positive complaints come from. A person triaging would fetch one URL and look.
This does that, under tight limits.

## Flow

1. **Select.** `isTriageCandidate`: medium or higher, has a `checkId`, not already proven or
   triaged, and not a DNS / TLS / port / dependency / secret-in-repo style finding (an HTTP
   request cannot show those). Most severe first, capped at 8 per scan.
2. **Propose.** The model gets the finding's title, check id, severity, a truncated detail and
   any `url` / `path` / `parameter` metadata. **Not the target host.** It answers with JSON:
   one GET or HEAD request, or `{"skip":true}`.
3. **Replay.** `replayProbe` validates and runs it: GET/HEAD only, absolute same-site path,
   allowlisted request headers only (no cookies or credentials), no redirects followed,
   16 KB body cap, `Set-Cookie` values redacted, a shared per-scan budget. Policy rejections
   are `refused`, failures `error`; neither becomes a verdict.
4. **Judge.** The model sees the finding and the captured response (body inside an
   `<untrusted_response>` fence, closing tags stripped) and returns
   `confirmed | not_confirmed | inconclusive` with a verbatim `evidence` quote.
5. **Verify.** `buildRecord` accepts `confirmed` only if the quote (whitespace and case
   insensitive) really appears in the captured status, headers, body or redirect, and the
   response is not the site's catch-all page (`fetchBaseline`). Otherwise it is downgraded
   to `inconclusive`. A reply that is not valid JSON is `inconclusive`.

## Guarantees

- Annotation only: `metadata.aiTriage = { verdict, evidence?, request, reasoning, triagedAt }`.
  Severity, score, status and `findingLifecycle` are untouched, so a finding is never
  closed, suppressed or marked fixed by the model. `not_confirmed` is shown as "AI: not
  reproduced" with a tooltip saying it is not evidence of a fix.
- Failure is silence: no model configured, a model error or a network error leaves the
  finding exactly as it was (CLAUDE.md rule 7).
- Prompt injection: the response is data in a fence, the output is schema-checked and must be
  backed by a quote from that same response, and the only action available is a replay that the
  allowlist constrains. A hostile page can at worst produce `inconclusive`.
- Same gating as proof of exploit: runs only for non-`safe` profiles, and `DISABLE_AI_TRIAGE=1`
  turns it off everywhere.

## Data handling

Sent to the Azure OpenAI deployment already used for summaries and fix text
(`AZURE_OPENAI_*`): finding title, check id, severity, truncated detail, a few metadata hints,
the replay request line and headers, and up to 16 KB of the response body. Never credentials,
cookies, the customer's stored secrets or the target host. Use a UK/EU-region deployment and
mention it in the privacy notice before enabling for customers.

## Report UI

`ScanReportView` shows **AI-verified** (amber, evidence and request line in the tooltip) for a
verified `confirmed` verdict, only when there is no deterministic proof, and ranks it between
"Confirmed exploitable" and unverified findings. `inconclusive` shows nothing.

## Evaluating the model

`npm run bench:triage` (`bench/triage/run.ts`) runs the real `triageFinding()` pipeline — real
prompts, real `replayProbe` allowlist, real model call — against the labeled cases in
`bench/triage/cases.ts`, each a tiny fixture site plus one finding with a known-correct verdict.
It reports per-case hits/misses and precision/recall for `confirmed` specifically, since a false
`confirmed` is the costlier mistake.

Needs `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_KEY` / `AZURE_OPENAI_DEPLOYMENT` set; without them it
exits 2 before scoring anything. **Not wired into CI** — no model credential there yet — so run it
by hand after touching the prompts in `aiTriage.ts`, and before raising `MAX_TRIAGED_PER_SCAN` or
otherwise widening triage's role. The seed set is intentionally small; grow it toward 30-50 cases
as real false positives/negatives turn up, one fixture per case, labeled with the verdict a careful
human reviewer would reach.

## Not built / next

- Wire `bench:triage` into CI once a scoped, low-budget model credential exists there (manually
  triggered or nightly, not on every PR).
- Two-request probes (for example a baseline plus a mutated request) and POST support. Both widen
  the blast radius; add only with their own review.
- Using the verdict to rank the executive report or to suppress anything. Do not suppress until a
  benchmark shows the false-negative rate.
