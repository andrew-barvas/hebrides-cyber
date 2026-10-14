# Architecture & workflow diagrams

**These `.mmd` files are the canonical source of truth for every diagram in the
docs.** They are Mermaid; GitHub renders them inline, and `npm run docs:diagrams`
exports SVG + PNG to `exports/` for slide decks, funder packs and offline use.

Same standing rule as the rest of `docs/`: **a diagram describes the system as it
is, including what's broken or unwired.** Boxes are annotated `STUB` /
`UNVERIFIED` / `FINDING X-n` / `GAP` where that is the truth — never draw an
aspirational box as if it shipped. Where this disagrees with marketing copy,
`FUNCTIONALITY-MATRIX.md` is the arbiter and the diagram follows it.

## Index

| Set | File | What it shows |
|---|---|---|
| Architecture (C4) | `c4-context.mmd` | System context: users, the single SaaS, ~20 external services & feeds |
| Architecture (C4) | `c4-container.mmd` | Containers: Next.js surface, Supabase, Postgres queue, GitHub Actions workers |
| Architecture (C4) | `c4-component-scanner.mmd` | Scan pipeline components: base → extended → enrichment → notifiers |
| Scan lifecycle | `seq-ondemand-scan.mmd` | On-demand scan sequence (two-step ownership proof, passive-only) |
| Scan lifecycle | `seq-scheduled-scan.mmd` | Scheduled scan sequence (cron, full/active profile) |
| Scan lifecycle | `flow-scan-profile-gating.mmd` | Profile resolution + Tier A offensive authorisation gate |
| Scan lifecycle | `state-scan-job.mmd` | `scan_jobs` state machine (pending→…→completed/failed/stale) |
| Scan lifecycle | `flow-finding-lifecycle.mmd` | New/Fixed diff, triage, SLA, ticket dedupe/auto-close |
| Data model | `er-core.mmd` | Entity-relationship of the core tables |
| Data model | `er-rls-tiers.mmd` | RLS / tenant-isolation tiers + credential-at-rest findings |
| Auth & tenancy | `flow-auth.mmd` | Login, magic link/password/OAuth, MFA step-up (+ sign-up/reset gaps) |
| Auth & tenancy | `map-plan-gating.mmd` | Plan tiers, nesting, and the feature-gating map |
| Deploy & CI | `deploy-topology.mmd` | Azure SWA hybrid + GitHub Actions workers + Supabase; alt Container Apps |
| Deploy & CI | `cicd-pipeline.mmd` | Quality gates + the 17 workflows + supply-chain gap |

## Regenerate exports

```bash
cd hebridescyber-app
npm run docs:diagrams   # renders every *.mmd -> exports/*.svg and *.png
```

The script fetches `@mermaid-js/mermaid-cli` on demand via `npx` (so it is **not**
a committed dependency — it drags in a heavy puppeteer tree this lean repo keeps
out of its lockfile). The first run needs network; it drives a headless Chromium,
auto-detecting a system Chrome/Edge (or `PUPPETEER_EXECUTABLE_PATH`) if mermaid's
bundled one isn't present.

`exports/` is derived output. If you change a `.mmd`, re-run the script and commit
both.
