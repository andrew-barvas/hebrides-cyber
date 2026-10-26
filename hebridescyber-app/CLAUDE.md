# CLAUDE.md

Guidance for Claude Code working in this repository. Everything here applies to
*every* change. Module-level detail lives in `docs/` — see "Where to read what"
at the bottom and read only the entry you need.

> **Moved sections.** This file was cut from 110 KB to ~20 KB on 2026-10-20. The
> module-level narrative that used to live here moved verbatim to
> `docs/ARCHITECTURE-NOTES.md`. Code comments and docs elsewhere still say
> things like *see CLAUDE.md's "Content generation" / "Scanner pipeline" /
> "Database schema" / "Mobile & PWA" / "EASM discovery" section* — every one of
> those is now a heading in `docs/ARCHITECTURE-NOTES.md`. Look there before
> concluding a reference is stale.

## Commands

```bash
npm run dev                  # Dev server (Next.js 16 + Turbopack, port 3000)
npm run build                # Production build
npm run lint                 # ESLint
npx tsc --noEmit             # Type check — build does NOT run tsc, always run it separately
npm test                     # Playwright e2e (builds app + starts server; slow, hermetic)
npm run test:unit            # Vitest unit/integration
npm run test:unit:coverage   # Same, with coverage report
npm run test:db              # Database/RLS tests (needs DATABASE_URL)
npm run bench                # Scanner accuracy benchmark
npm run scan:local           # Real scan against a URL, persisted (needs SCAN_OWNER_ID)
npm run seed:users           # Demo accounts in Supabase (admin, basic/pro/agency/no-plan)
npm run queue:enqueue-scheduled-scans  # Run the scheduled-scan enqueue step locally
npm run queue:run-worker               # Claim + run one batch of queued scan_jobs locally
npm run newsletter:daily               # Daily blog generation script (no HTTP hop)
npm run newsletter:weekly              # Weekly newsletter generation script
npm run threats:check -- --dry-run     # Emerging-threat alerts, no writes/sends
```

The `/verify` skill runs the full pre-deploy gate in `deploy.yml`'s order.

## Environment

Copy `.env.example` to `.env.local`. Minimum to boot locally:

```
NEXT_PUBLIC_SUPABASE_URL=https://<project>.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon-key>
```

Without those the app boots but all auth/data calls fail — the Supabase client
logs a warning and uses a placeholder rather than throwing.

## Rules that always apply

These are the ones that have actually broken CI or production. Follow them
without needing to be asked.

### Gate and tooling

1. **The gate is four commands, and you check exit codes, not summary lines.**
   From `hebridescyber-app/`: `npm run lint` (0 errors), `npx tsc --noEmit` (no
   output), `npm run test:unit:coverage`, `npm test`. Vitest prints "N passed"
   even when an *unhandled error* fails the run — a line `Errors  1 error` means
   failure. CI type-checks PRs merged into master, so rebase onto latest master
   before trusting a local pass.
2. **Never return a value from a `beforeEach`/`afterEach` arrow.**
   `beforeEach(() => mock.mockReset())` returns the mock, and Vitest runs a
   returned function as a cleanup hook — it called the mock with no arguments
   and failed CI. Use a block body.
3. **Windows line endings.** Every file in this repo is CRLF. String-replace
   scripts that assume `\n` silently miss. Use the Edit tool, and avoid passing
   `\n` escapes through shell heredocs.
4. **Coverage thresholds only go up**, to the value a PR's own
   `test:unit:coverage` run actually reports, after merging. Never lower them.
5. **One build at a time.** Parallel subagents exhausted the usage limit three
   times; local and cloud sessions share one allowance. Give any scratch file a
   unique name — two builds have overwritten each other's PR body.
6. **Commits and PRs carry the attribution lines** for the model that made the
   change (the session's own attribution guidance supplies the exact text).
   Draft PR → wait for CI → squash-merge → watch the `Deploy` run. The `/ship`
   skill does this.

### Scanner checks

7. **Evidence discipline: a failed lookup is `status: "error"`, never an empty
   "checked".** `findingLifecycle.ts` would otherwise mark last scan's findings
   fixed and close their tickets. "No evidence either way" is never "clean".
8. **Every finding needs a stable `checkId`** — `"<module>.<check-name>"`, or
   `"<module>.<check-name>:<key>"` in a loop. `findingsDiff.ts` matches on it to
   tell new from unchanged, so an untagged finding never participates in
   diffing. A new base-suite prefix that doesn't normalise to its `ScanResults`
   key needs a `BASE_ALIASES` entry; a new extended tool needs `TOOL_ALIASES`.
9. **Import the base pipeline as `@/lib/scanners` (the directory).** A
   single-file `src/lib/scanners.ts` once shadowed it in module resolution, so
   every entry point silently ran an old 4-check version. It is deleted — never
   recreate a file at that path.
10. **Shell out via `src/lib/execTool.ts`'s `execTool`, never bare
    `execFile`/`promisify(execFile)`.** It closes the child's stdin, without
    which tools that read targets from stdin (nuclei, gospider) hang until
    their timeout — which is why every scheduled scan's nuclei step produced
    nothing until this was found.
11. **A check that probes for a file must reuse `fetchBaseline`/`normaliseBody`
    (`httpProbe.ts`)**, never trust a 200 status. Without it every SPA that
    returns its shell for unknown paths reports an exposed `.env`.
12. **Remediation text is attached at the point the finding is created**
    (`remediationText.ts` → `Finding.remediation`), where the check result is
    still in scope. Never re-derive which fix applies by string-matching a
    finding's title. The field is optional, so consumers must guard.
13. A check with a genuine compliance angle gets its base checkId added to
    `COMPLIANCE_MAP` (`compliance.ts`). No entry means "not yet categorised",
    never a forced mapping.
14. **A path-probing check needs a bench fixture and expectation**
    (`bench/fixtures/sites.ts`, `bench/expectations/<target>.json`).
15. Writing or extending a check follows `docs/SCANNER-CONVENTIONS.md`'s five
    rules. Pinned release binaries are verified by version **and SHA-256**; an
    install step that only logs a failure hides a tool that never installed
    (how gospider/kiterunner/trivy silently did nothing until 2026-10-06).

### Data, auth and secrets

16. **`SUPABASE_SERVICE_ROLE_KEY` must never appear in a `NEXT_PUBLIC_*` var or
    any client bundle.**
17. **Plan gating is always `src/lib/planAccess.ts`** (`planGate`,
    `hasProAccess`/`hasAgencyAccess`/`hasTierAAccess`). The webhook marks a
    lapsed subscription `past_due`/`cancelled` but leaves `plan` unchanged, so
    never gate on `plan` alone — only `status === "active"` grants a tier
    (admins exempt). Tiers nest upward: Tier A ⊃ Agency ⊃ Pro, per
    `PLANS_FOR_TIER`.
18. **Client IP is always `getClientIp(req)`, never a header directly.** Azure
    Static Web Apps *appends* to a client-supplied `X-Forwarded-For`, so the
    leftmost entry is attacker-controlled. It feeds rate limits *and* API-key IP
    allowlists, so a forgeable value is an auth bypass.
19. **Customer-repo access is always `githubApp.ts`'s
    `resolveGithubAuth(githubRepo)`** — never read `process.env.GITHUB_PAT`
    directly in a new module. (`GITHUB_PAT` separately dispatches this repo's
    own `on-demand-scan.yml`; don't conflate the two concerns.)
20. **A new stored secret**: seal it on write behind the
    `isCredentialEncryptionConfigured()` 503 guard (never a plaintext
    fallback), `revealSecrets` where it is used, and add its table/columns to
    `STRING_SECRET_TARGETS` in `secretMigration.ts`. Browser code must never
    select a secret column.
21. **`ticket_integrations` is unique on `(owner, provider)` but trackers and
    on-call rows share the table**, so an owner can have two rows: every read
    must `.order("created_at", { ascending: false }).limit(1)` before
    `.maybeSingle()`, which would otherwise throw on exactly those accounts.
    Use `findTicketIntegration()` rather than querying it directly.
22. **Audit actions follow the stable `"<resource>.<verb>"` vocabulary** — the
    admin Audit tab filters on it. Keep new call sites consistent rather than
    inventing new verb shapes. Logging is best-effort and must never gate the
    action it describes.
23. RLS is enabled on every table; the only path that bypasses it is
    server-side code using the service role key.

### Migrations

24. **A migration must apply cleanly and re-apply idempotently.** Known
    exceptions are listed in `migrations.db.test.ts` and may only shrink. A new
    client-readable table needs an entry in `rls.db.test.ts`.
25. **A policy must never sub-select its own table inline** — Postgres fails it
    with 42P17 "infinite recursion". Put the read in a `SECURITY DEFINER`
    function, as `047` does.
26. Migrations auto-apply on push to master (`apply-migrations.ts`, ledger
    `schema_migrations`, checksum drift check). Take the next free number; the
    `/migration` skill walks the whole flow.

### Site and UI

27. **Generate `www` URLs** — `process.env.NEXT_PUBLIC_SITE_URL ??
    "https://www.hebridescyber.co.uk"`. The bare domain only redirects.
28. **Security headers are set by the Next server, not Azure SWA.** SWA hybrid
    mode serves every route through the managed Next.js server, which bypasses
    `staticwebapp.config.json`'s `globalHeaders` entirely (confirmed by curling
    production). Static headers live in `next.config.mjs`'s `headers()`; keep
    `staticwebapp.config.json` in sync as a fallback for pure static assets. The
    **CSP is the exception: it is per-request** (`src/proxy.ts` +
    `src/lib/csp.ts`) with a nonce and `'strict-dynamic'`, so `script-src` has no
    `'unsafe-inline'` — our own scanner grades it A (`csp.test.ts` asserts this).
    Any new inline `<script>` or `next/script` must take the nonce from
    `headers().get("x-nonce")`, and every page renders dynamically as a result.
    `tests/e2e/csp.spec.ts` fails on a browser-reported violation.
29. **Never run `shadcn init`** — it overwrites `globals.css` and
    `tailwind.config.cjs`. `npx shadcn@2 add <component>` is fine.
30. **E2E tests must never use real Supabase credentials.**
    `playwright.config.ts` hardcodes `example-project` as the project ref;
    it must stay that.

## Architecture

### One API layer

**`src/pages/api/`** — every server-side route, including the scan pipeline
(`run-scan`, `verify-ownership`, `generate-report`, `generate-fix-pr`), Stripe
webhooks/checkout/portal, admin endpoints and the contact form. Deployed to
Azure Static Web Apps, which auto-deploys them as managed Functions behind the
CDN — there is no separate standalone Azure Functions app. The daily blog and
weekly newsletter are **not** API routes. All of `src/pages/api/` can read
`NEXT_PUBLIC_*` alongside server-only vars, and uses `SUPABASE_URL` +
`SUPABASE_SERVICE_ROLE_KEY` directly for privileged operations — never the anon
key.

### Two routers in one Next.js app

- **App Router** (`src/app/`) — all pages and layouts
- **Pages Router** (`src/pages/api/`) — API routes only

### Supabase access pattern

| Context | Client | Key used |
|---------|--------|----------|
| Browser (dashboard, login) | `src/lib/supabaseClient.ts` | anon key — RLS enforced |
| API routes & Functions | `createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)` | service role — bypasses RLS |
| Admin API routes | service role for writes; anon client to verify the caller's JWT | both |

### Scan flow, in one paragraph

`/api/run-scan` is two steps: create a `scans` row and return a proof token,
then verify domain ownership and **enqueue** a `scan_jobs` row, answering
`202 { status: "queued" }`. Nothing calls `executeScan()` synchronously from an
HTTP request — a real scan once exceeded Azure SWA's Free-tier Functions
execution ceiling. `executeScan()` (`src/lib/scanExecution.ts`) is the single
implementation, called only by the queue workers
(`src/scripts/run-queued-scan-jobs.ts`) running in GitHub Actions. It always
runs the base passive suite; active tools run per the resolved profile, which
in practice means scheduled jobs only. Full detail, including the queue and
cadence: `docs/ARCHITECTURE-NOTES.md`.

### Theme system

Tailwind `darkMode: 'class'`. `ThemeScript` in `src/app/layout.tsx` adds `dark`
to `<html>` on load unless `localStorage.getItem('hc-theme') === 'light'`.
Default is dark (cyber theme).

**The cyber tokens are CSS variables, not fixed hex.** `tailwind.config.cjs`
maps them to `rgb(var(--c-*) / <alpha-value>)`, and the `:root` / `.dark` blocks
in `src/app/globals.css` hold the two palettes. This is what makes light mode
work: any surface built from these tokens re-themes automatically, with no
`dark:` variant on any of the ~700 usages.

| Token | Role | Light | Dark |
|-------|------|-------|------|
| `cyberbg` | page background | `#F6F7F9` | `#070B14` |
| `cyberpanel` | card/panel background | `#FFFFFF` | `#0D1524` |
| `cyberborder` | borders on panels | `#D6DCE4` | `#1C2940` |
| `cybertext` | primary body text | `#2F3A44` | `#FFFFFF` |
| `neon` | accent, links, glow | `#067A5B` | `#39FFC0` |

Rules when adding UI:

- **Never use `text-white` on a themed surface** — it cannot follow the theme
  and turns invisible in light mode. Use `text-cybertext`. `text-white` is
  correct only on a permanently dark background such as `bg-atlantic`.
- Same for `bg-white/N` and `border-white/N` overlays — use `bg-cybertext/N`.
- Fixed brand colours (`atlantic`, `seafoam`, `heather`, `slatedark`,
  `slatelight`) do not change between themes. Pair them with an explicit text
  colour rather than letting text inherit.
- Low-opacity steps of `cybertext` and `neon` get an alpha boost in light mode
  (the parity block in `globals.css`). Alpha tuned for white-on-black reads far
  too faint as dark-on-light — `/40` would otherwise sit at ~2.1:1 contrast.
- `shadow-glow` / `shadow-glowsm` vary by theme too; the neon bloom is dialled
  right down in light mode.

Three more per-theme tokens meet WCAG AA without the parity overrides above —
prefer them over alpha steps in new code: `cybermuted` (secondary text),
`danger`, `warning`. The shadcn/ui names (`bg-primary`,
`text-muted-foreground`, `border-input`, …) are aliases onto the same variables
so CLI-generated components render on-brand; don't use them in hand-written
code.

### UI primitives

New UI is composed from `src/components/ui/` — the shadcn/ui pattern,
hand-written against the cyber tokens (lowercase filenames there, matching
shadcn). Current set: `button` (primary/secondary/ghost/danger; `asChild` to
style a `<Link>`; defaults to `type="button"`), `card` (+`CardTitle`, the
`// section` overline with the `//` hidden from screen readers), `input`/`label`
(every input gets a label, `sr-only` if visually redundant), `alert` (danger →
`role="alert"`, else `role="status"`), `stat-card`, `segmented-control`
(`aria-pressed`), `page-header`, `empty-state`, `skeleton`. Use `cn()`
(`src/lib/utils.ts`) so callers can override classes. Don't hand-roll another
panel/button/input — the older feature components still do, and migrate
incrementally.

### App shell

`src/components/app-shell/AppShell.tsx`, mounted by
`src/app/dashboard/layout.tsx` and `src/app/account/layout.tsx`: sidebar (lg+)
or scrolling section tabs, plus one session + subscription load exposed through
`useAppSession()`. Use its `plan` for feature gating (the stored plan only while
`status === "active"`, else `"none"`) and `billingPlan` for billing display. It
also runs the MFA (AAL2) step-up redirect for every route it wraps —
`proxy.ts` only checks authentication. Pages inside it render content only:
no `min-h-screen`/`bg-grid` wrapper, no "← Dashboard" button.

| Route | Holds |
|---|---|
| `/dashboard` | Overview — KPIs, trends, latest findings, onboarding checklist |
| `/dashboard/scans` | `RunScanForm` + paginated scan list |
| `/dashboard/scans/history` | Trends (per-site score/category history) |
| `/dashboard/assets` | domain verification, monitored sites, discovered inventory |
| `/dashboard/findings` | every open finding across all sites (E-74) |
| `/dashboard/sla` | remediation SLAs — deadlines, time-to-fix, targets (Agency) |
| `/dashboard/integrations` | every external connection; plan-gated ones render `LockedFeature` |
| `/account` | profile, billing, branding, team, 2FA, audit requests, deletion |

Nav items and active-state matching live in `AppNav.tsx` (`NAV_ITEMS`,
`activeNavHref` — longest segment-prefix wins).

### Rate limiting

`src/lib/rateLimit.ts` uses Upstash Redis (`UPSTASH_REDIS_REST_URL` +
`UPSTASH_REDIS_REST_TOKEN`) for shared state across Function instances. Falls
back to an in-memory `Map` in dev — not safe across instances; don't rely on it
in production. `getClientIp` takes the entry `TRUSTED_PROXY_HOPS` (default 2)
from the right of `X-Forwarded-For` and strips the port; `GET /api/client-ip`
returns what it resolves — probe it with a forged header after any hosting
change. See rule 18.

### Payments

Stripe webhooks at `src/pages/api/stripe/webhook.ts` update `subscriptions` on
`checkout.session.completed`, `invoice.payment_failed` and
`customer.subscription.deleted`. Requires `STRIPE_WEBHOOK_SECRET` and the
`STRIPE_PRICE_*` vars. Until the price IDs are set, checkout answers 503
`checkout_unavailable` (customer wording plus a contact link on /pricing; the
missing variable is logged server-side, never sent to the browser). `plan` is
free-text, so adding a tier is a code change, not a schema one. Gating: rule 17.

### Tier A offensive scanning

Tier A unlocks the opt-in **`offensive` profile** — the only one enabling
`OFFENSIVE_ONLY_TOOLS` (`contentDiscovery`, `credentialSpray`, `strix`,
`cairn`). Being on Tier A is necessary but not sufficient:
`run-queued-scan-jobs.ts` is the authoritative gate — an `offensive` job runs
only when the owner is on Tier A **and** has a current
`offensive_scan_authorizations` row for the target **and** the domain is
verified. Otherwise it is downgraded to `safe` and audited
(`offensive_scan.refused`). This reverses the default "no destructive payloads"
posture for Tier A only, per-scan and per-target. **Owner action before
enabling the destructive tools: customer contracts/ToS must authorise real
attack traffic.**

## Testing strategy

Four independent gates, run by `deploy.yml` in this exact order before every
deploy. Reproduce locally with the matching command above (or `/verify`) rather
than inventing a different check.

1. **Lint** (`npm run lint`) — ESLint, zero tolerance for errors. Pre-existing
   `react-hooks/set-state-in-effect` warnings on a handful of components are
   known and not a regression signal.
2. **Type check** (`npx tsc --noEmit`) — `next build` does **not** run this, so
   a type error can pass a build and still be wrong.
3. **Unit/integration** (`npm run test:unit`) — Vitest, colocated as
   `*.test.ts(x)` next to the module, except API-route tests under
   `src/__tests__/api/` (the Pages Router would otherwise treat a colocated test
   under `src/pages/api/` as a route and break `npm run build`). Favour pure,
   dependency-free functions — `scanCadence.ts`'s `isScanDue()` and
   `ticketLinks.ts`'s `decideTicketAction()` are the model, unit-testable
   without a mocked Supabase/Jira. See rules 1, 2, 4.
4. **E2E** (`npm test`) — Playwright, builds the app and starts its own server
   (slow, hermetic). See rule 30.

**Database tests** (`tests/db/`, `npm run test:db`) apply every
`sql/migrations/*.sql` in order to a throwaway database on real Postgres and
test RLS as the `anon`/`authenticated`/`service_role` roles. Separate vitest
config, so `test:unit` never needs a database. See rules 24, 25.

A new scanner check or API route needs a unit test alongside it; there's no
requirement to add e2e coverage for server-only logic.

## Where to read what

Read the one entry that matches the task. Don't read these up front.

| Task | Read |
|---|---|
| Adding/changing a scanner check | `/new-scanner-check` skill, then `docs/SCANNER-CONVENTIONS.md` |
| What a specific check does, how it's gated | `docs/SCANNER-INVENTORY.md`, `docs/FUNCTIONALITY-MATRIX.md` |
| A database migration | `/migration` skill |
| Opening and landing a PR | `/ship` skill |
| Running the pre-deploy gate | `/verify` skill |
| Container Apps deploy path | `/deploy-containerapp` skill |
| Scan flow, queue, cadence internals | `docs/ARCHITECTURE-NOTES.md` |
| Remediation PRs / AI fixes / tickets / SLAs / alerts / admin panel | `docs/ARCHITECTURE-NOTES.md` |
| Content generation, sign-up, erasure, secrets at rest, audit log | `docs/ARCHITECTURE-NOTES.md` |
| Mobile table pattern, PWA icon traps, full table list | `docs/ARCHITECTURE-NOTES.md` |
| System diagrams, data flow, C4 | `docs/architecture.md` |
| Tables, ER diagram, RLS tiers | `docs/DATA-MODEL.md` |
| Public API shapes | `docs/API.md` |
| Authenticated/signed-in crawl design + safety | `docs/AUTHENTICATED-CRAWL.md` |
| Current state, in-flight plan, owner actions | `docs/NEXT-STEPS.md` |
| Security posture, threat model | `docs/security.md`, `SECURITY.md` |
