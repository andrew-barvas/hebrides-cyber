# Onboarding (contributors)

## §0 Scope

**This is for contributors/developers, not customers.** A customer never
reads the repo — their onboarding is `docs/USER-GUIDE.md` §4.1's first-scan
walkthrough and the in-app flow itself. Building a separate
customer-facing markdown file has a readership of zero and becomes a fourth
place plan behaviour can drift out of sync; proper in-app customer
onboarding (a first-run checklist) is tracked as an enhancement instead —
see `docs/ENHANCEMENTS.md` E-16.

**Two-root repo layout** — the first thing that trips up a new contributor:
`marketing/`, `action/`, and the primary `.github/workflows/` (including
`deploy.yml` and `scheduled-scans.yml`) live at the **git root**
(`hebrides-cyber/`), one level *above* the app itself
(`hebrides-cyber/hebridescyber-app/`), which has its own package.json,
CLAUDE.md, README, and a second, unrelated `on-demand-scan.yml`. GitHub only
executes workflows from the repo-root `.github/workflows/` — the copy
nested inside `hebridescyber-app/` never runs. This has already caused one
real mistake: an earlier engineering pass concluded `scheduled-scans.yml`
was missing because it checked the wrong directory (see the frozen decision
log for the full story). If something "isn't there," check the other root
before concluding it's missing.

---

## §1 Reading order (with a time budget)

Product before code — reading `CLAUDE.md` first produces a contributor who
can edit a scanner but can't judge whether a finding should exist.

1. **`README.md`** (~10 min) — setup, commands, deploy. Follow it to get
   the app running locally before reading further.
2. **Run it** (§2 below) — don't skip this. Reading architecture docs
   without ever seeing the dashboard render makes every later doc more
   abstract than it needs to be.
3. **`docs/USER-GUIDE.md` §1–3** (~15 min) — what this product is, who it's
   for, what it actually checks. This is the "why" that everything in
   CLAUDE.md exists to serve.
4. **`CLAUDE.md`** (~25 min) — the deep technical reference: architecture,
   scan flow, scanner pipeline, ticket lifecycle, DB schema, deployment.
5. **`docs/architecture.md`** (~10 min) — the data-flow picture: on-demand
   vs. scheduled-queue-worker scans, one deployed surface, the security
   model summary.

Total: under an hour to a genuinely useful mental model. Everything else
(`docs/API.md`, `docs/security.md`, `docs/SCANNER-CONVENTIONS.md`,
`docs/FUNCTIONALITY-MATRIX.md`) is reference material — read on demand when
a task needs it, not up front.

---

## §2 Running it — verification checkpoints

Not a repeat of README's commands (link them, don't restate) — each step
here is "you know it worked when X," so a stuck contributor can tell
*where* it's stuck.

| Step | Command | You know it worked when |
|---|---|---|
| Install | `npm ci` | No errors; `node_modules/` populated |
| Env | copy `.env.example` → `.env.local`, fill in Supabase URL + anon key | App boots without the `[supabaseClient] ... using a placeholder client` console warning |
| Dev server | `npm run dev` | `localhost:3000` renders the homepage |
| A real scan, no dashboard | `npm run scan:local -- https://example.com` | Prints real findings as JSON + a 0–100 score to the console |
| Seed demo accounts | `npm run seed:users` | Prints login credentials for admin/basic/pro/agency/no-plan accounts |
| Dashboard, logged in | log in with a seeded account | `/dashboard` renders with that account's plan state |
| Unit tests | `npm run test:unit` | All green |
| Coverage floor | `npm run test:unit:coverage` | Reported statements/branches/functions/lines all ≥ the thresholds in `vitest.config.mts` (never below — see §6) |
| Type check | `npx tsc --noEmit` | No errors |
| Lint | `npm run lint` | 0 errors (warnings are pre-existing and tracked separately, not a blocker) |
| Full build | `npm run build` | Succeeds — this is also where a Next.js Pages-Router route-validator conflict would surface (e.g. a stray test file under `src/pages/api/`) that `tsc --noEmit` alone won't catch |

---

## §3 Minimum viable env vs. what silently degrades

`.env.example` documents ~40 vars with real prose per var — read it, don't
skip it. Three actually boot the app:
`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, and (for
server-side/admin work) `SUPABASE_SERVICE_ROLE_KEY`.

Everything else degrades to `not_configured` or a disabled feature rather
than an error — which is exactly why it's easy to miss that a check never
ran. The three most commonly missed in local dev:
`WPSCAN_API_TOKEN`, `GOOGLE_SAFE_BROWSING_API_KEY`, `HIBP_API_KEY` — a local
scan will complete successfully and simply be missing those findings
entirely, with no error to notice. If you're testing one of those specific
checks, confirm the key is actually set before concluding the check itself
is broken.

Full inventory of what depends on what: `docs/FUNCTIONALITY-MATRIX.md` §7.

---

## §4 Code map — five things that unlock the rest

Pointers into `CLAUDE.md`, not restated here:

1. **One API layer, two routers.** `src/app/` (App Router) owns every page.
   `src/pages/api/` (Pages Router) owns every API route. This split is
   deliberate, not legacy — see CLAUDE.md's "Two routers in one Next.js app."
2. **Anon-key vs. service-role client selection is the whole security
   model.** Browser code uses the anon key (RLS-enforced); API routes use
   the service role (bypasses RLS, requires an explicit ownership/admin
   check in the route itself). Getting this backwards in a new route is the
   most common way to introduce a real vulnerability here — see
   `docs/ONBOARDING.md` §5 below and `CLAUDE.md`'s "Supabase access pattern."
3. **`executeScan()` (`src/lib/scanExecution.ts`) is the single scan entry
   point.** Every scan path — dashboard, public API, scheduled queue — ends
   up here. There is no second implementation to keep in sync.
4. **`runExtendedTools` is the passive/active boundary**, not a plan gate —
   see `docs/FUNCTIONALITY-MATRIX.md` §3 for exactly what that means and why
   it surprises people.
5. **Migrations are append-only and numbered.** Never edit an old migration
   file to "fix" it — write a new one that supersedes it (see `015` and
   `017` for examples of exactly this pattern) — and run it against the
   Supabase project yourself; nothing applies it automatically.

---

## §5 Danger zones

Places where a small, reasonable-looking change has caused (or almost
caused) a real problem in this codebase:

- **RLS migrations.** `001_init.sql` shipped an UPDATE policy that let any
  authenticated user grant themselves admin — fixed in `017`, but it's a
  reminder that a policy checking *who* is writing is not the same as
  checking *what* they're allowed to write. Read an existing migration's
  `with check` clause carefully before writing a new one.
- **`src/lib/apiAuth.ts` / `src/lib/adminAuth.ts`.** The sole gate on every
  session-authenticated and admin route respectively. Two admin routes
  (`overview.ts`, `contacts.ts`) hand-roll their own version instead of
  calling `requireAdmin()` — don't add a third; use the shared helper.
- **Any new service-role Supabase call.** Must carry an explicit ownership
  or admin check in the same function — service-role bypasses RLS entirely,
  so there's no database-level safety net if the code forgets.
- **`src/lib/scanners/remediationText.ts`.** 1,400+ lines of static text
  shown directly to paying customers as fix instructions. A wrong snippet
  here is a customer-facing correctness bug, not just a typo.
- **`src/lib/ownership.ts`'s `validateNoSsrf()`.** The guard that stops this
  product being used to scan infrastructure the caller doesn't control (or
  internal/cloud-metadata addresses). Called on every scan-creation path —
  never add a new scan-triggering route without it.
- **`src/pages/api/stripe/webhook.ts`.** Real money. The idempotency guard
  (an `audit_logs` ledger, not Stripe's own idempotency keys) and the
  plan-defaults-to-`"basic"`-on-missing-metadata fallback are both easy to
  break without noticing in a refactor.

---

## §6 What gets a PR rejected

- **An unevidenced finding.** Every check follows
  `docs/SCANNER-CONVENTIONS.md` §4 — if the server's behaviour is
  ambiguous, the check returns nothing. No exceptions for "probably right."
- **Lowering the coverage floor** in `vitest.config.mts`. It's a floor set
  to the actual number achieved, not a target — it only ever moves up,
  matching whatever `npm run test:unit:coverage` reports after a change
  that adds real coverage.
- **A new env var with no `.env.example` entry** (with prose explaining
  what it's for and what happens if it's unset) **and no README Secrets
  table row** if it needs to be a GitHub Actions secret.
- **Editing an old migration file.** Append a new one instead — see §4.
- **A test file under `src/pages/api/`.** Next.js's Pages Router treats
  every file there as a route candidate regardless of extension, and its
  build-time route validator will fail on a `*.test.ts` with no default
  export. API route tests live under `src/__tests__/api/` instead, importing
  the handler via the `@/pages/api/...` alias.

---

## §7 First tasks

Five bounded, real starting points — pick one, or use them as a template
for scoping your own. Each references its full write-up in
`docs/ENHANCEMENTS.md` by ID; read the linked item for the actual
acceptance criteria rather than treating this list as the spec.

- **E-05** — add rate limiting (and ideally a honeypot field) to the public,
  unauthenticated `POST /api/contact` — currently the only fully open write
  path with no abuse protection at all. Good first task: small, isolated,
  the pattern to copy (`checkRateLimit`) already exists in `run-scan.ts`.
- **E-08** — migrate `admin/overview.ts` and `admin/contacts.ts` off their
  hand-rolled admin checks onto the shared `requireAdmin()` helper. Good
  first task: mechanical, but touches a security-sensitive path, so it's a
  real exercise in reading `src/lib/adminAuth.ts` carefully before changing
  anything that depends on it.
- **E-19** — delete the stale, never-executed duplicate
  `hebridescyber-app/.github/workflows/on-demand-scan.yml` (the real one is
  one level up, at the git root). Good first task for getting comfortable
  with the two-root layout described in §0.
- One item from `docs/FUNCTIONALITY-MATRIX.md` §5/§6 — pick any dashboard
  capability currently marked ❌ "no plan gate" and add the server-side
  check, following `branding-logo.ts`'s pattern (the one capability that
  already does this correctly). Good first task for learning the
  anon-vs-service-role model in §5 above by doing it correctly once.
- Extend test coverage for one scanner module currently marked "no" in
  `docs/FUNCTIONALITY-MATRIX.md` §2/§3's Tests column, following the pattern
  in an already-tested module like `headers.test.ts` or `dns.test.ts` (both
  demonstrate mocking Node built-ins correctly — read their header comments,
  they document a real gotcha with `vi.mock` + `importOriginal` on Node
  built-in modules that cost real debugging time to discover).
