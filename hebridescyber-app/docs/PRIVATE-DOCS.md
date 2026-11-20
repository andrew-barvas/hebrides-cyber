# Private documents

On 2026-11-20 the business documents below moved to the **private** repo
[`andrew-barvas/hebrides-cyber-docs`](https://github.com/andrew-barvas/hebrides-cyber-docs)
so this repo can be public. They were copied from master at `798cdca`; their
earlier versions are still in this repo's git history.

Code comments and other docs here still name them (for example "pricing copy
sourced from marketing/03-pricing-page.md"). The paths in the private repo
mirror the old ones, with `hebridescyber-app/docs/` shortened to `docs/`:

| Old path here | In the private repo |
|---|---|
| `marketing/*` (homepage, pricing and brand copy, marketing and advertising plans, business plan, funding roadmap, grant applications, outreach, launch campaigns) | `marketing/*` |
| `hebridescyber-app/docs/legal/*` (OT-13 solicitor and insurer briefs, draft terms of service) | `docs/legal/*` |
| `hebridescyber-app/docs/COMPETITOR-ANALYSIS-ENTERPRISE-2026-11.md`, `COMPETITOR-MATRIX.md`, `COMPETITIVE-ANALYSIS.md`, `COMPETITIVE-REVIEW-2026-11.md`, `STRATEGY-REVIEW-2026-10.md` | `docs/` |
| `hebridescyber-app/docs/EXPLOIT-PRODUCT-PLAN.md`, `DEFENSIVE-ASSESSMENT-PLAN.md` | `docs/` |
| `hebridescyber-app/docs/SPRINT-PLAN.md` | `docs/` |
| `hebridescyber-app/docs/OWNER-TODO.md`, `OWNER-SETUP.md` (second batch, from `a97a782`) | `docs/` |
| `hebridescyber-app/docs/ROADMAP.md`, `PRODUCT-IDEAS.md`, `LAUNCH-PRIORITY.md`, `PRODUCT-REVIEW-2026-10.md`, `ENTERPRISE-GAP-ANALYSIS.md`, `IMPROVEMENT-REVIEW-2026-11.md`, `ONE-PAGE-OVERVIEW.md`, `AUDIT-2026-11-POST-MERGE.md` (second batch) | `docs/` |

**Rule for new work:** business plans, pricing strategy, funding, grant,
legal, insurance, competitor and go-to-market documents go in the private
repo, never here. Engineering docs (architecture, data model, scanner
inventory, runbooks) stay here. Read or edit the private repo with
`gh repo clone andrew-barvas/hebrides-cyber-docs` (it needs the owner's
GitHub access, so cloud sessions may not have it).

**Owner to-dos (OT items)** live in the private repo's `docs/OWNER-TODO.md`
now. A session that finds an owner-only step adds it there by PR, and
references it here only by number ("OT-69"), never with its detail.

**Full-history backup:** the private `andrew-barvas/hebrides-cyber-archive`
repo holds every branch of this repo as of 2026-11-20, plus every pull
request's head as `archive/pr-<n>`, taken before removing these files from
history.
