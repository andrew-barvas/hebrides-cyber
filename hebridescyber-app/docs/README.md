# Documentation map

Which doc answers which question. No original content lives here — every
row links to the file that owns that topic; if you find the same fact
stated in two places, one of them is wrong and should be pointing here
instead.

## Two-root repo layout

`marketing/`, `action/`, and the primary `.github/workflows/` (including
`deploy.yml` and `scheduled-scans.yml`) live at the **git root**
(`hebrides-cyber/`), one level *above* this app (`hebridescyber-app/`),
which has its own `package.json`, this `docs/` folder, and a second,
unrelated `.github/workflows/on-demand-scan.yml`. GitHub only executes
workflows from the repo-root `.github/workflows/`. If something "isn't
there," check the other root before concluding it's missing — this has
caused a real mistake before (see the frozen engineering log's 16 Aug
entry).

## "I want to..."

| Question | Doc |
|---|---|
| ...get this running locally, deploy it, or set GitHub Secrets | [`../README.md`](../README.md) |
| ...understand what the product does, who it's for, and see user stories | [`USER-GUIDE.md`](USER-GUIDE.md) |
| ...see the high-level system picture / data flow | [`architecture.md`](architecture.md) |
| ...understand the security model, threat handling, retention | [`security.md`](security.md) |
| ...use the public REST API or the packaged GitHub Action | [`API.md`](API.md) |
| ...know exactly what exists, how it's triggered, and how it's *actually*
  gated by plan (as opposed to how it's advertised) | [`FUNCTIONALITY-MATRIX.md`](FUNCTIONALITY-MATRIX.md) |
| ...know how this compares to Intruder/Probely/Astra/etc., and where the
  real product gaps are | [`COMPETITIVE-ANALYSIS.md`](COMPETITIVE-ANALYSIS.md) |
| ...see the backlog of things that could be built, with reasoning and an
  ID to reference | [`ENHANCEMENTS.md`](ENHANCEMENTS.md) |
| ...see what's actually blocking this from being safe to sell/scale, with
  verifiable exit criteria | [`ROADMAP.md`](ROADMAP.md) |
| ...get oriented as a new contributor | [`ONBOARDING.md`](ONBOARDING.md) |
| ...know the rules for writing or extending a scanner check | [`SCANNER-CONVENTIONS.md`](SCANNER-CONVENTIONS.md) |
| ...find the Terms of Service starting draft (not yet published — needs a solicitor and every `[PLACEHOLDER]` resolved first, see `docs/ROADMAP.md` BETA-B1) | [`legal/terms-of-service-draft.md`](legal/terms-of-service-draft.md) |
| ...understand *why* a past architectural decision was made (BullMQ
  deletion, Azure Container Apps rejection, etc.) | [`decisions/ENGINEERING-LOG-2026-08.md`](decisions/ENGINEERING-LOG-2026-08.md) (frozen — historical only, see its own banner) |
| ...see day-to-day coding conventions and the deep technical reference | [`../CLAUDE.md`](../CLAUDE.md) |
| ...find consultancy service-line market pricing (pen tests, IR retainers,
  compliance advisory) — a different question from the product-competitor
  one above | [`../../marketing/09-competitor-services-catalogue.md`](../../marketing/09-competitor-services-catalogue.md) |

## Ownership rules (so nothing gets duplicated)

- **`FUNCTIONALITY-MATRIX.md`** owns *what exists and how it's gated*.
  **`USER-GUIDE.md`** owns *what a feature is for and how a customer uses
  it*. **`CLAUDE.md`** owns *how the code implements it*. Never restate one
  in another — link instead.
- **`ENHANCEMENTS.md`** owns *what could be built and why*, no commitment,
  no dates. **`ROADMAP.md`** owns *what's actually sequenced*, referencing
  `ENHANCEMENTS.md` items by `E-nn` ID only, never restating their content.
- **`COMPETITIVE-ANALYSIS.md`** owns SaaS product comparison (Intruder,
  Probely, Astra, etc.). **`../../marketing/09-competitor-services-catalogue.md`**
  owns consultancy service-line market pricing (pen tests, IR retainers).
  Different questions; they cross-reference, never duplicate.
- **`decisions/ENGINEERING-LOG-2026-08.md`** owns *history*. It is frozen —
  nothing forward-looking gets written back into it, and nothing in it
  should be trusted as current without checking the file it points to
  instead.

## Standing rule for every doc in this folder

**Docs describe the system as it is, including what's broken or
unenforced.** Where the product doesn't yet do what it's sold to do (see
`FUNCTIONALITY-MATRIX.md` §5/§6 for the current list), say so plainly and
link the tracking item — don't silently describe the aspiration as if it
were shipped. The roadmap is where aspiration belongs; everything else
describes reality.
