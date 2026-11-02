# OT-13 — Solicitor brief (DRAFT, owner to action)

> **This is a brief for a solicitor, not legal text and not legal advice.** It
> lists what the engagement terms need to cover so a practising UK solicitor can
> draft or review them and take professional responsibility for the wording. No
> offensive-tier testing may run until these terms are solicitor-reviewed and PI
> insurance is bound (OT-13). The existing draft terms are at
> `docs/legal/terms-of-service-draft.md`.

## Context for the solicitor

HebridesCyber is a UK solo-operator security business. It currently sells
non-intrusive external vulnerability scanning. It plans an **authorised
offensive-testing tier** that would send real test traffic to a customer's own
systems, only with the customer's signed authorisation and after verifying the
customer controls the target domain. That tier is not live and will not go live
until these terms and insurance are in place.

## What the terms need to cover

1. **Authorisation and scope.** How the customer authorises testing: named
   assets/domains/IP ranges only, agreed time windows, and the fact that
   authorisation is evidenced per engagement (the platform records a signed
   authorisation and verifies domain ownership before any traffic). The
   Computer Misuse Act 1990 makes the customer's authorisation the thing that
   makes the testing lawful, so the terms should make that authorisation
   explicit and recorded.

2. **Customer warranties.** The customer warrants it owns, or is contractually
   entitled to permit testing of, every in-scope asset, and will not list
   assets on shared or third-party infrastructure without that provider's
   consent (e.g. cloud-provider acceptable-use policies). An indemnity to
   HebridesCyber if that warranty is false.

3. **Limitation of liability.** A liability cap and exclusions appropriate to
   the activity, **aligned to the PI policy limit** once that is bound (see
   `OT-13-insurer-brief.md`). Treatment of consequential loss and of
   service disruption that may occur even in authorised testing.

4. **Safety and control.** The customer's right to pause or abort a test; an
   emergency contact; HebridesCyber's right to stop if it detects risk of harm.

5. **Data handling and confidentiality.** Findings contain sensitive security
   data about the customer. Retention, confidentiality, and UK GDPR
   obligations (what is processed, on what basis, for how long).

6. **Out of scope / prohibited.** No social engineering, no physical testing,
   no denial-of-service, nothing beyond the signed scope — whatever the
   solicitor considers prudent to exclude.

7. **Regulatory fit.** Any professional, insurance, or advertising-standards
   requirements the solicitor identifies for selling security testing in the UK.

## Questions for the solicitor

- Are the draft terms sufficient to rely on the customer's authorisation as the
  lawful basis for testing under the Computer Misuse Act 1990?
- Is the liability cap appropriate, and does it need to match a specific
  insurance limit?
- Are there consumer vs. business-customer distinctions that change the terms?
- Anything that must be a condition precedent before the first engagement?

## Owner inputs still needed

- `[OWNER: the PI policy limit, once quoted/bound, so the cap can be aligned]`
- `[OWNER: target customer type — businesses only, or also sole traders/consumers]`

## Sequence (do not reorder)

1. Insurance quoted and **bound** (`OT-13-insurer-brief.md`).
2. Solicitor reviews/drafts these terms and aligns the liability cap to the
   policy.
3. Only then does the engineering gate open. Until both are done, the
   offensive tools (`contentDiscovery`, `credentialSpray`, `strix`, `cairn`)
   stay `not_configured` and the `offensive` profile is downgraded to `safe`
   and audited — per `hebridescyber-app/CLAUDE.md`, "Tier A offensive scanning",
   and OT-13 in `OWNER-TODO.md`.
