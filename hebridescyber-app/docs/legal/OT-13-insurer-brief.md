# OT-13 — Insurer / broker brief (DRAFT, owner to action)

> **This is preparation material, not insurance cover.** It is written so the
> owner can get an accurate quote from a broker quickly. No offensive-tier
> testing may run until a policy is **bound** and the ToS is solicitor-reviewed
> (OT-13). Fill the `[OWNER: …]` gaps before sending to a broker.

## 1. The business, in one paragraph

HebridesCyber is a UK-based, solo-operator security business. It sells
automated external vulnerability scanning to small and medium businesses by
subscription. All current scanning is non-intrusive: it inventories exposed
services, checks TLS and configuration, and reports known-vulnerability matches.
It does **not** currently run exploitation or send attack payloads. The cover
being sought is to support (a) the existing non-intrusive service today, and
(b) a planned, authorised offensive-testing tier that is **not yet live**.

## 2. What the planned offensive tier would do

- Active security testing **only against assets the customer owns or is
  contractually authorised to permit testing of**, confirmed by domain-ownership
  verification (DNS TXT or a well-known file) and a signed per-engagement
  authorisation before any traffic is sent.
- Testing would be scoped, time-boxed and rate-limited, with the customer able
  to pause or abort.
- No testing of shared or third-party infrastructure without that party's
  consent.

This tier is the reason PI / cyber cover is needed before launch: authorised
testing can still, in rare cases, disrupt a customer system or surface customer
data, and the policy is the backstop if a claim arises.

## 3. Cover to ask about

- Professional indemnity (PI) — for claims that the testing caused loss.
- Cyber liability — for data-handling and breach-response exposure.
- Public liability — if the broker recommends it for the activity.

## 4. Questions for the broker

1. Does your PI wording cover **authorised penetration testing / security
   testing**, or is "hacking" / "deliberate acts" excluded? Get this in writing.
2. What minimum limit of indemnity do you recommend for this activity, and what
   limit do typical B2B customer contracts require?
3. Is cover per-claim or aggregate? What is the excess?
4. What territorial and jurisdiction limits apply? (Business is UK-based;
   customers may be UK-only — `[OWNER: confirm]`.)
5. What do you need to see about the **authorisation process** (signed consent,
   scope control, ownership verification) to offer cover?
6. Is run-off / retroactive cover available, and at what cost?
7. Are there conditions precedent (e.g. a solicitor-reviewed contract) that must
   be in place for a claim to be valid? — this ties OT-13's two halves together.

## 5. Owner inputs still needed

- `[OWNER: expected annual revenue / number of customers for the quote]`
- `[OWNER: customer geography]`
- `[OWNER: any existing business insurance to extend vs. new policy]`

## 6. Sequence (do not reorder)

1. Get quotes using this brief.
2. **Bind** a policy.
3. Solicitor reviews the ToS (see `OT-13-solicitor-brief.md`) and aligns the
   liability cap to the policy limit.
4. Only then does the engineering gate open: see
   `docs/DEFENSIVE-ASSESSMENT-PLAN.md` and OT-13 in `OWNER-TODO.md`. The
   offensive tools stay `not_configured` until all of the above is done.
