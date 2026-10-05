# Signed-in crawl (E-70 follow-up)

## What ships now (slice 1)
When a monitored target has a saved credential (`target_auth_credentials`: session cookie or Basic Auth,
migration 014, written only by `/api/account/target-auth`), the scheduled extended-tool suite runs the E-70
crawler **signed in** after the existing header recheck (`checkAuthenticated`, `authenticatedCheck.ts`).

- `authenticatedCrawl.ts`: `checkAuthenticatedCrawl`, `buildAuthenticatedCrawlFindings`.
- `crawler.ts`: `CrawlOptions.credentialHeaders`; with it set, `skipReason` also refuses
  `AUTH_ACTION_URL_RE` links (billing, checkout, invite, API keys, export, approve, ...).
- Findings are `crawl.auth.<check>[:<path>]` with the title suffix "(signed in)". Compliance and
  fix-difficulty lookups map `crawl.auth.*` to `crawl.*`. They never merge with anonymous `crawl.*` findings,
  so a signed-in gap can't be "resolved" by an anonymous scan (and vice versa).
- Unlike the anonymous crawl, the **start page is analysed too**: the base suite never saw it signed in.

## Safety rules
1. Read-only. The crawler issues GETs only; logout/delete/cancel (always) and billing/payment/invite/export
   style links (signed in) are never followed.
2. The credential is only sent to the target's own host. Off-site redirects are recorded, not followed.
   robots.txt and sitemaps are fetched anonymously. The credential is never stored in a result or logged.
3. Evidence discipline: a 401/403 start page, or a start page that redirects to a login path, makes the
   crawl `error` ("credential not accepted") rather than an empty `checked`.
4. Same limits as the anonymous crawl (50 pages, depth 3, 45 s) and robots.txt is honoured.
5. Off unless the owner connected a credential for that target; the existing `authCheck` scan-profile flag
   gates it.

## Not done yet (later slices)
- **Login recording**: a Playwright-driven login for form/CSRF/MFA-free apps, producing a session stored
  encrypted. Needs a consent wording review and encryption at rest (today `cookie_value` is plaintext
  behind service-role-only RLS, same as the other credential tables).
- **Per-target opt-in toggle** and an owner-supplied exclusion list for paths.
- **SPA route discovery** so client-routed apps expose more than their shell.
- Surfacing the signed-in crawl's own status (`extended.authCheck.crawl`) in the report UI, including the
  "credential not accepted" error, so an expired cookie is visible instead of silent.
