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

## Login recording (slice 2, shipped 2026-10-12)
The owner no longer has to manually copy a session cookie out of devtools: `POST
/api/account/record-login` (`src/lib/scanners/loginRecorder.ts`) drives a real headless browser through the
site's own login **form** — loads the login page, fills a username and password field, presses Enter — and
saves the resulting cookies as a normal `target_auth_credentials` "cookie" row, same as entering one by
hand.

- Scope matches the "form/CSRF/MFA-free apps" framing above: a plain username/password form submitted by
  pressing Enter (so the page's own CSRF token, if any, travels with it exactly as a real visitor's would).
  **TOTP MFA only** (migration 064): an optional base32 `totpSecret` (RFC 6238, SHA-1, 6 digits, 30 s;
  `src/lib/totp.ts`) makes the recorder wait for the MFA field after the password step, type the current
  code, and submit. The secret needs a verified domain, is stored sealed in `target_auth_credentials.totp_secret`
  (reused on re-record), and the browser runner only ever gets a code supplier. Any other challenge (SMS, push,
  WebAuthn, OAuth) still reads as a failed login, not a false success. Not verified against a real MFA site.
- Same gates as the manual cookie/Basic-auth path: Agency plan, session auth only (no API key), and the
  caller must own the `monitored_targets` row. The `loginUrl` is additionally required to be on the same
  host as the monitored target (or a subdomain of it) and `https://` — a plaintext login page would send
  the password unencrypted.
- The password is used once, server-side, and is never logged, stored, returned, or placed in the audit
  row (`login_recorder.succeeded`/`.failed`) — only whether the attempt succeeded.
- **Still open, called out again because the item above didn't resolve it**: `cookie_value` is plaintext at
  rest behind service-role-only RLS, identically to the manual-entry path this reuses — login recording
  doesn't make that gap worse, but doesn't fix it either. A public-facing consent-wording review (what the
  UI's checkbox and any marketing copy say about using a dedicated test account, never a personal/admin
  login) is also still owed before this is promoted beyond the dashboard's own in-form copy.

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
- **Per-target opt-in toggle** and an owner-supplied exclusion list for paths.
- **SPA route discovery** so client-routed apps expose more than their shell.

Done 2026-10-31: the signed-in crawl's own status (`extended.authCheck.crawl`) is surfaced by
`signedInCrawlStatus.ts`, as a "signed-in crawl" card on the report page and as "signed-in crawl" under
the executive PDF's "Checks that did not finish", so a "credential not accepted" error is visible
instead of silent.
