# Microsoft 365 / Entra ID posture checks (P1-4)

Read-only checks of a customer's Microsoft 365 tenant for the settings behind
most SME compromises. From `ENTERPRISE-GAP-ANALYSIS.md` §3, item P1-4. It fits
the non-intrusive Lookout review: it only reads configuration, and only after
the customer's admin consents.

## How it fits together

| Piece | File |
|---|---|
| Table (tenant ID only) | `sql/migrations/068_m365_tenants.sql` |
| Start, status and disconnect | `src/pages/api/account/m365-connect.ts` |
| Microsoft's redirect back | `src/pages/api/account/m365-callback.ts` |
| Signed state, nonce cookie, consent URL | `src/lib/m365Consent.ts` |
| Token and Graph client (plain `fetch`, injectable) | `src/lib/m365Graph.ts` |
| The checks (pure functions) and runner | `src/lib/scanners/m365Posture.ts` |
| Dashboard card | `src/components/M365Config.tsx` on `/dashboard/integrations` |
| Wiring | `m365` in `EXTENDED_TOOL_NAMES` (`full`, `osint`, `exposure`); `executeScan()` next to `cloudPosture` |

### Connect

1. A Pro-or-above user clicks **Connect Microsoft 365**. `POST
   /api/account/m365-connect` returns Microsoft's v2 admin-consent URL
   (`/organizations/v2.0/adminconsent`, `scope=https://graph.microsoft.com/.default`)
   and sets an HttpOnly, `SameSite=Lax` nonce cookie scoped to the callback
   path for 10 minutes.
2. `state` is `base64url({owner, nonce, expiry}).HMAC`. The HMAC key is
   derived from `M365_CLIENT_SECRET` with a fixed label.
3. A Global Administrator signs in at Microsoft and approves the permissions.
4. Microsoft redirects to `GET /api/account/m365-callback?tenant=…&admin_consent=True&state=…`.
   The callback:
   - is rate-limited by IP;
   - needs a valid, unexpired state **and** the matching nonce cookie, so a
     link started in one browser can't be finished in another;
   - doesn't trust `tenant`: it requests an app-only token for that tenant,
     which only works if our app really is consented there, checks the
     token's `tid`, and checks its `roles` include every permission in
     `M365_REQUIRED_APP_ROLES`;
   - only then upserts `m365_tenants` and audits `m365_tenant.connected`.
   The browser always lands on `/dashboard/integrations?m365=<outcome>`.
   Microsoft's error text is never reflected.

### Disconnect

`DELETE /api/account/m365-connect` deletes the row (audited as
`m365_tenant.disconnected`), so no further scan reads the tenant. Our app
has read-only permissions and can't delete its own service principal, so the
response tells the admin to remove **Hebrides Cyber** under Entra admin
center → Enterprise applications → Properties → Delete. Until they do, the
consent stays in their tenant, but we hold nothing to use it with.

### What we store

One row per owner: `tenant_id`, `consented_at`, `last_checked_at`. There's no
token, refresh token or secret of the customer's. Each scan gets a fresh
app-only token with our own credential, uses it, and discards it. Findings
contain user principal names (forwarding, the Global Admin count's detail)
and are stored with the scan like every other finding.

## Permissions

Application permissions on Microsoft Graph, all read-only:

| Permission | Used for |
|---|---|
| `Policy.Read.All` | security defaults, Conditional Access policies, authorization policy (guest and consent settings) |
| `Directory.Read.All` | Global Administrator role members, users, verified domains |
| `MailboxSettings.Read` | inbox rules (`/users/{id}/mailFolders/inbox/messageRules`) |
| `AuditLog.Read.All` | whether Entra sign-in logs are available (`/auditLogs/signIns?$top=1`) |
| `Reports.Read.All` | in the gap analysis's list; not read by any check yet. Kept so a later MFA-registration or usage check doesn't need every customer to consent again |

`AuditLog.Read.All` is **added to the gap analysis's list**. No permission in
that list can read any audit-log state. The callback refuses a consent missing
any of the five.

## Checks

| checkId | Finding when | Severity | Graph |
|---|---|---|---|
| `m365.noSecurityBaseline` | security defaults off and no enabled CA policy | high | `/policies/identitySecurityDefaultsEnforcementPolicy`, `/identity/conditionalAccess/policies` |
| `m365.mfaNotEnforcedAllUsers` | defaults off and no enabled CA policy for All users + All apps requiring MFA or an authentication strength | high | same |
| `m365.mfaNotEnforcedAdmins` | as above, for All users or the Global Administrator role | critical | same |
| `m365.legacyAuthAllowed` | defaults off and no enabled CA policy for All users blocking `exchangeActiveSync` + `other` | high | same |
| `m365.tooManyGlobalAdmins` | more than 4 user accounts hold Global Administrator | medium | `/directoryRoles(roleTemplateId='62e90394-…')/members` |
| `m365.singleGlobalAdmin` | fewer than 2 | low | same |
| `m365.externalForwarding:<userId>` | an enabled inbox rule forwards or redirects to a domain the tenant hasn't verified | high | `/domains`, `/users`, `/users/{id}/mailFolders/inbox/messageRules` |
| `m365.guestAccessUnrestricted` | guests have the same directory access as members | high | `/policies/authorizationPolicy` |
| `m365.guestInvitesUnrestricted` | `allowInvitesFrom` is `everyone` | medium | same |
| `m365.userConsentUnrestricted` | users can consent to any app (`microsoft-user-default-legacy`) | high | same |
| `m365.signInLogsUnavailable` | Microsoft refuses sign-in logs for want of Entra ID P1/P2 | medium | `/auditLogs/signIns?$top=1` |

Report-only CA policies (`enabledForReportingButNotEnforced`) don't count.
CA reads refused for licensing (no Entra ID P1) count as "no policies". Any
other failed read is an error.

Every check maps to `COMPLIANCE_MAP` (Cyber Essentials *User access control*,
a new `cis-m365` framework cited by CIS Microsoft 365 Foundations Benchmark
recommendation title, plus CIS Controls v8, ISO 27001, NIS2 and so on),
`fixDifficulty.ts`, and `attackMap.ts` where a technique fits.

### Evidence discipline

Each check returns `checked` or `error`. If any check errors, `extended.m365`
is `status: "error"` with a note naming each failed check, so
`findingLifecycle.ts` closes nothing from this scan. The findings the other
checks did evidence are still reported. More than `MAX_MAILBOXES` (1,000)
enabled users, or any failed inbox-rule read other than "no mailbox", makes
the forwarding check an error rather than a partial clean.

### What this doesn't cover (Graph has no read for it)

- **Mailbox-level forwarding** (`ForwardingSmtpAddress`) and the **outbound
  spam policy's** automatic-forwarding switch. These are Exchange Online
  settings. Inbox rules are the usual attacker route and are covered.
- **The Purview unified audit log switch** (CIS "audit log search is
  Enabled"). We report the Entra sign-in log, which an account-takeover
  investigation needs first, and the remediation text tells the customer
  to check Purview. `m365.signInLogsUnavailable` therefore isn't mapped to the
  CIS M365 audit recommendation.
- **Per-user MFA** (the legacy "enforced" toggle) and **PIM-eligible**
  Global Admin assignments.

All three could come from the Exchange Online admin API
(`Exchange.ManageAsApp`). That needs the app assigned an Entra role such as
Global Reader in each tenant, which is a bigger ask of the customer. Left as
a follow-up.

One more limit: findings are per tenant, but scans are per target, so an
owner with several sites sees the same `m365.*` findings on each, as with
`cloudPosture`.

## Configuration

| Variable | Notes |
|---|---|
| `M365_CLIENT_ID` | Application (client) ID of our multi-tenant app registration |
| `M365_CLIENT_SECRET` | Its client secret. Server-only. Rotating it also invalidates consents in flight |
| `NEXT_PUBLIC_SITE_URL` | Builds the redirect URI; defaults to `https://www.hebridescyber.co.uk` |

Without both M365 variables, the card says the feature isn't available, the
connect route answers 503, and the tool reports `not_configured`.

## Owner steps (OT candidates)

These are for `docs/OWNER-TODO.md`. That file isn't edited by this change.

1. **Register the Entra app.** Entra admin center (our own tenant) → App
   registrations → New registration. Name it *Hebrides Cyber*. Supported
   account types: *Accounts in any organizational directory (multitenant)*.
   Redirect URI (Web): `https://www.hebridescyber.co.uk/api/account/m365-callback`.
   Under API permissions → Microsoft Graph → **Application permissions**,
   add the five in the table above. Don't grant admin consent in our own
   tenant unless it's also the test tenant. Under Certificates & secrets,
   create a client secret. Set `M365_CLIENT_ID` and `M365_CLIENT_SECRET` in
   the SWA app settings **and** in the scan-worker secrets, because the
   workers run `executeScan()`.
2. **Microsoft publisher verification.** Link a verified Microsoft AI Cloud
   Partner Program (MPN) ID to the app registration. Without it, the consent
   screen shows "unverified", and tenants that only allow consent to verified
   publishers can't connect.
3. **Microsoft 365 developer tenant** for testing (see below).
4. **Approve the privacy-notice text** below and publish it on `/privacy`.

## Verifying against a Microsoft 365 developer tenant

There's no test tenant in CI. The unit tests replay hand-built Graph JSON. To
test end to end:

1. Get a developer tenant: the Microsoft 365 Developer Program sandbox, or
   any trial tenant with Entra ID P1 (Business Premium trial). Without P1
   you can only exercise the security-defaults paths.
2. In that tenant, seed known-bad settings:
   - Turn security defaults **off** and create no Conditional Access policy.
     Expect `noSecurityBaseline`, `mfaNotEnforcedAllUsers`,
     `mfaNotEnforcedAdmins` and `legacyAuthAllowed`.
   - Assign Global Administrator to five users. Expect `tooManyGlobalAdmins`.
   - In one user's Outlook on the web, add an inbox rule forwarding to an
     outside address. Expect `externalForwarding:<that user's object ID>`.
   - External collaboration settings: guest access "same as members", and
     invites from "anyone, including guests". Expect both guest findings.
   - User consent settings: "Allow user consent for apps". Expect
     `userConsentUnrestricted`.
3. Run the app locally with the M365 variables set and
   `NEXT_PUBLIC_SITE_URL=http://localhost:3000`. Add
   `http://localhost:3000/api/account/m365-callback` as a second redirect URI
   on a dev copy of the app registration. Sign in as a Pro test user, open
   `/dashboard/integrations`, click **Connect Microsoft 365** and consent as
   the developer tenant's Global Admin. Expect
   `?m365=connected` and the tenant ID on the card.
4. Queue a `full` or `exposure` scan for one of that user's verified sites
   and run `npm run queue:run-worker`. The scan's `extended.m365` should be
   `status: "checked"` with the findings above.
5. Fix each setting (turn on security defaults, or add the three CA template
   policies; reduce to two Global Admins; delete the rule; restore the guest
   and consent defaults) and scan again. Each finding should show as fixed.
6. **Error path:** in the developer tenant, delete the *Hebrides Cyber*
   enterprise application, then scan again. Expect `extended.m365.status:
   "error"` with an `AADSTS` code in the note, and **no** finding marked
   fixed.
7. **Partial consent:** remove one permission from the app registration,
   disconnect, and connect again. Expect `?m365=missing_permissions` and no
   row saved.
8. **Disconnect:** click Disconnect. The row is gone, the next scan reports
   `not_configured`, and the card shows the revoke steps.

## Draft privacy-notice addition (needs owner approval)

> **Microsoft 365 connection (optional).** If you connect your Microsoft 365
> tenant, a Global Administrator in your organisation grants our application
> read-only access through Microsoft's own consent screen. We store your
> tenant ID and when you connected. We don't store passwords, access tokens
> or any credential of yours. When a scan runs, we read your tenant's
> security configuration from Microsoft Graph: security defaults and
> Conditional Access policies, which accounts hold the Global Administrator
> role, guest and app-consent settings, your verified domains, whether
> sign-in logs are available, and, for each enabled user, the forwarding and
> redirect actions of their inbox rules. We don't read the content of email,
> files, calendars or chats. We keep the results of each check as part of
> that scan's findings. That includes the user names of Global
> Administrators and of mailboxes that forward outside your organisation, and
> the external addresses they forward to. They're kept for as long as we keep
> the scan. Our lawful basis is our contract with you, and the legitimate
> interest of securing your organisation's accounts. You can disconnect at
> any time from Integrations, after which we stop reading your tenant. To
> remove our access entirely, a Global Administrator deletes the Hebrides
> Cyber enterprise application in the Microsoft Entra admin center.

Before publishing, the owner should check the retention wording against the
existing scan-retention section of `/privacy`, and add the processing to the
records of processing activities.
