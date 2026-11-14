# Designs: Lookout report builder, estate screenshots, Google Workspace checks (2026-11-14)

These are tasks 5, 6 and 10 from `IMPROVEMENT-REVIEW-2026-11.md`. Each is too big for one PR and depends on an owner decision, so this file is the build plan. **Owner decisions are marked ⚑.** Everything else follows the repo's rules: evidence discipline, service-role tables, and plan gating through `planAccess.ts`.

## 5. Lookout analyst report builder

**Goal:** an engineer turns a month or quarter of a Lookout customer's results into a dated report with commentary. The customer reads it in the portal, can download a PDF, and confirms they've seen it. This is the "managed" in the managed exposure review (`DEFENSIVE-ASSESSMENT-PLAN.md`, "Reporting Structure").

**What already exists to reuse:**
- `estateDrift.ts` (#226): what changed in the period
- `estatePriority.ts`: the "fix this first" ranking, with reasons
- `groupFindings`: one fix across many hosts
- `attackMap.ts` (ATT&CK and CWE)
- the exploitability engine's "assessed" wording
- `executiveReport.ts` (HTML for PDF) and `portfolioReport.ts` (multi-site)

**Data (migration, service-role only, managed through the API):**

| Table | Columns |
|---|---|
| `lookout_reports` | `id`, `customer` (owner id), `period_start`, `period_end`, `status` (draft, published, acknowledged), `summary` (the analyst's text), `created_by`, `published_at`, `acknowledged_at`, `acknowledged_by` |
| `lookout_report_items` | `report_id`, `host`, `check_id`, `included`, `priority` (1 to n), `analyst_note`, `business_impact`, `fix_owner` (customer or their IT supplier) |

**Flow:**
1. **Create (admin, `/admin/lookout`):** choose a customer and period. The draft is pre-filled from drift, the ranking and the grouped fixes, with the top 10 included.
2. **Edit:** the engineer reorders, writes notes and the summary, and previews the PDF.
3. **Publish:** the customer gets an email (OT-02) and a portal page, `/dashboard/lookout/reports/<id>`, gated by `isLookoutPlan`.
4. **Acknowledge:** the customer clicks "I've read this report". It's recorded with who and when, and audited.

**Owner decisions:**
- ⚑ **Who writes reports.** Admins only for now (`users.is_admin`), or a new analyst role.
- ⚑ **What "acknowledge" means.** It's not legal acceptance of risk. The wording should be checked under OT-35.
- ⚑ **Cadence per tier** (OT-42): quarterly for Essentials, monthly for Assured, as `DEFENSIVE-ASSESSMENT-PLAN.md` proposes.

**Size:** about three PRs (data and API; admin editor; customer portal and PDF).

## 6. Per-host screenshots for Lookout

**Goal:** one screenshot per live web host across the customer's estate, so the analyst and the owner can spot forgotten sites at a glance. #230 already captures the scanned page inline.

**Design:**
- **Which hosts:** live web hosts from the `httpx` results and `asset_inventory`, capped per tier ⚑. The cap is in OT-42, perhaps 25 for Essentials and 100 for Assured.
- **Capture:** one Playwright page load per host in the worker, the same as #230: viewport only, JPEG at quality 45, a 5-second limit, and robots.txt respected as the crawl already does.
- **Storage:** inline data URIs don't scale to 100 hosts.
  - **Where:** a private Supabase Storage bucket, `host-screenshots`, at `<owner>/<host>/<scan_id>.jpg`.
  - **Who writes:** only the service role uploads.
  - **How the owner sees them:** through `GET /api/scans/<id>/screenshots`, which returns short-lived signed URLs.
  - **Retention:** deleted with the scan, plus a 90-day sweep in `cleanup-retention.ts`.
- **Display:** an estate gallery on the report and in the Lookout report builder (task 5).
- **Traffic disclosure:** "load pages from your websites" already covers one page load per host, so no change is expected. ⚑ Confirm under OT-43.

**Owner decision:** ⚑ the per-tier host cap. (Storage cost is small: about 50 KB × hosts × scans.)

**Size:** two PRs (capture and storage; gallery).

## 10. Google Workspace posture checks

**Goal:** the Workspace equivalent of `m365Posture.ts`, for customers on Google Workspace. CISA's ScubaGoggles is the reference baseline (see `M365-POSTURE.md`).

**Consent model:** the same pattern as Microsoft 365.
- **Connection:** a Workspace super admin authorises our Google Cloud app with **read-only** OAuth scopes. We store only a refresh token, sealed with `credentialEncryption.ts` (rule 20).
- **Rejected alternative:** domain-wide delegation through a service account. It would mean asking customers to grant a broad standing delegation, which is a bigger ask than M365's admin consent.

**Scopes (read-only):**
- `admin.directory.user.readonly`: users and their 2-Step Verification status
- `admin.directory.rolemanagement.readonly`: super admins
- `admin.reports.audit.readonly`: login and admin audit, and whether data is available
- `apps.alerts`: read alert centre alerts, if wanted ⚑

**First checks:**

| checkId | Finding when | Severity |
|---|---|---|
| `workspace.2svNotEnforced` | 2-Step Verification isn't enforced for all users (users not enrolled in or enforced into 2SV) | high |
| `workspace.adminsWithout2sv` | a super admin isn't enrolled in 2SV | critical |
| `workspace.tooManySuperAdmins` / `singleSuperAdmin` | more than 4 / fewer than 2 super admins (the same CIS logic as M365) | medium / low |
| `workspace.externalForwarding` | users with automatic forwarding to outside domains, from the Gmail settings API (needs `gmail.settings.basic` per user via delegation) ⚑ | high |
| `workspace.loginAuditUnavailable` | the Reports API refuses login events | medium |

**Owner steps (new OT-58):**
- create a Google Cloud project and OAuth client
- configure the OAuth consent screen
- pass Google's verification for sensitive scopes, which can take weeks; the admin-directory read scopes are "sensitive", not "restricted"
- set `GOOGLE_WORKSPACE_CLIENT_ID` and `GOOGLE_WORKSPACE_CLIENT_SECRET`

**Owner decisions:**
- ⚑ **Forwarding check.** It needs per-user Gmail settings access, which only works with domain-wide delegation. Leave it out of version 1, or offer delegation as an optional extra step.
- ⚑ **Alert centre.** Whether to read alert centre alerts.

**Size:** about three PRs (consent flow and storage; the checks; report and compliance mapping).
