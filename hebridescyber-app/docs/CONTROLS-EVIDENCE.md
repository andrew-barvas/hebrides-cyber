# Controls evidence map (SOC 2 / ISO 27001 readiness)

**Status: HebridesCyber is not SOC 2 attested and not ISO 27001 certified.**
This file maps the engineering controls already in this repository to the
SOC 2 Trust Services Criteria and ISO/IEC 27001:2022 Annex A themes, so a
future auditor (or readiness tool) has somewhere to start. It is a mapping,
not a claim of compliance. Mapping a control to a criterion says "evidence
exists here", not "the criterion is met".

Paths are relative to the git root (the repository contains `.github/` and
`hebridescyber-app/`). Everything under "Evidence" was checked to exist when
this file was written; re-check after large moves. The public summary is the
`/trust` page (`hebridescyber-app/src/app/trust/page.tsx`). Detailed weakness
lists are deliberately not kept in this public repository; the "Gaps" column
states programme-level gaps only.

## Security (SOC 2 Common Criteria)

| Criterion | ISO 27001:2022 Annex A | Evidence in this repo | Gaps (programme level) |
|---|---|---|---|
| CC1 Control environment | A.5.1 Policies, A.5.2 Roles, A.6.3 Awareness | `SECURITY.md`; `hebridescyber-app/docs/security.md` (operational guidance); `hebridescyber-app/CODE_OF_CONDUCT.md` | No formal information-security policy set, no documented roles and responsibilities, no awareness-training record |
| CC2 Communication | A.5.14 Information transfer, A.6.8 Event reporting | `SECURITY.md` (disclosure policy); `hebridescyber-app/public/.well-known/security.txt`; `hebridescyber-app/src/app/privacy/page.tsx`; `hebridescyber-app/src/app/terms/page.tsx` | No dedicated monitored security inbox yet (OT-19) |
| CC3 Risk assessment | A.5.7 Threat intelligence, A.8.8 Technical vulnerability management | `hebridescyber-app/docs/DEFENSIVE-ASSESSMENT-PLAN.md`; `hebridescyber-app/docs/STRATEGY-REVIEW-2026-10.md`; `hebridescyber-app/docs/PRODUCT-REVIEW-2026-10.md` | No formal risk register or periodic risk-assessment cycle |
| CC4 Monitoring | A.5.35 Independent review, A.8.15 Logging | `.github/workflows/uptime.yml` (probes `/api/health`); `hebridescyber-app/src/pages/api/health.ts`; Sentry error monitoring (disclosed in `hebridescyber-app/src/app/privacy/page.tsx` section 4) | No independent review or internal audit |
| CC5 Control activities | A.5.15 Access control, A.8.32 Change management | `.github/workflows/deploy.yml` (lint, typecheck, unit and E2E tests, migration apply and drift check, post-deploy health check) | Merges to the default branch are not yet gated by enforced branch protection (OT-07); no formal change-management policy |
| CC6.1 Logical access | A.5.15, A.5.18, A.8.2, A.8.3, A.8.5 | Server-side session checks in `hebridescyber-app/src/proxy.ts`; TOTP MFA at `hebridescyber-app/src/app/account/security/page.tsx` and `hebridescyber-app/src/app/login/mfa-challenge/page.tsx`; scan-target ownership verification in `hebridescyber-app/src/lib/ownership.ts` with `ownership.test.ts` | MFA is available but not enforced for all accounts; no access-review procedure |
| CC6.1 Tenant isolation | A.8.3 Information access restriction | Row Level Security across the schema (`hebridescyber-app/sql/migrations/001_init.sql` onward, e.g. `047_fix_self_referencing_policies.sql`); policy tests in `hebridescyber-app/tests/db/rls.db.test.ts`; CI run in `.github/workflows/db-tests.yml` | Tests cover the policies written so far; no external review of them |
| CC6.1 Encryption | A.8.24 Use of cryptography | AES-256-GCM envelope encryption of stored third-party secrets in `hebridescyber-app/src/lib/credentialEncryption.ts` with `credentialEncryption.test.ts`; back-fill workflow `.github/workflows/encrypt-stored-secrets.yml`; HSTS and related headers in `hebridescyber-app/staticwebapp.config.json` | No documented key-management and rotation policy (OT-28 is a pending decision) |
| CC6.6 Boundary protection | A.8.20 Network security, A.8.23 Web filtering | Per-request nonce Content-Security-Policy in `hebridescyber-app/src/lib/csp.ts` and `hebridescyber-app/src/proxy.ts`, tested by `hebridescyber-app/src/lib/csp.test.ts`, `hebridescyber-app/src/proxy.test.ts` and `hebridescyber-app/tests/e2e/csp.spec.ts`; rate limiting in `hebridescyber-app/src/lib/rateLimit.ts` with `hebridescyber-app/src/__tests__/rateLimit.test.ts` | Rate limiting depends on a configured backing store (OT-06) |
| CC6.7 Data transmission | A.5.14, A.8.24 | Transport and browser security headers in `hebridescyber-app/staticwebapp.config.json` | Formal data-classification scheme not defined |
| CC6.8 Malicious software and supply chain | A.8.7 Malware protection, A.5.21 ICT supply chain | SHA-pinned GitHub Actions kept current by `.github/dependabot.yml`; npm audit gate `.github/workflows/dependency-audit.yml`; SBOM export `hebridescyber-app/src/pages/api/v1/scans/[id]/sbom.ts`; licence record `hebridescyber-app/docs/THIRD-PARTY-NOTICES.md` | No supplier-review procedure beyond the sub-processor list |
| CC7.1 Vulnerability detection | A.8.8, A.8.9 Configuration management, A.8.28 Secure coding | Static analysis rule tests `.github/workflows/sast-rules.yml` (rules in `hebridescyber-app/sast-rules/`); infrastructure scan `.github/workflows/terraform-security-scan.yml` over `hebridescyber-app/azure/terraform/main.tf`; ESLint and strict TypeScript in `deploy.yml` | No independent penetration test |
| CC7.2 Monitoring for anomalies | A.8.15 Logging, A.8.16 Monitoring | Audit log writer `hebridescyber-app/src/lib/audit.ts`; `audit_logs` table (`hebridescyber-app/sql/migrations/001_init.sql`); admin viewer `hebridescyber-app/src/pages/api/admin/audit.ts` with `hebridescyber-app/src/lib/auditFilters.ts` | No alerting rules or log-review routine documented |
| CC7.3 to CC7.5 Incident response and recovery | A.5.24 to A.5.28 Incident management | `hebridescyber-app/docs/RUNBOOK.md`; `SECURITY.md` commitments | No tested incident-response plan or post-incident review process |
| CC8.1 Change management | A.8.25 to A.8.33 Secure development | Migration runner with ledger and drift check (`hebridescyber-app/src/scripts/apply-migrations.ts`, used by `deploy.yml`); database tests on every migration change; PR-based history | Reviews are not enforced by the platform (OT-07) |
| CC9 Risk mitigation and vendors | A.5.19 to A.5.22 Supplier relationships | Sub-processor list in `hebridescyber-app/src/app/privacy/page.tsx` section 4 | No vendor due-diligence records or data-processing-agreement register in the repo |

## Availability

| Criterion | ISO 27001:2022 Annex A | Evidence in this repo | Gaps (programme level) |
|---|---|---|---|
| A1.1 Capacity and monitoring | A.8.6 Capacity management, A.8.16 | `.github/workflows/uptime.yml`; `hebridescyber-app/src/pages/api/health.ts`; post-deploy health check in `deploy.yml`; bounded job runtime in `hebridescyber-app/src/scripts/run-queued-scan-jobs.ts`; concurrency test `hebridescyber-app/tests/db/claimScanJob.db.test.ts` | No published availability target; public status page not yet set up (OT-27) |
| A1.2 Backup and recovery | A.8.13 Backup, A.8.14 Redundancy, A.5.30 ICT readiness | `hebridescyber-app/docs/BACKUP-RESTORE.md` (backup posture, restore steps, restore drill procedure); forward-only migrations with a ledger | Restore drill not yet performed (OT-12); point-in-time recovery depends on the hosting plan |
| A1.3 Recovery testing | A.5.29, A.5.30 | Restore drill procedure in `hebridescyber-app/docs/BACKUP-RESTORE.md` | Not yet exercised; no recorded results |

## Confidentiality

| Criterion | ISO 27001:2022 Annex A | Evidence in this repo | Gaps (programme level) |
|---|---|---|---|
| C1.1 Identify and protect confidential data | A.5.12 Classification, A.5.33 Records, A.8.11 Data masking | Encrypted secrets (`hebridescyber-app/src/lib/credentialEncryption.ts`); per-user RLS isolation (`hebridescyber-app/tests/db/rls.db.test.ts`); `hebridescyber-app/docs/DATA-MODEL.md` | No formal data-classification policy |
| C1.2 Disposal and retention | A.8.10 Information deletion, A.5.34 Privacy | Retention job `hebridescyber-app/src/scripts/cleanup-retention.ts` run by `.github/workflows/data-retention-cleanup.yml`; account erasure `hebridescyber-app/src/lib/accountErasure.ts` with `accountErasure.test.ts`, `hebridescyber-app/src/scripts/erase-user-data.ts` and `.github/workflows/deletion-requests.yml`; retention table in `hebridescyber-app/src/app/privacy/page.tsx` | Retention periods are not yet backed by a written policy |

## Not mapped yet

Physical security (A.7), HR security (A.6.1 to A.6.6), business-continuity
planning beyond backup, and the ISMS management clauses (4 to 10: scope,
leadership, internal audit, management review) have no repo evidence. They
are owner and organisational work, tracked as OT-38 to OT-41 in
`hebridescyber-app/docs/OWNER-TODO.md`.

## Keeping this honest

- Add a row only when the evidence path exists. Do not map a control to a
  planned feature.
- Do not turn the "Gaps" column into public promises, and do not publish
  detailed weakness descriptions in this repository.
- `/trust` must keep saying the platform is not SOC 2 attested and not
  ISO 27001 certified until an auditor says otherwise; the test in
  `hebridescyber-app/src/app/trust/page.test.tsx` guards the wording.
