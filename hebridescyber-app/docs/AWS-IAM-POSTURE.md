# AWS IAM posture check (Prowler)

Read-only check of a customer's AWS IAM: policies that allow privilege
escalation, administrator-equivalent grants, root and user MFA. Runs Prowler
5.47.0 (Apache-2.0), `iam` service only, in the scheduled-scan worker
(`src/worker/tools/prowlerIam.ts`). Agency plan, same as the other cloud
posture checks. Findings are `prowler.<check>:<account>:<resource>`.

## Customer setup

1. Dashboard, Account, Cloud Posture Scanning, "AWS IAM & privilege-escalation
   check": enter a label and press **Generate external ID**.
2. In the AWS account, create an IAM role with this trust policy (replace
   `PLATFORM_ACCOUNT_ID` with the account id the dashboard shows and
   `EXTERNAL_ID` with the generated `hc-…` value):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "AWS": "arn:aws:iam::PLATFORM_ACCOUNT_ID:root" },
       "Action": "sts:AssumeRole",
       "Condition": { "StringEquals": { "sts:ExternalId": "EXTERNAL_ID" } }
     }]
   }
   ```
3. Attach the AWS managed policies `SecurityAudit` and `ViewOnlyAccess`. Nothing
   else; the role needs no write permission.
4. Paste the role ARN (`arn:aws:iam::<12 digits>:role/<name>`) into the
   dashboard and save. The next scheduled full scan runs the check.

To stop access, delete the role or the connection in the dashboard.

## What a result means

- `completed`: Prowler assessed the account; only failed checks are findings.
- `error`: it could not assess (role can't be assumed, no report, empty report,
  report for a different account, Prowler or our AWS identity missing). Nothing
  is marked fixed, and no "clean" is reported.
- `not_configured`: no role connected, or one is still waiting for its ARN.
- `not_applicable`: below the Agency plan.

## Operating it

Needs, on the worker: `prowler` on PATH (installed pinned by SHA-256 in
`.github/workflows/scheduled-scans.yml`), and `PROWLER_AWS_ACCESS_KEY_ID` /
`PROWLER_AWS_SECRET_ACCESS_KEY` for our scan identity (only `sts:AssumeRole`).
The app needs `PROWLER_PLATFORM_AWS_ACCOUNT_ID` to show customers the trust
principal. Owner steps: OT-46, OT-47 in `OWNER-TODO.md`.

To upgrade Prowler: bump `PROWLER_VERSION` and `PROWLER_SHA256` in the workflow,
re-capture the fixture in `src/worker/tools/fixtures/prowler/`, run the tests.
