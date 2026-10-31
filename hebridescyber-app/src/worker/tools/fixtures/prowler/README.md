# Prowler fixtures

`iam-ocsf-5.47.0.json` is **hand-built, not captured from a real run**. It
follows the record shape Prowler 5.47.0's `json-ocsf` writer produces
(`prowler/lib/outputs/ocsf/ocsf.py`: `status_code`, `status_detail`,
`severity`, `risk_details`, `remediation`, `resources[]`,
`metadata.event_code`, `cloud.account.uid`), and the check ids are real
`iam_*` checks shipped in 5.47.0. The account id is a placeholder. Nothing in
it came from a real AWS account.

Replace it with a capture from a real run (`prowler aws --role <arn>
--external-id <id> -s iam -M json-ocsf --ignore-exit-code-3`, then redact
account ids) as soon as one exists; see OT-42 in `docs/OWNER-TODO.md`.
