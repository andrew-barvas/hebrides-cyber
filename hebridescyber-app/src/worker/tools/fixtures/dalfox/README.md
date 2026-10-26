# Dalfox fixtures

Real `dalfox scan -f json` output, captured 2026-10-23 against Dalfox
v3.2.4 (pinned binary, SHA-256 verified — see `.github/workflows/tool-integration.yml`
and `scheduled-scans.yml`) run against this repo's own local test-app fixture
(`tests/fixtures/test-app/app.py`), never a third party's site.

- `reflected.json` — `dalfox scan 'http://127.0.0.1:8099/search?q=hello'`. The
  `q` parameter is reflected unescaped; Dalfox confirms a DOM-verified XSS
  (`type: "V"`, confidence `"high"`).
- `clean.json` — `dalfox scan 'http://127.0.0.1:8099/api/health'`. No
  injectable parameter; `target_summary[].status` is `"clean"`.
- `unreachable.json` — `dalfox scan 'http://127.0.0.1:9999/nope?x=1'` against a
  closed port. `target_summary[].status` is `"skipped"` with
  `error_code: "CONNECTION_FAILED"` — this must parse as an error, never a
  clean result (CLAUDE.md rule 7).

`dalfoxOutput.ts` is written directly against these three files, not a
schema read from Dalfox's docs.
