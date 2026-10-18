# Third-party notices

Data and tools this product uses under their own licences, beyond the npm
dependencies listed in `package.json` (whose licences ship with each package).

## retire.js vulnerability repository

- **Used by:** `src/lib/scanners/retireJs.ts` (client-side JavaScript library
  detection and vulnerability matching).
- **Source:** https://github.com/RetireJS/retire.js, file
  `repository/jsrepository.json`, pinned to the commit in
  `RETIRE_DATA_COMMIT`. Fetched at scan time. The only copy in this
  repository is `bench/fixtures/retire-subset.json` (the jquery, jquery-ui
  and lodash entries, unchanged), which keeps the accuracy benchmark offline.
- **Licence:** Apache License 2.0. Copyright the retire.js authors (Erlend
  Oftedal and contributors). https://www.apache.org/licenses/LICENSE-2.0
- **Changes:** none to the data. We read its extractors and vulnerable
  version ranges; the matching code is our own.

## Scan-worker binaries

The scheduled scan workers install third-party tools (nuclei, subfinder,
httpx, gitleaks, trivy, opengrep, zizmor, ffuf, gospider, kiterunner, nmap,
sqlmap, commix, testssl.sh, OWASP ZAP). Each is pinned by version and checksum
in `.github/workflows/scheduled-scans.yml` and runs as a separate program under
its own licence; see `docs/SCANNER-INVENTORY.md`. No rules are copied from
semgrep-rules or opengrep-rules (see CLAUDE.md, SAST).
