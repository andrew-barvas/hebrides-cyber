Real kiterunner v1.0.2 output, captured 2026-10-06 by running

    kr scan http://127.0.0.1:8099/ -w routes.kite -o json -q --fail-status-codes 404,429 \
       --max-connection-per-host 3 --timeout 5s --wildcard-detection=false

against the local test app (tests/fixtures/test-app), whose `/api/health` returns
200 and `/api/admin` returns 401, with a compiled .kite wordlist of
api/health, api/admin, api/users, api/nope, admin/login. `-o json -q` prints one
JSON object per route to stdout; `--fail-status-codes 404,429` drops the misses, so
only discovered endpoints remain. The two-phase scan can repeat a line (health
appears twice), which the wrapper dedupes by method+path.
