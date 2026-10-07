# httpx fixture

`probe-1.6.10.jsonl` is **real** httpx v1.6.10 `-json` output, captured by running
the pinned binary against `tests/fixtures/test-app/app.py` (the deliberately
vulnerable local app), probing `/`, `/api/health` (200) and `/api/admin` (401):

```
httpx -u "http://127.0.0.1:PORT,.../api/health,.../api/admin" \
      -json -silent -no-color -timeout 10 -status-code -title -tech-detect -tls-grab
```

The binary is pinned by version **and SHA-256** in `.github/workflows/scheduled-scans.yml`
and `tool-integration.yml` (v1.6.10, `e7eb8473530c2d0eb4eb132c7253c0138745d622970f36413c1f349ddd60edb7`,
the publisher's own `httpx_1.6.10_checksums.txt` line for `httpx_1.6.10_linux_amd64.zip`).

`src/lib/scanners/hostProbe.test.ts` parses this file, so regenerate it (same command)
if the httpx pin changes and the output shape moves.
