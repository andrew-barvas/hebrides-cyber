# ffuf fixture

`scan-2.1.0.json` is **real** ffuf v2.1.0 `-of json` output, captured by running
the pinned binary against `tests/fixtures/test-app/app.py` with a tiny wordlist
(`api/health`, `api/admin`, `item`, `search`, `nope-not-here`):

```
ffuf -w wl.txt -u http://127.0.0.1:PORT/FUZZ -of json -o scan-2.1.0.json -s -ac
```

ffuf's default status matcher (`200-299,301,302,307,401,403,405,500`) kept
`/api/health` (200), `/item` (200), `/api/admin` (401) and `/search` (200), and
dropped `/nope-not-here` (404). The binary is pinned by version + SHA-256 in
`.github/workflows/scheduled-scans.yml` and `tool-integration.yml`
(v2.1.0, `fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5`,
the publisher's own `ffuf_2.1.0_checksums.txt` line for the linux_amd64 tarball).

`src/worker/tools/contentDiscovery.test.ts` parses this file; regenerate it the
same way if the ffuf pin changes.
