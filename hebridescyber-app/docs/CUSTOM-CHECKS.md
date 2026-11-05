# Custom checks (Agency and Tier A)

Write your own nuclei template and have it run against your site on every scan
that runs nuclei (the extended scans). Findings appear as
`[Custom check] <name>` with check id `custom-nuclei:<template id>`, and take
part in New/Fixed, triage, SARIF and CI gating like any other finding.

## API

Session-only (not API keys). All four need an Agency or Tier A plan.

| Method | Body | Result |
|--------|------|--------|
| `GET /api/account/custom-checks` | | `{ checks, limit }` |
| `POST /api/account/custom-checks` | `{ yaml }` | `201 { check }`, or `422 { problems: [...] }` listing why it was refused |
| `PATCH /api/account/custom-checks` | `{ id, enabled }` | `{ check }` |
| `DELETE /api/account/custom-checks` | `{ id }` | `{ ok: true }` |

Up to 20 checks per account, 16 KB each.

## What a template can do

Plain HTTP requests to the site being scanned, matched on the response:

```yaml
id: internal-admin-exposed
info:
  name: Internal admin console reachable
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/internal-admin"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Admin console"]
```

Allowed: `id`, `info` (needs `name` and `severity`), `http` with `method`, `path`
(must start with `{{BaseURL}}` or `{{RootURL}}`), `raw` (request line must be a
path; any `Host` must be `{{Hostname}}`), `headers`, `body`, `matchers`
(`word`, `regex`, `status`, `size`, `binary`; at least one), `extractors`
(`regex`, `kval`, `json`, `xpath`), `payloads` (inline lists only), `attack`,
`redirects` / `max-redirects` (0 to 3), `stop-at-first-match`, `req-condition`.
Helpers: `rand_int`, `rand_text_alpha`, `rand_text_alphanumeric`,
`rand_text_numeric`, `randstr`, `to_lower`, `to_upper`, `base64`,
`base64_decode`, `url_encode`, `url_decode`, `md5`, `sha1`, `sha256`, `concat`,
`trim`, `len`. At most 5 `http` blocks and 60 requests per template per scan.

## What it cannot do (and why)

The template runs on our scan workers, so the validator is an allowlist.
Refused: every other protocol (`code`, `headless`, `javascript`, `network`,
`tcp`, `dns`, `file`, `ssl`, `whois`, `websocket`, `workflow`, `flow`),
anything addressed to another host (absolute URLs, a different `Host`),
out-of-band `interactsh` callbacks, DSL matchers/extractors, payload files,
file/exec/DNS helpers, and request smuggling, racing, pipelining and fuzzing
options.

The worker repeats the main limits as nuclei flags (no out-of-band server, no
code or headless, no local file access, 5 requests per second, 3 concurrent)
and re-validates every template before each scan, so a stored template that no
longer passes is skipped, not run.

A check runs against the scan's target only. It does not make a site
yours: the target must already be verified like any other scan.
