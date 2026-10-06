# Hebrides Cyber Security Scan

Runs a [Hebrides Cyber](https://www.hebridescyber.co.uk) security scan against a
verified domain and, by default, fails the step if a **new** critical or high
finding was introduced since the previous scan of that target — not on the
existing backlog. Gating on total findings would red-line every pipeline on
its first run; this only cares about what your change actually introduced.

## Usage

```yaml
name: Security
on:
  pull_request:
  schedule:
    - cron: "0 3 * * 1"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: andrew-barvas/hebrides-cyber/action@master
        id: scan
        with:
          api-key: ${{ secrets.HEBRIDES_CYBER_API_KEY }}
          target-url: https://staging.example.com
          fail-on: high

      - name: Comment score on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `Security score: **${{ steps.scan.outputs.score }}/100** — [full report](${{ steps.scan.outputs.report-url }})`
            })
```

Create an API key in **Account → API Keys**. The target URL must already be a
domain verified on your account — there's no interactive verification step
available to a CI runner.

## Pull-request dependency check (Pro / Agency)

`mode: dependencies` catches a vulnerable package in the pull request that
adds it. It reads each changed lockfile on the PR's base and head, asks
Hebrides Cyber which of the **newly added** packages have known
vulnerabilities (OSV.dev), fails the check at `fail-on` severity, and posts —
then keeps updating — one comment on the PR. Existing vulnerabilities in the
base aren't reported. No GitHub App to install; the comment uses your
workflow's own token.

```yaml
name: Dependencies
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # git must see the PR's base commit
      - uses: andrew-barvas/hebrides-cyber/action@master
        with:
          mode: dependencies
          api-key: ${{ secrets.HEBRIDES_CYBER_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: high
```

Pull requests from forks get a read-only token, so the comment can't be
posted there; the result is still in the job summary and the check still
gates. If a lockfile can't be read or the lookup can't cover everything, the
check **fails** rather than passing as clean (unless `fail-on: none`).
Supported lockfiles are listed under `POST /api/v1/dependency-diff` in
`docs/API.md`. `target-url` isn't used in this mode.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | yes | — | Your Hebrides Cyber API key |
| `mode` | no | `scan` | `scan` or `dependencies` (see above) |
| `target-url` | scan mode | — | URL to scan (must already be verified) |
| `github-token` | no | — | `dependencies` mode: token for the PR comment (`secrets.GITHUB_TOKEN`) |
| `fail-on` | no | `high` | Fail on a new finding at or above this severity: `critical`, `high`, `medium`, `low`, or `none` to never fail |
| `api-base-url` | no | `https://www.hebridescyber.co.uk` | Override for a self-hosted/staging instance |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score, 0–100 |
| `compared-to-previous-scan` | `"true"` if there was a previous scan of this target to diff against, `"false"` for a first scan |
| `new-finding-count` | Findings newly introduced since the previous scan |
| `report-url` | Link to the full report in the dashboard |

## Triaged findings don't fail the build

A new finding you've triaged in the dashboard (or through
`PUT /api/findings/triage`) — marked as an accepted risk / authorised, a
false positive, or snoozed — never fails the step while that decision is in
effect. It's logged as a `::notice::` instead of a `::warning::`. Once a
snooze (or any triage with an expiry) runs out, the finding counts again.
The action reads this from each finding's `triage` field in
`GET /api/v1/scans/{id}`, and re-checks `expires_at` itself.

## First scan of a target

There's nothing to compare against, so the action never fails on a first
scan regardless of what it finds — a `::notice::` is logged instead. Run it
once manually (or let a scheduled run go first) before relying on it to gate
a PR.

## No dependencies

This action has no `node_modules` and nothing to `npm install` — it's a
single file using Node 20's built-in `fetch`. See `index.js`.
