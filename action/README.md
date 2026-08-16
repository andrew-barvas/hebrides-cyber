# Hebrides Cyber Security Scan

Runs a [Hebrides Cyber](https://hebridescyber.com) security scan against a
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

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | yes | — | Your Hebrides Cyber API key |
| `target-url` | yes | — | URL to scan (must already be verified) |
| `fail-on` | no | `high` | Fail on a new finding at or above this severity: `critical`, `high`, `medium`, `low`, or `none` to never fail |
| `api-base-url` | no | `https://hebridescyber.com` | Override for a self-hosted/staging instance |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score, 0–100 |
| `compared-to-previous-scan` | `"true"` if there was a previous scan of this target to diff against, `"false"` for a first scan |
| `new-finding-count` | Findings newly introduced since the previous scan |
| `report-url` | Link to the full report in the dashboard |

## First scan of a target

There's nothing to compare against, so the action never fails on a first
scan regardless of what it finds — a `::notice::` is logged instead. Run it
once manually (or let a scheduled run go first) before relying on it to gate
a PR.

## No dependencies

This action has no `node_modules` and nothing to `npm install` — it's a
single file using Node 20's built-in `fetch`. See `index.js`.
