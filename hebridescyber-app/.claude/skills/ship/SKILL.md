---
name: ship
description: Land a finished change — branch, commit with the right attribution, open a draft PR, wait for CI, squash-merge, then watch the Deploy run (and the migration step if the PR carried one). Use when a change has passed the gate and is ready to go to master.
---

# Ship a change

The sequence is **draft PR → wait for CI → squash-merge → watch `Deploy`**. Don't
merge on a local pass alone: CI type-checks the PR as merged into master, which
a local run on a stale branch doesn't.

Run `/verify` first. If it hasn't passed, this skill is premature.

## 1. Branch and commit

Never commit directly to `master`.

```bash
git checkout -b feat/short-description
```

Commit messages follow the repo's existing convention — `type(scope): summary`,
matching what `git log --oneline -20` shows (`feat(scanner)`, `fix(ci)`,
`test(bench)`, …). End the message with the `Co-Authored-By:` line for the
model that made the change; this session's own attribution guidance gives the
exact text. Don't copy a version number out of an older commit — it tracks
whichever model wrote the change.

## 2. Draft PR

```bash
git push -u origin HEAD
```

Then open it as a **draft** with `gh pr create --draft`. The body ends with the
Claude Code attribution line from this session's attribution guidance.

The body should say what changed and why, name any migration the PR carries,
and note anything the owner has to do that code can't (a secret to set, a
contract term, a tool needing an input). Those belong in
`docs/NEXT-STEPS.md`'s "Owner actions pending" too if they're not immediate.

**Give any scratch file a unique name.** Two concurrent builds have overwritten
each other's PR body.

## 3. Wait for CI

```bash
gh pr checks --watch
```

Don't poll in a loop beyond this, and don't schedule your own checks. Once the
PR is open, bind it so the app tracks its CI and can offer Auto-fix.

`deploy.yml` runs on `pull_request` too, so the PR gets the same four gates
plus the schema verification. A fork PR skips the migration step (no
`DATABASE_URL`) and falls back to verify-only.

If CI fails on something that passed locally, the usual cause is a stale
branch — rebase onto latest master and push again, rather than assuming a
flake.

## 4. Mark ready and squash-merge

Mark ready for review, then squash-merge. Squash keeps one commit per change on
master, which is what the migration ledger and the `Deploy` concurrency group
assume.

## 5. Watch the deploy

```bash
gh run list --workflow=deploy.yml --limit 3
```

Push to master triggers `deploy.yml`, which applies pending migrations and
verifies the schema **before** deploying. Two things to actually check:

- **If the PR carried a migration**, confirm the `Apply migrations + verify
  schema` job applied it and the drift check is clean. A failed migration
  blocks the deploy — the app is still on the old code, which is the safe
  outcome, but the fix is a new migration, never an edit to the applied one
  (the runner refuses an edited applied file by checksum).
- **If the change touched headers or hosting**, the live site is served by the
  managed Next.js server, so `next.config.mjs`'s `headers()` is what applies —
  not `staticwebapp.config.json`. Curl production to confirm rather than
  trusting the config file.

A change isn't shipped until that run is green. Report what the run actually
says, including a failure.

## One at a time

Local and cloud sessions share one usage allowance, and parallel builds have
exhausted it three times. Ship one change through this flow before starting the
next.
