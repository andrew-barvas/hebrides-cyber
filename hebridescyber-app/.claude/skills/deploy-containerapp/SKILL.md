---
name: deploy-containerapp
description: Stand up or push a new build to the Azure Container Apps deploy path (the alternate to the default Azure Static Web Apps deploy) — use when asked to deploy, redeploy, or provision the container path for hebridescyber-app.
---

# Deploy to Azure Container Apps

This is the **alternate**, opt-in deploy path — see CLAUDE.md's Deployment
section. It does not touch the live `deploy.yml`/Azure Static Web Apps
path in any way; both can exist at once.

## First-time provisioning (skip if infrastructure already exists)

**Never run a bare `terraform apply` against this file** — see
`docs/ENHANCEMENTS.md` E-26. The file's `azurerm_resource_group.main`/
`azurerm_storage_account.main`/`azurerm_static_site.main` blocks describe
resources that don't match what's actually deployed (real resource group is
`rg-hebrides-cyber` in `eastus2`, not `hebridescyber-rg` in `uksouth`) and
have never been applied or imported — a bare `apply` creates 3 unwanted
duplicate resources alongside the real, currently-serving ones. Confirmed
via a real `terraform plan` on 2026-08-27: 7 resources planned, only 4 of
which (the container ones) are wanted. Always scope with `-target`:

```
terraform plan \
  -target=data.azurerm_resource_group.existing \
  -target=azurerm_container_registry.main \
  -target=azurerm_log_analytics_workspace.container_apps \
  -target=azurerm_container_app_environment.main \
  -target=azurerm_container_app.main
```

Review the plan output, then re-run the same command with `apply` in place
of `plan` **only after the user explicitly confirms** — it provisions real,
billed Azure resources (ACR + Container Apps Environment + Log Analytics
workspace + Container App) inside the real `rg-hebrides-cyber` group.

1. Bootstrap remote state first (one-time, real but cheap Azure resources —
   confirm with the user before running):
   `azure/cli-scripts/bootstrap-tfstate.sh`, then uncomment the
   `backend "azurerm" {}` block at the top of `main.tf` with the values the
   script prints, and run `terraform init` to migrate.
2. Supply the `supabase_service_role_key` / `next_public_supabase_url` /
   `next_public_supabase_anon_key` Terraform variables via `-var` or a
   gitignored `.tfvars` — no defaults on purpose, never commit real values
   into the `.tf` file itself. `ARM_SUBSCRIPTION_ID` env var (or
   `provider "azurerm" { subscription_id = ... }`) must also be set — this
   subscription's ID is `0efed950-a227-41af-b0a6-f76e9d4e41c6` ("Microsoft
   Azure Sponsorship"), confirmed via `az account show` on 2026-08-27.
   `azurerm_container_registry.main`'s name (`hebridescyberacr`) was
   confirmed globally available the same day.
3. Run the `-target`-scoped `plan`/`apply` above from `azure/terraform/`.
4. Set the GitHub Secrets `deploy-containerapp.yml`'s header comment
   lists: `AZURE_CREDENTIALS`, `ACR_LOGIN_SERVER`, `ACR_USERNAME`,
   `ACR_PASSWORD` (from the Terraform outputs / `az acr credential show`),
   `AZURE_RESOURCE_GROUP`, `AZURE_CONTAINER_APP_NAME`, plus the same
   `NEXT_PUBLIC_*` secrets `deploy.yml` already uses.

## Pushing a new build (infrastructure already exists)

Trigger `.github/workflows/deploy-containerapp.yml` via `workflow_dispatch`
— it is never triggered by a push, by design. From the GitHub UI (Actions
tab) or `gh workflow run deploy-containerapp.yml`.

To validate the image builds before triggering the real workflow:

```bash
cd hebridescyber-app
docker build -t hebridescyber-app:test \
  --build-arg NEXT_PUBLIC_SUPABASE_URL=<real-or-placeholder-url> \
  --build-arg NEXT_PUBLIC_SUPABASE_ANON_KEY=<real-or-placeholder-key> \
  .
```

Requires Docker Desktop's daemon running locally (`docker --version` alone
doesn't confirm this — a build attempt with the daemon down fails with a
pipe-connect error, not a build error).

## Known gotchas

- `playwright`/`playwright-core` end up in the standalone build's
  `node_modules` (~43MB) even though only the queue-worker script (which
  never runs inside this container) needs them — not a blocker, just
  larger than minimal. Worth revisiting if image size becomes a real cost.
- `min_replicas = 0` in the Terraform (`azurerm_container_app.main.template`)
  means scale-to-zero — free-tier friendly, but the first request after an
  idle period pays a cold start. Bump to 1 if that becomes a real complaint.
- The Terraform `image` attribute is a `:latest` placeholder deliberately
  ignored via `lifecycle.ignore_changes` — the real deploy path is
  `az containerapp update --image <tag>` inside the workflow, not
  `terraform apply` tracking image versions.
