---
name: deploy-containerapp
description: Stand up or push a new build to the Azure Container Apps deploy path (the alternate to the default Azure Static Web Apps deploy) — use when asked to deploy, redeploy, or provision the container path for hebridescyber-app.
---

# Deploy to Azure Container Apps

This is the **alternate**, opt-in deploy path — see CLAUDE.md's Deployment
section. It does not touch the live `deploy.yml`/Azure Static Web Apps
path in any way; both can exist at once.

## First-time provisioning (skip if infrastructure already exists)

1. Fill in the TODOs in `azure/terraform/main.tf`'s "Container Apps deploy
   path" block — globally-unique `azurerm_container_registry` name, a
   remote state backend (same TODO the file's top already flags for the
   Static Web App resources), and the `supabase_service_role_key` /
   `next_public_supabase_url` / `next_public_supabase_anon_key` Terraform
   variables (no defaults on purpose — never commit real values into the
   `.tf` file itself; pass via `-var` or a gitignored `.tfvars`).
2. `terraform plan` then `terraform apply` from `azure/terraform/` — **ask
   the user to confirm before running `apply`**, it provisions real,
   billed Azure resources (ACR + Container Apps Environment + Log
   Analytics workspace + Container App).
3. Set the GitHub Secrets `deploy-containerapp.yml`'s header comment
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
