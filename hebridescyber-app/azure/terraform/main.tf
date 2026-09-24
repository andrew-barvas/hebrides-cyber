# Terraform scaffold for Hebrides Cyber Azure infrastructure.
#
# This is a STARTING POINT, not a ready-to-apply config — it uses
# placeholder names and does not include state backend config. Fill in the
# TODOs, set up a remote state backend (e.g. an Azure Storage container)
# before running this against a real subscription, and review with
# `terraform plan` before `apply`.
#
# Only one deployed surface now: the Static Web App runs the whole
# application (marketing site, dashboard, and every /api/* route, including
# what used to be a separate Functions app for run-scan/verify-ownership/
# generate-report/generate-fix-pr/generate-newsletter — see
# src/pages/api/run-scan.ts's header comment for why that was consolidated).
# No Function App, Function App Service Plan, or Key Vault-for-Function-App
# access policy needed as a result — secrets live in GitHub Secrets (for
# build-time vars, see deploy.yml) or the Static Web App's own application
# settings, matching what's actually deployed today.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }

  # Provisioned via azure/cli-scripts/bootstrap-tfstate.sh on 2026-08-27.
  backend "azurerm" {
    resource_group_name  = "hebridescyber-tfstate-rg"
    storage_account_name = "hebridescybertfstate"
    container_name       = "tfstate"
    key                  = "hebridescyber.tfstate"
  }
}

provider "azurerm" {
  features {}
  # TODO: set subscription_id, or export ARM_SUBSCRIPTION_ID env var.
}

variable "resource_group_name" {
  default = "hebridescyber-rg"
}

variable "location" {
  default = "uksouth"
}

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
}

# Used for temp report generation and (optionally) uploaded PDF storage —
# see AZURE_STORAGE_CONNECTION_STRING in src/pages/api/generate-report.ts.
#
# Ran Checkov against this file directly (`checkov -d azure/terraform`) and
# triaged every finding rather than either ignoring all of them or applying
# every suggestion blindly — see .github/workflows/terraform-security-scan.yml
# for where this now runs in CI, and re-ran locally after each change below
# to confirm the actual pass/fail count, not just that the change compiled.
# Fixed, cheap, no behaviour change:
#   CKV_AZURE_44  - min_tls_version
#   CKV_AZURE_3   - https_traffic_only_enabled
#   CKV2_AZURE_38 - blob soft-delete (protects against an accidental report
#                  delete, real value at negligible cost for this data volume)
#   CKV_AZURE_206 - replication upgraded LRS -> GRS; at this data volume
#                  (a handful of PDF reports) the cost delta is negligible
#                  against real protection from a regional outage
# Mitigated but still flagged — the real fix is applied, Checkov's static
# analysis just doesn't credit it:
#   CKV2_AZURE_41 - added the sas_policy block below (7-day account-level
#                  expiration ceiling, well above anything generate-report.ts
#                  actually mints); still fails in isolation
#                  (`checkov --check CKV2_AZURE_41`) even with that block
#                  present — a checkov 3.3.13 policy-matching limitation
#                  against this attribute shape, not a missing control.
#                  Re-check next time checkov is upgraded before assuming
#                  this skip is still warranted.
# Explicitly accepted, not fixed — each would require an architectural
# change disproportionate to what this app actually stores (transient PDF
# reports, not regulated data), documented inline rather than left as an
# unexplained CI failure:
#   CKV_AZURE_59  - allow_nested_items_to_be_public is already set below
#                  (closes the per-container anonymous-access variant of
#                  this concern), but this specific check wants
#                  public_network_access_enabled = false, which needs a
#                  private endpoint/VNet-integrated access path — same
#                  dependency as CKV2_AZURE_2 below
#   CKV_AZURE_33  - Queue service logging: this account has no queue_properties
#                  block because the app doesn't use Azure Queue Storage at all
#   CKV2_AZURE_2  - public network access: disabling this needs a private
#                  endpoint/VNet-integrated access path from the Static Web
#                  App, infrastructure this free-tier scaffold doesn't have
#   CKV2_AZURE_40 - Shared Key auth: the app authenticates via
#                  AZURE_STORAGE_CONNECTION_STRING (shared-key by
#                  definition); moving to AAD-only auth means rewriting
#                  generate-report.ts's storage access, an application
#                  change, not a Terraform one
#   CKV2_AZURE_33 - private endpoint: same VNet dependency as CKV2_AZURE_2
#   CKV2_AZURE_1  - customer-managed key encryption: needs a Key Vault +
#                  access-policy wiring disproportionate to transient report
#                  PDFs; Microsoft-managed keys (the default) are accepted
resource "azurerm_storage_account" "main" {
  name                             = "hebridescyberstorage" # TODO: must be globally unique, lowercase, no dashes
  resource_group_name              = azurerm_resource_group.main.name
  location                         = azurerm_resource_group.main.location
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  min_tls_version                  = "TLS1_2"
  https_traffic_only_enabled       = true
  allow_nested_items_to_be_public  = false
  # checkov:skip=CKV_AZURE_59: public_network_access_enabled needs a private-endpoint/VNet path this scaffold doesn't have — see comment above
  # checkov:skip=CKV2_AZURE_2: no private-endpoint/VNet infrastructure on this free-tier scaffold — see comment above
  # checkov:skip=CKV2_AZURE_40: app auth is AZURE_STORAGE_CONNECTION_STRING (shared-key) — see comment above
  # checkov:skip=CKV2_AZURE_33: same VNet dependency as CKV2_AZURE_2
  # checkov:skip=CKV2_AZURE_1: Microsoft-managed keys accepted for transient report PDFs — see comment above
  # checkov:skip=CKV_AZURE_33: this account has no queue_properties block — the app doesn't use Azure Queue Storage
  # checkov:skip=CKV2_AZURE_41: sas_policy block below is the real mitigation — checkov 3.3.13 doesn't credit it, see comment above

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  sas_policy {
    expiration_period = "07.00:00:00"
    expiration_action = "Log"
  }
}

# Static Web App for the Next.js app — marketing site, dashboard, and every
# API route (Oryx auto-deploys App Router pages + Pages API routes as
# managed Functions behind the CDN; see deploy.yml).
# TODO: azurerm_static_site does not support all Static Web Apps features
# (e.g. GitHub integration is usually set up via `az staticwebapp create`
# or the Portal instead). See azure/cli-scripts/provision.sh for that path.
resource "azurerm_static_site" "main" {
  name                 = "hebridescyber-app"
  resource_group_name  = azurerm_resource_group.main.name
  location             = var.location
  sku_tier             = "Free" # TODO: upgrade to Standard for custom domains + more bandwidth
}

output "static_web_app_url" {
  value = azurerm_static_site.main.default_host_name
}

# --- Container Apps deploy path (alternative to the Static Web App above) ---
#
# Parallel scaffold, not a replacement — see Dockerfile and
# .github/workflows/deploy-containerapp.yml (manual workflow_dispatch, does
# not touch deploy.yml's push-to-master SWA path). Exists to get off Azure
# SWA's Free-tier Functions execution ceiling that already forced the
# scan-queue workaround (see CLAUDE.md's "Scan flow" section) without
# adopting a second cloud. Same TODO-scaffold caveats as the rest of this
# file apply: fill in secret values, review with `terraform plan` before
# `apply`, and this is not wired to auto-apply from any workflow.
#
# IMPORTANT: the azurerm_resource_group/azurerm_storage_account/
# azurerm_static_site resources above are a NEVER-APPLIED scaffold — the
# real production infrastructure was provisioned by hand via
# azure/cli-scripts/provision.sh into resource group "rg-hebrides-cyber"
# (eastus2), not "hebridescyber-rg" (uksouth) as this file assumes; the real
# storage account is "hebridescyberstor", not "hebridescyberstorage". Do not
# `terraform apply` the whole file — it would stand up a second, duplicate
# resource group/storage/SWA next to the real ones. The Container Apps
# resources below are scoped to sit inside the REAL resource group via the
# data source immediately below, specifically to avoid that trap. See
# docs/ENHANCEMENTS.md for reconciling the rest of this file (importing the
# real resources into state, or deleting the unapplied scaffold) — out of
# scope for the container-deploy work itself.

data "azurerm_resource_group" "existing" {
  name = "rg-hebrides-cyber"
}

resource "azurerm_container_registry" "main" {
  name                = "hebridescyberacr" # confirmed globally available via `az acr check-name` on 2026-08-27
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
  sku                 = "Basic"
  admin_enabled       = true
  # checkov:skip=CKV_AZURE_137: admin credentials are the push credential
  # for deploy-containerapp.yml, stored in the ACR_PASSWORD GitHub Secret
  # the same way AZURE_STATIC_WEB_APPS_API_TOKEN already is for the SWA
  # path above — a per-repo service principal + OIDC federated credential
  # would remove this, but is disproportionate infra for one deploy
  # pipeline at this scale. Revisit if a second consumer of this registry
  # ever appears.
  # checkov:skip=CKV_AZURE_163: retention policy requires Premium SKU — Basic is appropriate for this single-app deploy pipeline
  # checkov:skip=CKV_AZURE_233: zone redundancy requires Premium SKU — overkill for a single-region hobby-scale registry
}

resource "azurerm_log_analytics_workspace" "container_apps" {
  name                = "hebridescyber-caenv-logs"
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_container_app_environment" "main" {
  name                       = "hebridescyber-caenv"
  resource_group_name        = data.azurerm_resource_group.existing.name
  location                   = data.azurerm_resource_group.existing.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.container_apps.id
}

# Secret values for the container app. Left as sensitive variables with no
# default (see variables.tf-style TODO pattern above) rather than hardcoded
# — same secrets already listed in README.md's "Server-only secrets" table
# and GitHub Secrets table; add the rest there the same way as this app
# needs them (Stripe, GitHub App, Azure OpenAI, Upstash, etc.).
variable "supabase_service_role_key" {
  sensitive = true
  default   = null
}

variable "next_public_supabase_url" {
  default = null
}

variable "next_public_supabase_anon_key" {
  sensitive = true
  default   = null
}

resource "azurerm_container_app" "main" {
  name                         = "hebridescyber-app"
  resource_group_name          = data.azurerm_resource_group.existing.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "acr-password"
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.main.admin_password
  }

  secret {
    name  = "supabase-service-role-key"
    value = var.supabase_service_role_key
  }

  secret {
    name  = "next-public-supabase-anon-key"
    value = var.next_public_supabase_anon_key
  }

  template {
    # min_replicas = 0 scales to zero when idle — free-tier friendly, but
    # means a cold start on the next request. Bump to 1 if dashboard
    # latency after idle periods becomes a real complaint.
    min_replicas = 0
    max_replicas = 2

    container {
      name = "hebridescyber-app"
      # TODO: :latest is a placeholder — deploy-containerapp.yml pins this
      # to the actual pushed tag (git SHA) via `az containerapp update
      # --image` rather than relying on Terraform to track image versions.
      image  = "${azurerm_container_registry.main.login_server}/hebridescyber-app:latest"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "NEXT_PUBLIC_SUPABASE_URL"
        value = var.next_public_supabase_url
      }
      env {
        name        = "NEXT_PUBLIC_SUPABASE_ANON_KEY"
        secret_name = "next-public-supabase-anon-key"
      }
      env {
        name        = "SUPABASE_SERVICE_ROLE_KEY"
        secret_name = "supabase-service-role-key"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  lifecycle {
    # deploy-containerapp.yml updates the image tag directly via `az
    # containerapp update` between applies — don't let a later `terraform
    # apply` snap it back to the :latest placeholder above.
    ignore_changes = [template[0].container[0].image]
  }
}

output "container_app_url" {
  value = azurerm_container_app.main.latest_revision_fqdn
}
