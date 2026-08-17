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

  # TODO: configure a remote backend, e.g.:
  # backend "azurerm" {
  #   resource_group_name  = "hebridescyber-tfstate-rg"
  #   storage_account_name = "hebridescybertfstate"
  #   container_name       = "tfstate"
  #   key                  = "hebridescyber.tfstate"
  # }
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
resource "azurerm_storage_account" "main" {
  name                     = "hebridescyberstorage" # TODO: must be globally unique, lowercase, no dashes
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
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
