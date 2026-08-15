# Terraform scaffold for Hebrides Cyber Azure infrastructure.
#
# This is a STARTING POINT, not a ready-to-apply config — it uses
# placeholder names and does not include state backend config. Fill in the
# TODOs, set up a remote state backend (e.g. an Azure Storage container)
# before running this against a real subscription, and review with
# `terraform plan` before `apply`.

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

# Storage account backing the Function App + used for temp report files.
resource "azurerm_storage_account" "main" {
  name                     = "hebridescyberstorage" # TODO: must be globally unique, lowercase, no dashes
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Consumption-plan Function App for run-scan / generate-report.
resource "azurerm_service_plan" "functions" {
  name                = "hebridescyber-functions-plan"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption plan
}

resource "azurerm_linux_function_app" "main" {
  name                       = "hebridescyber-functions" # TODO: must be globally unique
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  storage_account_name       = azurerm_storage_account.main.name
  storage_account_access_key = azurerm_storage_account.main.primary_access_key
  service_plan_id            = azurerm_service_plan.functions.id

  site_config {
    application_stack {
      node_version = "20"
    }
  }

  # TODO: set app_settings for SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
  # AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY, etc. via Key Vault references
  # rather than plain values here — never commit real secrets to this file.
  app_settings = {
    "TODO_SET_VIA_KEY_VAULT_REFERENCE" = "see docs/security.md"
  }

  identity {
    type = "SystemAssigned" # used to grant Key Vault access below
  }
}

# Key Vault for production secrets.
resource "azurerm_key_vault" "main" {
  name                = "hebridescyber-kv" # TODO: must be globally unique
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault_access_policy" "function_app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_function_app.main.identity[0].principal_id

  secret_permissions = ["Get", "List"]
}

# Static Web App for the Next.js marketing site + dashboard.
# TODO: azurerm_static_site does not support all Static Web Apps features
# (e.g. GitHub integration is usually set up via `az staticwebapp create`
# or the Portal instead). See azure/cli-scripts/provision.sh for that path.
resource "azurerm_static_site" "main" {
  name                = "hebridescyber-app"
  resource_group_name = azurerm_resource_group.main.name
  location             = var.location
  sku_tier            = "Free" # TODO: upgrade to Standard for custom domains + more bandwidth
}

output "function_app_url" {
  value = "https://${azurerm_linux_function_app.main.default_hostname}"
}

output "static_web_app_url" {
  value = azurerm_static_site.main.default_host_name
}
