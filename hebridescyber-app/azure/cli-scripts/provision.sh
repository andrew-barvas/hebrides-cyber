#!/usr/bin/env bash
# Provision Hebrides Cyber Azure resources via the Azure CLI.
# This is an ALTERNATIVE to the Terraform config for a quick manual setup,
# or for the parts Terraform's azurerm_static_site doesn't fully cover
# (GitHub-linked Static Web Apps deployment tokens).
#
# Usage: ./provision.sh
# Requires: az CLI installed and `az login` already run.

set -euo pipefail

# ---- Fill these in before running -------------------------------------
RESOURCE_GROUP="hebridescyber-rg"
LOCATION="uksouth"
STATIC_WEB_APP_NAME="hebridescyber-app"
FUNCTION_APP_NAME="hebridescyber-functions"
STORAGE_ACCOUNT_NAME="hebridescyberstorage" # TODO: must be globally unique
KEY_VAULT_NAME="hebridescyber-kv"           # TODO: must be globally unique
GITHUB_REPO_URL="https://github.com/TODO/hebridescyber-app"
GITHUB_BRANCH="main"
# -------------------------------------------------------------------------

echo "== Verifying Azure CLI login =="
az account show --output table

echo "== Creating resource group: $RESOURCE_GROUP =="
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

echo "== Creating storage account: $STORAGE_ACCOUNT_NAME =="
az storage account create \
  --name "$STORAGE_ACCOUNT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS

echo "== Creating Static Web App (linked to GitHub): $STATIC_WEB_APP_NAME =="
# NOTE: this will prompt for GitHub auth the first time and creates a
# GitHub Actions workflow in your repo automatically. If .github/workflows/deploy.yml
# already exists (it does in this repo), review for conflicts afterwards.
az staticwebapp create \
  --name "$STATIC_WEB_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --source "$GITHUB_REPO_URL" \
  --branch "$GITHUB_BRANCH" \
  --app-location "/" \
  --output-location ".next" \
  --login-with-github

echo "== Creating Function App: $FUNCTION_APP_NAME (Consumption plan) =="
az functionapp create \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --storage-account "$STORAGE_ACCOUNT_NAME" \
  --consumption-plan-location "$LOCATION" \
  --runtime node \
  --runtime-version 20 \
  --functions-version 4

echo "== Creating Key Vault: $KEY_VAULT_NAME =="
az keyvault create \
  --name "$KEY_VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION"

echo "== Granting Function App managed identity access to Key Vault =="
az functionapp identity assign \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP"

PRINCIPAL_ID=$(az functionapp identity show \
  --name "$FUNCTION_APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query principalId -o tsv)

az keyvault set-policy \
  --name "$KEY_VAULT_NAME" \
  --object-id "$PRINCIPAL_ID" \
  --secret-permissions get list

echo ""
echo "== Done. Manual steps still required: =="
echo "1. Add secret values to Key Vault ($KEY_VAULT_NAME) — do NOT put them in this script:"
echo "   az keyvault secret set --vault-name $KEY_VAULT_NAME --name SUPABASE-SERVICE-ROLE-KEY --value <value>"
echo "2. Set Function App settings to reference Key Vault secrets (see docs/security.md)."
echo "3. Set GitHub Secrets for the deploy.yml workflow (see README.md)."
echo "4. Configure a custom domain + SSL on the Static Web App via the Portal or:"
echo "   az staticwebapp hostname set --name $STATIC_WEB_APP_NAME --hostname hebridescyber.com"
echo "5. Apply for Azure OpenAI access if not already approved for this subscription."
