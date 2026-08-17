#!/usr/bin/env bash
# Provision Hebrides Cyber Azure resources via the Azure CLI.
# This is an ALTERNATIVE to the Terraform config for a quick manual setup,
# or for the parts Terraform's azurerm_static_site doesn't fully cover
# (GitHub-linked Static Web Apps deployment tokens).
#
# Usage: ./provision.sh
# Requires: az CLI installed and `az login` already run.
#
# Only provisions a Static Web App + storage account now — no Function App.
# The whole application (marketing site, dashboard, every /api/* route,
# including what used to be a separate Functions app for run-scan/
# verify-ownership/generate-report/generate-fix-pr/generate-newsletter) runs
# on the Static Web App alone; Oryx auto-deploys the Next.js API routes as
# managed Functions behind the CDN. See
# src/pages/api/run-scan.ts's header comment for why that consolidation
# happened, and docs/PLATFORM-ROADMAP.md for the "17 Aug" note on it.

set -euo pipefail

# ---- Fill these in before running -------------------------------------
RESOURCE_GROUP="hebridescyber-rg"
LOCATION="uksouth"
STATIC_WEB_APP_NAME="hebridescyber-app"
STORAGE_ACCOUNT_NAME="hebridescyberstorage" # TODO: must be globally unique
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

echo ""
echo "== Done. Manual steps still required: =="
echo "1. Set Static Web App application settings for secrets that must stay"
echo "   server-side (SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY,"
echo "   GITHUB_PAT, AZURE_OPENAI_KEY, etc.) — see docs/security.md:"
echo "   az staticwebapp appsettings set --name $STATIC_WEB_APP_NAME \\"
echo "     --setting-names SUPABASE_SERVICE_ROLE_KEY=<value>"
echo "2. Set GitHub Secrets for the deploy.yml workflow (see README.md)."
echo "3. Configure a custom domain + SSL on the Static Web App via the Portal or:"
echo "   az staticwebapp hostname set --name $STATIC_WEB_APP_NAME --hostname hebridescyber.com"
echo "4. Apply for Azure OpenAI access if not already approved for this subscription."
