#!/usr/bin/env bash
# One-time bootstrap for Terraform's remote state backend. Terraform can't
# manage the storage account that holds its own state (chicken-and-egg), so
# this is a plain CLI script, matching provision.sh's pattern.
#
# Usage: ./bootstrap-tfstate.sh
# Requires: az CLI installed and `az login` already run.
#
# Run this ONCE, then uncomment the backend "azurerm" {} block in
# azure/terraform/main.tf with these exact values and run `terraform init`
# to migrate to remote state. Names below were confirmed globally available
# via `az storage account check-name` on 2026-08-27 — re-check if this
# script sits unused for long, another Azure customer could take the name
# in the meantime (storage account names are a global namespace).

set -euo pipefail

RESOURCE_GROUP="hebridescyber-tfstate-rg"
LOCATION="eastus2" # matches rg-hebrides-cyber, the real app's resource group
STORAGE_ACCOUNT_NAME="hebridescybertfstate"
CONTAINER_NAME="tfstate"

echo "== Verifying Azure CLI login =="
az account show --output table

echo "== Creating resource group: $RESOURCE_GROUP =="
az group create --name "$RESOURCE_GROUP" --location "$LOCATION"

echo "== Creating storage account: $STORAGE_ACCOUNT_NAME =="
az storage account create \
  --name "$STORAGE_ACCOUNT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --sku Standard_LRS \
  --min-tls-version TLS1_2 \
  --https-only true \
  --allow-blob-public-access false

echo "== Creating blob container: $CONTAINER_NAME =="
az storage container create \
  --name "$CONTAINER_NAME" \
  --account-name "$STORAGE_ACCOUNT_NAME" \
  --auth-mode login

echo ""
echo "== Done. Next steps: =="
echo "1. Uncomment the backend \"azurerm\" {} block at the top of"
echo "   azure/terraform/main.tf — the values already match what this script"
echo "   just created:"
echo "     resource_group_name  = \"$RESOURCE_GROUP\""
echo "     storage_account_name = \"$STORAGE_ACCOUNT_NAME\""
echo "     container_name       = \"$CONTAINER_NAME\""
echo "     key                  = \"hebridescyber.tfstate\""
echo "2. Run: terraform init  (it will offer to migrate any existing local"
echo "   state into this backend — confirm yes)."
