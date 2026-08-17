# Claude Prompt: Provision Azure Resources for hebridescyber-app

Use this prompt with a Claude agent that has shell/Azure CLI access (e.g. Claude Code, or Cowork with a connected terminal). It assumes the `hebridescyber-app` repo scaffold already exists and you're ready to stand up real infrastructure — not another scaffold.

Fill in the bracketed values before running, then paste the whole block as your instruction to the agent.

---

## Prerequisites (fill in before running)

```
AZURE_SUBSCRIPTION_ID   = [your subscription ID]
RESOURCE_GROUP          = hebridescyber-rg
LOCATION                = uksouth
STATIC_WEB_APP_NAME     = hebridescyber-app
STORAGE_ACCOUNT_NAME    = hebridescyberstorage   (must be globally unique, lowercase, no dashes)
GITHUB_REPO             = [org/hebridescyber-app]
CUSTOM_DOMAIN           = hebridescyber.com
```

You must already have: an Azure account with an active subscription, the `az` CLI installed and authenticated (`az login`), and owner/contributor rights on the subscription or a resource group.

---

## The Prompt

```
You are provisioning real Azure infrastructure for a project called hebridescyber-app.
The repo scaffold already exists at [path to repo] and includes:
- azure/terraform/main.tf (placeholder Terraform)
- azure/cli-scripts/provision.sh (placeholder CLI script)
- .github/workflows/deploy.yml (expects specific GitHub Secrets)
- src/pages/api/* (the whole app — marketing site, dashboard, and every API
  route including run-scan/verify-ownership/generate-report/generate-fix-pr/
  generate-newsletter — deploys as ONE Azure Static Web App; there is no
  separate Functions app to provision)

Do the following, checking in with me before any step that costs money or is
destructive:

1. Verify Azure CLI is authenticated (`az account show`) and confirm the
   subscription ID matches AZURE_SUBSCRIPTION_ID above. Stop and ask if not.

2. Create a resource group named RESOURCE_GROUP in LOCATION, if it doesn't
   already exist.

3. Provision an Azure Static Web App (STATIC_WEB_APP_NAME) linked to
   GITHUB_REPO, on the free or standard tier (ask me which). This should
   auto-generate a GitHub Actions deployment token — capture it, do not
   print it in full, and tell me which GitHub Secret to store it under
   (AZURE_STATIC_WEB_APPS_API_TOKEN).

4. Provision a Storage Account (STORAGE_ACCOUNT_NAME) for PDF report
   generation (see AZURE_STORAGE_CONNECTION_STRING in
   src/pages/api/generate-report.ts).

5. List the application settings the Static Web App will eventually need,
   based on .env.example in the repo (SUPABASE_SERVICE_ROLE_KEY,
   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, AZURE_OPENAI_KEY,
   AZURE_STORAGE_CONNECTION_STRING, GITHUB_PAT, GITHUB_ACTIONS_TOKEN). Do
   NOT set any real secret values yet — just produce the list, and tell me
   the `az staticwebapp appsettings set` command to set each one myself.

6. Update azure/terraform/main.tf and azure/cli-scripts/provision.sh in the
   repo to reflect the actual resource names and IDs you just created,
   replacing the TODO placeholders, so the infra-as-code matches reality
   and can be re-run idempotently later.

7. Print a checklist of GitHub Secrets I still need to set manually
   (Settings > Secrets and variables > Actions) for GITHUB_REPO, matching
   what .github/workflows/deploy.yml and scheduled-scans.yml expect — plus
   the NEXT_PUBLIC_SITE_URL repo *variable* (not secret) weekly-newsletter.yml needs.

8. Do NOT attempt to configure the custom domain (CUSTOM_DOMAIN), Azure
   OpenAI resource, or Stripe products automatically — these require manual
   approval steps or dashboard actions. Instead, list the exact steps I need
   to take for each, with links to the relevant Azure Portal blade.

9. Summarize everything created, its estimated monthly cost, and ask me to
   confirm before you consider this task complete.

Ask me for confirmation before creating anything that isn't free-tier, and
never commit any real secret value to the repo — only reference Key Vault
secret names or GitHub Secret names in code and workflow files.
```

---

## Notes

- **Azure OpenAI** requires a separate access request/approval in some regions — apply for this early, it's not instant. See `docs/security.md` and `docs/architecture.md` in the repo for how it's used.
- **Custom domain + SSL**: Azure Static Web Apps provisions a free managed SSL certificate once you add the custom domain and verify DNS — this step is manual via the Portal or `az staticwebapp hostname set`.
- **Cost control**: Static Web Apps free tier and Functions Consumption plan should keep this near £0/month until traffic or storage grows — confirm pricing tier choices with the agent before it provisions anything above free tier.
- Re-run this prompt (or the updated Terraform) any time you need to recreate the environment (e.g. staging vs. production).
