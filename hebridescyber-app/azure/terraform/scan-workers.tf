# --- Always-on scan workers, with an optional fixed source IP (P1-1) ---
#
# The queue loop (src/scripts/run-queued-scan-jobs.ts) as an Azure Container
# Apps Job, built from the Dockerfile's `scan-worker` stage, started by a KEDA
# rule whenever scan_jobs rows are pending.
#
# The fixed source IP is a switch, off by default to keep this free for now:
#   scan_static_egress_ip = false (default): the job runs in a workload
#     profiles environment with Azure-managed egress. Outbound addresses are
#     Microsoft's, can change, and are not ours alone, so nothing is published
#     and /trust says so. Cost: the Consumption profile's monthly free grant
#     (180,000 vCPU-seconds and 360,000 GiB-seconds per subscription, about 12
#     hours of this 4 vCPU / 8 GiB job), then per second of use.
#   scan_static_egress_ip = true: adds a VNet, a subnet, an NSG and a NAT
#     gateway on one static public IP, and moves the environment onto that
#     subnet, so every scan leaves from that one address. That is the address
#     customers allowlist and /trust publishes (src/lib/scannerEgress.ts).
#     Cost at list price, East US 2: ~$33/month for the NAT gateway plus
#     $0.045/GB processed, ~$3.65/month for the IP. Turning it on REPLACES the
#     environment and the job (a subnet can't be added to an existing
#     environment); they hold no state, so that is safe. Once on, the IP has
#     prevent_destroy: turning it back off fails the plan by design, because
#     losing the address breaks every customer allowlist.
#
# Replaces nothing yet: .github/workflows/scheduled-scans.yml stays as the
# fallback and works the same queue (claim_scan_job() is SKIP LOCKED, so two
# paths never run one job twice). docs/RUNBOOK.md 6.18 has the apply/deploy
# steps and the cut-over.
#
# NOT APPLIED. Same caveats as main.tf: review with `terraform plan`, and
# target these resources rather than applying the whole file, which also holds
# a never-applied scaffold (see the IMPORTANT note above
# data.azurerm_resource_group.existing in main.tf):
#   terraform plan -target=azurerm_container_app_job.scan_worker \
#     -target=azurerm_subnet_nat_gateway_association.scan_workers \
#     -target=azurerm_subnet_network_security_group_association.scan_workers
# (the targets pull in everything they depend on; the last two are empty
# while the switch is off).
#
# Why a second Container Apps environment rather than the existing
# azurerm_container_app_environment.main: the job needs a workload profiles
# environment, and the NAT gateway needs that environment on a subnet of our
# own VNet. Keeping the web app's environment untouched also keeps scan
# traffic and the web app's egress apart.

variable "scan_static_egress_ip" {
  description = "Route scan egress through a NAT gateway on one static public IP (~$37/month). Off: Azure-managed egress, nothing to publish."
  type        = bool
  default     = false
}

variable "scan_worker_vnet_cidr" {
  description = "Address space of the scan workers' VNet. Only needs to avoid overlapping a network it is ever peered with."
  default     = "10.40.0.0/16"
}

variable "scan_worker_subnet_cidr" {
  description = "Subnet the Container Apps environment runs in. Workload profiles environments need at least a /27."
  default     = "10.40.0.0/24"
}

variable "scan_worker_max_executions" {
  description = "Most job executions running at once. Each runs one scan at a time, so this is the scan concurrency."
  default     = 5
}

variable "scan_worker_jobs_per_execution" {
  description = "KEDA target: pending jobs per running execution. 1 starts an execution per pending job, up to the max."
  default     = 1
}

# Libpq URI KEDA's postgresql scaler polls with. Use the Supabase pooler's
# session-mode URI (IPv4; the direct database host is IPv6-only) and a role
# that can only read scan_jobs — docs/RUNBOOK.md "Scan workers" has the SQL.
# It is a credential for the database, so never the service-role key's owner.
variable "scan_queue_keda_connection" {
  sensitive = true
  default   = null
}

variable "supabase_url" {
  default = null
}

variable "next_public_site_url" {
  default = "https://www.hebridescyber.co.uk"
}

# Optional worker settings, by the env var name the worker reads. Each mirrors
# what the "Work the scan job queue" step of scheduled-scans.yml passes
# (scanWorkerEnv.test.ts checks that every name there is accounted for here).
# An unset one is left out, which the code reads as "not configured", exactly
# as an empty GitHub secret is.
variable "scan_worker_secrets" {
  description = "Secret worker settings: RESEND_API_KEY, CREDENTIALS_ENC_KEY, SENTRY_DSN, AZURE_OPENAI_KEY, GITHUB_PAT, GITHUB_APP_PRIVATE_KEY, WPSCAN_API_TOKEN, GOOGLE_SAFE_BROWSING_API_KEY, HIBP_API_KEY, INTERACTSH_TOKEN, STRIX_LLM_API_KEY, PROWLER_AWS_ACCESS_KEY_ID, PROWLER_AWS_SECRET_ACCESS_KEY."
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "scan_worker_settings" {
  description = "Non-secret worker settings: AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, GITHUB_APP_ID, AI_TRIAGE, INTERACTSH_SERVER, DISABLE_OAST."
  type        = map(string)
  default     = {}
}

locals {
  # Container Apps secret names: lowercase letters, digits and dashes.
  scan_worker_secret_names = { for k in nonsensitive(keys(var.scan_worker_secrets)) : k => lower(replace(k, "_", "-")) }
}

# The ZAP API key: random per environment instead of the old literal
# "changeme", shared by the ZAP sidecar and the worker through one secret.
resource "random_password" "zap_api_key" {
  length  = 48
  special = false
}

resource "azurerm_public_ip" "scan_egress" {
  count = var.scan_static_egress_ip ? 1 : 0

  name                = "hebridescyber-scan-egress-ip"
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
  allocation_method   = "Static"
  sku                 = "Standard"

  # This address is published to customers and allowlisted in their WAFs.
  # Destroying it loses it for good, and every allowlist with it.
  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_nat_gateway" "scan_egress" {
  count = var.scan_static_egress_ip ? 1 : 0

  name                = "hebridescyber-scan-egress-nat"
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
  sku_name            = "Standard"
  # Above the 4-minute default: a slow target can hold a scan connection open.
  idle_timeout_in_minutes = 10
}

resource "azurerm_nat_gateway_public_ip_association" "scan_egress" {
  count = var.scan_static_egress_ip ? 1 : 0

  nat_gateway_id       = azurerm_nat_gateway.scan_egress[0].id
  public_ip_address_id = azurerm_public_ip.scan_egress[0].id
}

resource "azurerm_virtual_network" "scan_workers" {
  count = var.scan_static_egress_ip ? 1 : 0

  name                = "hebridescyber-scan-vnet"
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
  address_space       = [var.scan_worker_vnet_cidr]
}

resource "azurerm_subnet" "scan_workers" {
  count = var.scan_static_egress_ip ? 1 : 0

  name                 = "scan-workers"
  resource_group_name  = data.azurerm_resource_group.existing.name
  virtual_network_name = azurerm_virtual_network.scan_workers[0].name
  address_prefixes     = [var.scan_worker_subnet_cidr]

  delegation {
    name = "container-apps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet_nat_gateway_association" "scan_workers" {
  count = var.scan_static_egress_ip ? 1 : 0

  subnet_id      = azurerm_subnet.scan_workers[0].id
  nat_gateway_id = azurerm_nat_gateway.scan_egress[0].id
}

# Nothing listens in this subnet: the job has no ingress. The default rules
# already deny inbound from the internet and allow outbound, which is what the
# workers need; the group exists so that stays explicit and auditable.
resource "azurerm_network_security_group" "scan_workers" {
  count = var.scan_static_egress_ip ? 1 : 0

  name                = "hebridescyber-scan-workers-nsg"
  resource_group_name = data.azurerm_resource_group.existing.name
  location            = data.azurerm_resource_group.existing.location
}

resource "azurerm_subnet_network_security_group_association" "scan_workers" {
  count = var.scan_static_egress_ip ? 1 : 0

  subnet_id                 = azurerm_subnet.scan_workers[0].id
  network_security_group_id = azurerm_network_security_group.scan_workers[0].id
}

resource "azurerm_container_app_environment" "scan_workers" {
  name                       = "hebridescyber-scan-env"
  resource_group_name        = data.azurerm_resource_group.existing.name
  location                   = data.azurerm_resource_group.existing.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.container_apps.id
  # On our subnet only with the static IP; otherwise Azure manages the network.
  infrastructure_subnet_id = var.scan_static_egress_ip ? azurerm_subnet.scan_workers[0].id : null
  # No app in this environment takes requests, so nothing gets a public
  # endpoint. Only settable on an environment in our own subnet.
  internal_load_balancer_enabled = var.scan_static_egress_ip ? true : null

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  # With the static IP on, egress only leaves through the NAT gateway once the
  # subnet is attached to it, so the environment must not exist (and run a
  # job) before that. An empty dependency while the switch is off.
  depends_on = [azurerm_subnet_nat_gateway_association.scan_workers]
}

resource "azurerm_container_app_job" "scan_worker" {
  name                         = "hebridescyber-scan-worker"
  resource_group_name          = data.azurerm_resource_group.existing.name
  location                     = data.azurerm_resource_group.existing.location
  container_app_environment_id = azurerm_container_app_environment.scan_workers.id
  workload_profile_name        = "Consumption"

  # The loop stops claiming after 25 minutes (TIME_BUDGET_MS) and then
  # finishes the job in hand. Two hours covers that with room to spare, and
  # stays well under the 390 minutes after which reset_stale_scan_jobs()
  # (sql/migrations/041) assumes a running job's worker is dead.
  replica_timeout_in_seconds = 7200
  # A retry would start a fresh loop, not resume the job: the claimed row is
  # recovered by reset_stale_scan_jobs() instead.
  replica_retry_limit = 0

  event_trigger_config {
    parallelism              = 1
    replica_completion_count = 1

    scale {
      min_executions              = 0
      max_executions              = var.scan_worker_max_executions
      polling_interval_in_seconds = 30

      rules {
        name             = "pending-scan-jobs"
        custom_rule_type = "postgresql"
        metadata = {
          # Pending = enqueued and not yet claimed (claim_scan_job() moves a
          # row to 'running'). Same filter as /api/health's queue check.
          query                      = "SELECT COUNT(*) FROM public.scan_jobs WHERE status = 'pending'"
          targetQueryValue           = tostring(var.scan_worker_jobs_per_execution)
          activationTargetQueryValue = "0"
        }
        authentication {
          secret_name       = "keda-postgres-connection"
          trigger_parameter = "connection"
        }
      }
    }
  }

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
    name  = "keda-postgres-connection"
    value = var.scan_queue_keda_connection
  }

  secret {
    name  = "supabase-service-role-key"
    value = var.supabase_service_role_key
  }

  secret {
    name  = "zap-api-key"
    value = random_password.zap_api_key.result
  }

  dynamic "secret" {
    for_each = local.scan_worker_secret_names
    content {
      name  = secret.value
      value = var.scan_worker_secrets[secret.key]
    }
  }

  template {
    # Consumption caps one replica at 4 vCPU / 8 GiB across its containers.
    container {
      name = "scan-worker"
      # Placeholder: deploy-scan-worker.yml sets the pushed tag (the git SHA)
      # with `az containerapp job update --image`; see ignore_changes below.
      image  = "${azurerm_container_registry.main.login_server}/hebridescyber-scan-worker:latest"
      cpu    = 2.5
      memory = "5Gi"

      env {
        name  = "SUPABASE_URL"
        value = var.supabase_url
      }
      env {
        name        = "SUPABASE_SERVICE_ROLE_KEY"
        secret_name = "supabase-service-role-key"
      }
      env {
        name  = "NEXT_PUBLIC_SITE_URL"
        value = var.next_public_site_url
      }
      env {
        name        = "ZAP_API_KEY"
        secret_name = "zap-api-key"
      }

      dynamic "env" {
        for_each = local.scan_worker_secret_names
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      dynamic "env" {
        for_each = var.scan_worker_settings
        content {
          name  = env.key
          value = env.value
        }
      }
    }

    # ZAP, pinned by digest (the same one scheduled-scans.yml runs). It shares
    # the replica's localhost with the worker, so it binds 127.0.0.1 only; the
    # worker's entrypoint shuts it down when the loop ends, which is what lets
    # the execution complete.
    container {
      name    = "zap"
      image   = "ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238"
      cpu     = 1.5
      memory  = "3Gi"
      command = ["/bin/sh", "-c"]
      args = [
        "exec zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.key=\"$ZAP_API_KEY\" -config api.addrs.addr.name=127.0.0.1",
      ]

      env {
        name        = "ZAP_API_KEY"
        secret_name = "zap-api-key"
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }
}

output "scan_egress_ip" {
  description = "The scan workers' fixed source IP; null while scan_static_egress_ip is off. Publish it in src/lib/scannerEgress.ts once applied."
  value       = var.scan_static_egress_ip ? azurerm_public_ip.scan_egress[0].ip_address : null
}

output "scan_worker_job_name" {
  value = azurerm_container_app_job.scan_worker.name
}
