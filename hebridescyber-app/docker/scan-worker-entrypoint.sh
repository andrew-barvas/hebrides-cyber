#!/usr/bin/env bash
# Entrypoint of the scan-worker image (Dockerfile's `scan-worker` stage), run
# by the Azure Container Apps Job in azure/terraform/scan-workers.tf. One
# execution = one run of the existing queue loop (run-queued-scan-jobs.ts):
# claim jobs until the queue is empty or the loop's own job/time budget is
# spent, then exit. KEDA starts another execution while jobs are still
# pending, so nothing here loops forever.
#
# ZAP runs as a second container in the same replica (they share localhost).
# A Container Apps Job execution only completes when every container has
# exited, so this script shuts ZAP down through its API on the way out —
# otherwise each execution would sit idle until its replica timeout.
set -uo pipefail

# Same shape as the Actions shards' gha-<run_id>-<shard>: verify-scan-run.ts
# and anyone reading scan_jobs.claimed_by can tell which path ran a job.
export WORKER_ID="${WORKER_ID:-aca-${CONTAINER_APP_JOB_EXECUTION_NAME:-$(hostname)}}"

zap_api() {
  curl -sf -m 10 "${ZAP_API_URL}/JSON/core/$1/?apikey=${ZAP_API_KEY}" >/dev/null
}

if [ -n "${ZAP_API_URL:-}" ] && [ -n "${ZAP_API_KEY:-}" ]; then
  ready=0
  for i in $(seq 1 24); do
    if zap_api view/version; then ready=1; echo "ZAP is ready"; break; fi
    echo "Waiting for ZAP ($i/24)..."
    sleep 5
  done
  # Same fallback as the workflow: zap.ts reports status: error for this run.
  [ "$ready" = "1" ] || echo "ZAP did not become ready in time — continuing, zap.ts will report status: error"
fi

node node_modules/.bin/tsx src/scripts/run-queued-scan-jobs.ts
status=$?

if [ -n "${ZAP_API_URL:-}" ] && [ -n "${ZAP_API_KEY:-}" ]; then
  zap_api action/shutdown || echo "ZAP shutdown call failed — the execution ends at its replica timeout instead"
fi

exit "$status"
