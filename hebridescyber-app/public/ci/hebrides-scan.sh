#!/bin/sh
# Hebrides Cyber security scan for any CI system: GitLab, Jenkins, Azure
# DevOps, Bitbucket, GitHub Actions, or a plain cron job.
#
# Queues a scan of a site you have already verified, waits for it, and fails
# only on NEW findings at or above a severity that you have not triaged. It
# never fails on the existing backlog: gating on every finding turns a
# pipeline red on its first run, and the check gets switched off the same day.
#
# Needs sh, curl and jq. Save it in your repository (for example as
# ci/hebrides-scan.sh) rather than downloading it on every run, so a change
# to it reaches your pipeline only when you review and commit it.
#
# Settings (environment variables):
#   HEBRIDES_CYBER_API_KEY    required. Dashboard -> Integrations -> API keys.
#                             Store it as a masked/secret CI variable.
#   HEBRIDES_TARGET_URL       required. The verified site to scan.
#   HEBRIDES_FAIL_ON          critical | high (default) | medium | low | none
#   HEBRIDES_TIMEOUT_SECONDS  how long to wait for the scan (default 540)
#   HEBRIDES_POLL_SECONDS     seconds between status checks (default 5)
#   HEBRIDES_RESULT_FILE      full JSON result (default hebrides-scan.json)
#   HEBRIDES_JUNIT_FILE       optional: also write a JUnit XML report here,
#                             so new findings show in your CI's test view
#   HEBRIDES_API_BASE_URL     default https://www.hebridescyber.co.uk
#
# Exit codes: 0 passed; 1 blocked by new findings; 2 could not scan (bad
# settings, API error, scan failed or timed out). Treat 2 as a failure too:
# a scan that did not run is not a pass.

set -eu

base="${HEBRIDES_API_BASE_URL:-https://www.hebridescyber.co.uk}"
base="${base%/}"
key="${HEBRIDES_CYBER_API_KEY:-}"
target="${HEBRIDES_TARGET_URL:-}"
fail_on=$(printf '%s' "${HEBRIDES_FAIL_ON:-high}" | tr '[:upper:]' '[:lower:]')
timeout="${HEBRIDES_TIMEOUT_SECONDS:-540}"
interval="${HEBRIDES_POLL_SECONDS:-5}"
result_file="${HEBRIDES_RESULT_FILE:-hebrides-scan.json}"
junit_file="${HEBRIDES_JUNIT_FILE:-}"

# Annotations where the CI understands them; plain lines everywhere else.
say() {
  level="$1"; shift
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::$level::$*"
  elif [ "${TF_BUILD:-}" = "True" ] && [ "$level" != "notice" ]; then
    echo "##vso[task.logissue type=$level]$*"
  else
    echo "$*"
  fi
}

die() {
  say error "Hebrides Cyber: $*"
  exit 2
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq >/dev/null 2>&1 || die "jq is required"
[ -n "$key" ] || die "HEBRIDES_CYBER_API_KEY is not set"
[ -n "$target" ] || die "HEBRIDES_TARGET_URL is not set"
case "$fail_on" in
  critical | high | medium | low | none) ;;
  *) die "HEBRIDES_FAIL_ON must be critical, high, medium, low or none (got \"$fail_on\")" ;;
esac
case "$timeout$interval" in
  *[!0-9]*) die "HEBRIDES_TIMEOUT_SECONDS and HEBRIDES_POLL_SECONDS must be whole numbers" ;;
esac

body_file=$(mktemp)
trap 'rm -f "$body_file"' EXIT

# api METHOD PATH [JSON] prints the HTTP status and leaves the body in
# $body_file. The key is passed to curl on stdin, never on its command line,
# so it does not show up in a process listing.
api() {
  if [ $# -ge 3 ]; then
    code=$(printf 'Authorization: Bearer %s\n' "$key" | curl -sS -m 30 -o "$body_file" -w '%{http_code}' -X "$1" -H @- -H 'Content-Type: application/json' --data "$3" "$base$2") || true
  else
    code=$(printf 'Authorization: Bearer %s\n' "$key" | curl -sS -m 30 -o "$body_file" -w '%{http_code}' -X "$1" -H @- "$base$2") || true
  fi
  printf '%s' "${code:-000}"
}

api_error() {
  jq -r '.error // empty' "$body_file" 2>/dev/null || true
}

echo "Hebrides Cyber: scanning $target"
code=$(api POST /api/v1/scans "$(jq -cn --arg t "$target" '{target_url: $t}')")
case "$code" in
  2??) ;;
  *) die "could not queue the scan (HTTP $code) $(api_error)" ;;
esac
scan_id=$(jq -r '.scan_id // empty' "$body_file")
case "$scan_id" in
  "" | *[!A-Za-z0-9-]*) die "the API did not return a scan id" ;;
esac
echo "Queued scan $scan_id, waiting for it to finish"

deadline=$(($(date +%s) + timeout))
while :; do
  code=$(api GET "/api/v1/scans/$scan_id")
  case "$code" in
    2??) ;;
    *) die "could not check scan $scan_id (HTTP $code) $(api_error)" ;;
  esac
  status=$(jq -r '.status // empty' "$body_file")
  [ "$status" = "completed" ] && break
  [ "$status" = "failed" ] && die "scan $scan_id failed while running"
  [ "$(date +%s)" -ge "$deadline" ] && die "scan $scan_id did not finish within $timeout seconds"
  sleep "$interval"
done
cp "$body_file" "$result_file"

# The gate, identical to the packaged GitHub Action: a finding blocks when it
# is new since the previous scan, at or above HEBRIDES_FAIL_ON, and not
# triaged (accepted, false positive, or snoozed and not yet expired).
# shellcheck disable=SC2016 # a jq program: $f is jq's variable, not the shell's
defs='
def rank: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[(. // "") | tostring] // 0;
def triaged:
  (.triage | type) == "object" and ((.triage.state // "") | tostring | length) > 0 and
  (if .triage.expires_at == null then true
   else (try ((.triage.expires_at | sub("\\.[0-9]+"; "") | fromdateiso8601) > now) catch false) end);
def blocking($f): $f != "none" and .status == "new" and (.severity | rank) >= ($f | rank) and (triaged | not);
def new_findings: [(.findings // [])[] | select(.status == "new")];
'

score=$(jq -r '.score // "?"' "$result_file")
compared=$(jq -r '.compared_to_previous_scan == true' "$result_file")
new_count=$(jq -r "$defs"' new_findings | length' "$result_file")
blocking=$(jq -r --arg f "$fail_on" "$defs"' if .compared_to_previous_scan == true then [new_findings[] | select(blocking($f))] | length else 0 end' "$result_file")

echo "Security score: $score/100"
echo "Report: $base/dashboard/scans/$scan_id"

if [ -n "$junit_file" ]; then
  jq -r --arg f "$fail_on" --arg compared "$compared" "$defs"'
    def esc: tostring | @html;
    new_findings as $n
    | ([$n[] | select(blocking($f))] | length) as $failures
    | ([$n[] | select(triaged)] | length) as $skipped
    | "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<testsuite name=\"Hebrides Cyber security scan\" tests=\"\([($n | length), 1] | max)\" failures=\"\($failures)\" skipped=\"\($skipped)\">",
      (if ($n | length) == 0 then
         "  <testcase classname=\"hebrides-cyber\" name=\"\(if $compared == "true" then "No new findings since the previous scan" else "First scan of this target: baseline recorded" end)\"/>"
       else
         ($n[] |
           "  <testcase classname=\"hebrides-cyber.\(.severity | esc)\" name=\"\(.title | esc) (\(.check_id // "unknown" | esc))\">"
           + (if triaged then "<skipped message=\"Triaged: \(.triage.state | esc)\"/>"
              elif blocking($f) then "<failure message=\"New \(.severity | esc) finding\">\(.detail // "" | esc)</failure>"
              else "" end)
           + "</testcase>")
       end),
      "</testsuite>"
  ' "$result_file" >"$junit_file"
fi

if [ "$compared" != "true" ]; then
  say notice "First scan of this target, so there is no baseline to compare against yet. Nothing to gate on."
  exit 0
fi

jq -r --arg f "$fail_on" "$defs"'
  new_findings[]
  | if triaged then "notice\tNEW [\(.severity)] \(.title) (triaged: \(.triage.state), not counted)"
    elif blocking($f) then "error\tNEW [\(.severity)] \(.title)"
    else "warning\tNEW [\(.severity)] \(.title)" end
' "$result_file" | while IFS="$(printf '\t')" read -r level line; do
  say "$level" "$line"
done

if [ "$fail_on" = "none" ]; then
  say notice "$new_count new finding(s) since the last scan; not failing (HEBRIDES_FAIL_ON=none)."
  exit 0
fi
if [ "$blocking" -gt 0 ]; then
  say error "$blocking new finding(s) at or above \"$fail_on\" severity since the last scan."
  exit 1
fi
say notice "No untriaged new findings at or above \"$fail_on\" severity ($new_count new finding(s) below the threshold or triaged)."
