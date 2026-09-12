// Hostname allowlist for vendor "incoming webhook" URLs (Slack, MS Teams).
//
// These fields are advertised to customers as "paste your Slack/Teams
// webhook URL" — they're only ever supposed to point at the vendor's own
// service. That makes this a narrower, stronger fix than the generic
// SSRF check src/lib/ownership.ts's validateNoSsrf() does for a genuinely
// arbitrary customer URL (see src/lib/webhooks.ts, which uses that
// instead): here, nothing except the vendor's real hostnames should ever
// be accepted, so a public attacker-controlled HTTPS endpoint is rejected
// just as much as a private IP is. Without this, "Slack webhook URL" was
// validated only as "starts with https://" (still true standalone for any
// other https:// field), which makes it a free, customer-configurable
// SSRF/exfiltration proxy that fires on every scan completion.
//
// Exact-or-subdomain matching only — `hooks.slack.com.evil.com` must not
// match `hooks.slack.com`.
function matchesAllowedHost(hostname: string, allowedHosts: readonly string[]): boolean {
  const lower = hostname.toLowerCase();
  return allowedHosts.some((host) => lower === host || lower.endsWith(`.${host}`));
}

const SLACK_HOSTS = ["hooks.slack.com"] as const;

// outlook.office.com/office365.com cover classic "Incoming Webhook"
// connectors; *.webhook.office.com covers Teams Workflows-based webhooks
// (see msTeams.ts's own header comment on why this app still targets the
// legacy MessageCard schema both accept).
const TEAMS_HOSTS = ["outlook.office.com", "outlook.office365.com", "webhook.office.com"] as const;

function isValidVendorWebhookUrl(url: string, allowedHosts: readonly string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return parsed.protocol === "https:" && matchesAllowedHost(parsed.hostname, allowedHosts);
}

export function isValidSlackWebhookUrl(url: string): boolean {
  return isValidVendorWebhookUrl(url, SLACK_HOSTS);
}

export function isValidTeamsWebhookUrl(url: string): boolean {
  return isValidVendorWebhookUrl(url, TEAMS_HOSTS);
}
