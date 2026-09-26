// Which ticket_integrations rows are issue trackers. The same table also
// holds PagerDuty/Opsgenie on-call rows (028_oncall_integrations.sql), so
// every ticketing read must filter on this list — "the owner's most recent
// row" on its own can pick an on-call integration and break ticketing.
//
// Kept dependency-free so client components can import it without pulling
// the server-side provider clients into their bundle.
export const TICKET_PROVIDERS = ["jira", "linear", "servicenow", "github"] as const;

export type TicketProvider = (typeof TICKET_PROVIDERS)[number];

export const TICKET_PROVIDER_LABELS: Record<TicketProvider, string> = {
  jira: "Jira",
  linear: "Linear",
  servicenow: "ServiceNow",
  github: "GitHub Issues",
};
