// Deterministic fixtures shared by the authenticated e2e specs. Everything is
// fake: the Supabase project is "example-project" and the scanned site is
// example.com. Dates are fixed so nothing depends on the clock.

export const SCAN_ID = "aaaaaaaa-0000-4000-8000-000000000001";
export const PREVIOUS_SCAN_ID = "aaaaaaaa-0000-4000-8000-000000000002";
export const QUEUED_SCAN_ID = "aaaaaaaa-0000-4000-8000-000000000003";

export const SUBSCRIPTION = {
  plan: "pro",
  status: "active",
  slack_webhook_url: null,
  ms_teams_webhook_url: null,
};

const CE = (control: string) => ({ framework: "cyber-essentials", control });
const OWASP = (control: string) => ({ framework: "owasp-top-10", control });

export const FINDINGS = [
  {
    severity: "critical",
    title: "Exposed .env file",
    detail: "https://example.com/.env returned application secrets.",
    remediation: "Remove the file from the web root and rotate every secret it contained.",
    checkId: "exposure.env",
    complianceRefs: [CE("Secure configuration"), OWASP("A05:2021 – Security Misconfiguration")],
  },
  {
    severity: "high",
    title: "Missing Content-Security-Policy header",
    detail: "The response has no Content-Security-Policy header.",
    remediation: "Add a Content-Security-Policy header.",
    checkId: "headers.csp",
    complianceRefs: [CE("Secure configuration")],
  },
  {
    severity: "medium",
    title: "No SPF record",
    detail: "example.com publishes no SPF record.",
    checkId: "dns.spf",
    complianceRefs: [OWASP("A05:2021 – Security Misconfiguration")],
  },
  {
    severity: "info",
    title: "Third-party script from cdn.example.net",
    detail: "The page loads JavaScript from cdn.example.net.",
    checkId: "script-inventory.unreviewed:cdn.example.net",
  },
] as const;

// A scan of the same site, a week earlier, that did not yet have the CSP
// finding (so it is "new" now) and had one that has since been fixed.
const PREVIOUS_FINDINGS = [
  FINDINGS[0],
  FINDINGS[2],
  { severity: "low", title: "Server version disclosed", detail: "Server: nginx/1.18.0", checkId: "headers.server-disclosure" },
];

const scanRow = (id: string, createdAt: string, score: number, findings: readonly unknown[]) => ({
  id,
  target_url: "https://example.com",
  status: "completed",
  created_at: createdAt,
  owner: "11111111-1111-4111-8111-111111111111",
  scan_results: [
    {
      id: `result-${id}`,
      scan_id: id,
      score,
      summary: "Two serious issues need attention.",
      created_at: createdAt,
      results: { target_url: "https://example.com", checked_at: createdAt, findings },
    },
  ],
});

export const LATEST_SCAN = scanRow(SCAN_ID, "2026-10-04T09:00:00.000Z", 52, FINDINGS);
export const PREVIOUS_SCAN = scanRow(PREVIOUS_SCAN_ID, "2026-09-27T09:00:00.000Z", 61, PREVIOUS_FINDINGS);

/** scans + scan_results as the browser queries them (scan_results is embedded in the scan row). */
export const SCAN_ROWS = [LATEST_SCAN, PREVIOUS_SCAN];
/** The same data shaped as scan_results rows, for the report page's own query. */
export const SCAN_RESULT_ROWS = SCAN_ROWS.map((s) => s.scan_results[0]);
