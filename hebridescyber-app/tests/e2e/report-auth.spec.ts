import { test, expect } from "@playwright/test";
import { signIn } from "./helpers/session";
import { findingCard, findingsSection, openFindingTitles, openReport } from "./helpers/report";

// Scan report (/dashboard/scans/[id]): the report is read in the browser
// through Supabase (scan_results, scans for history/diff) and the triage API.
// Only those are mocked; the page's server-rendered shell is just the app
// shell, so nothing here depends on a server-side data fetch.

test.beforeEach(async ({ context }) => {
  await signIn(context);
});

test("report shows the score, summary and severity counts", async ({ page }) => {
  await openReport(page);

  await expect(page.getByText("Two serious issues need attention.")).toBeVisible();
  await expect(page.getByText("/100 · Poor")).toBeVisible();
  for (const pill of ["1 critical", "1 high", "1 medium", "1 info"]) {
    await expect(page.getByText(pill, { exact: true })).toBeVisible();
  }
  // Critical/high findings trigger the remediation prompt.
  await expect(page.getByText("2 critical/high findings found.")).toBeVisible();
});

test("findings are grouped by severity, most severe first, with New/Fixed against the previous scan", async ({ page }) => {
  await openReport(page);
  const findings = findingsSection(page);

  await expect(openFindingTitles(page)).toHaveText([
    "Exposed .env file",
    "Missing Content-Security-Policy header",
    "No SPF record",
    "Third-party script from cdn.example.net",
  ]);
  await expect(findings.getByText("Critical", { exact: true })).toBeVisible();
  await expect(findings.getByText("High", { exact: true })).toBeVisible();
  await expect(findings.getByText("Medium", { exact: true })).toBeVisible();
  await expect(findings.getByText("Info", { exact: true })).toBeVisible();

  // The CSP finding did not exist on the previous scan.
  await expect(findings.getByText("NEW", { exact: true })).toHaveCount(2);
  await findings.getByRole("button", { name: "Fixed (1)" }).click();
  await expect(findings.getByText("Server version disclosed", { exact: true })).toBeVisible();
  await expect(findings.getByText("Exposed .env file", { exact: true })).toHaveCount(0);
});

test("compliance badges appear on findings and in the control-area summary", async ({ page }) => {
  await openReport(page);

  // One badge per framework on the finding itself.
  const envCard = findingCard(page, "Exposed .env file");
  await expect(envCard.getByText("Cyber Essentials", { exact: true })).toBeVisible();
  await expect(envCard.getByText("OWASP Top 10", { exact: true })).toBeVisible();
  await expect(envCard.getByText("PCI DSS", { exact: true })).toHaveCount(0);

  // Control areas: Cyber Essentials first; controls with a finding are marked.
  const summary = page.getByText("Compliance control areas").locator("xpath=..");
  const control = (name: string) => summary.locator("div.rounded-lg").filter({ has: page.getByText(name, { exact: true }) });
  await expect(control("Secure configuration")).toContainText("✗");
  await expect(control("Malware protection")).toContainText("✓");

  await summary.getByRole("button", { name: "OWASP Top 10" }).click();
  await expect(control("A05:2021 – Security Misconfiguration")).toContainText("✗");
  await expect(control("A03:2021 – Injection")).toContainText("✓");
});

test("the executive summary counts open findings", async ({ page }) => {
  await openReport(page);
  const summary = page.getByText("Executive summary", { exact: true }).last().locator("xpath=..");
  await expect(summary.getByText("Open findings", { exact: true }).locator("xpath=..")).toContainText("4");
  await expect(summary.getByText("Critical + High", { exact: true }).locator("xpath=..")).toContainText("2");
});
