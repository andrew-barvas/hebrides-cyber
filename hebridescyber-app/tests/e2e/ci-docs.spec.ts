import { test, expect } from "@playwright/test";

// /docs/ci is public and static: the CI setup guide, built from the files in
// public/ci/. The downloads it links to must actually be served.
test("CI guide lists every CI system and its downloads are served", async ({ page, request }) => {
  await page.goto("/docs/ci");
  await expect(page.getByRole("heading", { level: 1, name: /Security scans in your CI pipeline/i })).toBeVisible();

  for (const name of ["GitHub Actions", "GitLab CI", "Azure DevOps", "Bitbucket Pipelines", "Jenkins"]) {
    await expect(page.getByRole("heading", { level: 3, name })).toBeVisible();
  }
  await expect(page.getByText(/^SHA-256: [0-9a-f]{64}$/)).toBeVisible();

  const hrefs = await page.locator('a[download][href^="/ci/"]').evaluateAll((links) => [...new Set(links.map((a) => a.getAttribute("href")))]);
  expect(hrefs).toHaveLength(6); // the script + five templates
  for (const href of hrefs) {
    const res = await request.get(href!);
    expect(res.status(), href!).toBe(200);
    expect(await res.text()).toContain("hebrides-scan.sh");
  }
});
