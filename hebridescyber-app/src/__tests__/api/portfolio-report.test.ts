// GET /api/portfolio-report, through the real loader (portfolioData.ts) and
// renderer (portfolioReport.ts), with Supabase and the browser stood in.
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, checkRateLimitMock, tables, setContent } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  checkRateLimitMock: vi.fn(),
  tables: {} as Record<string, { data: unknown; error: unknown }[]>,
  setContent: vi.fn(),
}));

function builder(table: string) {
  const reply = () => Promise.resolve(tables[table]?.shift() ?? { data: null, error: null });
  const b: Record<string, unknown> = {};
  for (const op of ["select", "eq", "order", "limit", "in"]) b[op] = () => b;
  b.maybeSingle = reply;
  b.then = (resolve: (v: unknown) => void, reject: (e: unknown) => void) => reply().then(resolve, reject);
  return b;
}

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: (t: string) => builder(t) },
}));
vi.mock("@/lib/rateLimit", () => ({ checkRateLimit: checkRateLimitMock }));
vi.mock("playwright", () => ({
  chromium: {
    launch: async () => ({
      newPage: async () => ({
        setContent,
        pdf: async ({ path: out }: { path: string }) => {
          const { writeFile } = await import("node:fs/promises");
          await writeFile(out, "%PDF-stub");
        },
      }),
      close: async () => undefined,
    }),
  },
}));

import handler from "@/pages/api/portfolio-report";

const get = (query: Record<string, string> = {}) => createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query });

function agency() {
  tables.subscriptions = [{ data: { plan: "agency", status: "active" }, error: null }];
  tables.users = [{ data: { is_admin: false }, error: null }];
}

function portfolio(brand: { brand_name?: string; brand_logo_url?: string } | null = null) {
  tables.monitored_targets = [{ data: [{ target_url: "https://a.example/" }, { target_url: "https://a.example" }, { target_url: "https://b.example" }, { target_url: "https://new.example" }], error: null }];
  tables.scans = [{
    data: [
      { id: "s-a2", target_url: "https://a.example", created_at: "2026-10-05T00:00:00Z" },
      { id: "s-b", target_url: "https://b.example/", created_at: "2026-10-04T00:00:00Z" },
      { id: "s-a1", target_url: "https://a.example", created_at: "2026-09-01T00:00:00Z" },
      { id: "s-other", target_url: "https://not-monitored.example", created_at: "2026-10-05T00:00:00Z" },
    ],
    error: null,
  }];
  tables.subscriptions.push({ data: brand, error: null });
  tables.finding_triage = [{ data: [{ target_host: "b.example", check_id: "fp", state: "false_positive", reason: "not a real issue", expires_at: null }], error: null }];
  tables.scan_results = [{
    data: [
      { scan_id: "s-a2", score: 45, findings: [{ checkId: "hsts", severity: "high", title: "Missing HSTS", detail: "d" }] },
      { scan_id: "s-b", score: 82, findings: [{ checkId: "hsts", severity: "high", title: "Missing HSTS", detail: "d" }, { checkId: "fp", severity: "critical", title: "Not real", detail: "d" }] },
    ],
    error: null,
  }];
}

describe("GET /api/portfolio-report", () => {
  beforeEach(() => {
    for (const k of Object.keys(tables)) delete tables[k];
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    checkRateLimitMock.mockReset().mockResolvedValue({ allowed: true, retryAfterSeconds: 0 });
    setContent.mockReset();
  });

  it("answers 405, 401, and 403 plan_required below an active Agency plan", async () => {
    const post = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(post.req, post.res);
    expect(post.res._getStatusCode()).toBe(405);

    authenticateApiRequestMock.mockResolvedValueOnce(null);
    const anon = get();
    await handler(anon.req, anon.res);
    expect(anon.res._getStatusCode()).toBe(401);

    tables.subscriptions = [{ data: { plan: "agency", status: "cancelled" }, error: null }];
    const cancelled = get();
    await handler(cancelled.req, cancelled.res);
    expect(cancelled.res._getStatusCode()).toBe(403);
    expect(JSON.parse(cancelled.res._getData()).code).toBe("plan_required");
    expect(checkRateLimitMock).not.toHaveBeenCalled();
  });

  it("is rate-limited before any data is read", async () => {
    agency();
    checkRateLimitMock.mockResolvedValue({ allowed: false, retryAfterSeconds: 30 });
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(429);
    expect(tables.monitored_targets).toBeUndefined();
  });

  it("says so when there are no monitored sites", async () => {
    agency();
    tables.monitored_targets = [{ data: [], error: null }];
    tables.scans = [{ data: [], error: null }];
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(404);
    expect(JSON.parse(res._getData()).code).toBe("no_sites");
  });

  it("answers 500 when the sites can't be read", async () => {
    agency();
    tables.monitored_targets = [{ data: null, error: { message: "down" } }];
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(500);
    log.mockRestore();
  });

  it("answers 500 when scans or results can't be read, but carries on without triage", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    agency();
    portfolio();
    tables.scans = [{ data: null, error: { message: "scans down" } }];
    const scans = get({ format: "html" });
    await handler(scans.req, scans.res);
    expect(scans.res._getStatusCode()).toBe(500);

    for (const k of Object.keys(tables)) delete tables[k];
    agency();
    portfolio();
    tables.scan_results = [{ data: null, error: { message: "results down" } }];
    const results = get({ format: "html" });
    await handler(results.req, results.res);
    expect(results.res._getStatusCode()).toBe(500);

    for (const k of Object.keys(tables)) delete tables[k];
    agency();
    portfolio();
    tables.finding_triage = [{ data: null, error: { message: "triage down" } }];
    const noTriage = get({ format: "html" });
    await handler(noTriage.req, noTriage.res);
    expect(noTriage.res._getStatusCode()).toBe(200);
    // Without triage the false positive is counted like any open finding.
    expect(String(noTriage.res._getData())).toContain("Not real");
    expect(log).toHaveBeenCalledWith("[portfolio-report] triage load failed:", "triage down");
    log.mockRestore();
  });

  it("builds the report from each monitored site's latest scan, matched by hostname, with triage applied", async () => {
    agency();
    portfolio();
    const { req, res } = get({ format: "html" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res._getHeaders()["content-type"]).toBe("text/html; charset=utf-8");
    const html = String(res._getData());
    // Three sites: a.example once despite two spellings, b.example, and new.example with no scan.
    expect(html).toContain("3 sites · generated");
    expect(html).toContain("1 site has no completed scan yet");
    expect(html).not.toContain("not-monitored.example");
    // a.example uses its latest scan (45), not the older one.
    expect(html.indexOf("a.example")).toBeLessThan(html.indexOf("b.example"));
    expect(html).toContain("<b>45</b>");
    // The false positive on b.example is not counted or listed.
    expect(html).not.toContain("Not real");
    expect(html).toContain("2 of 2: a.example, b.example");
  });

  describe("?client=", () => {
    it("404s for a client the caller does not own, and 500s if the lookup fails", async () => {
      agency();
      tables.clients = [{ data: null, error: null }];
      const missing = get({ format: "html", client: "nope" });
      await handler(missing.req, missing.res);
      expect(missing.res._getStatusCode()).toBe(404);
      expect(JSON.parse(missing.res._getData()).code).toBe("client_not_found");

      agency();
      tables.clients = [{ data: null, error: { message: "down" } }];
      const failed = get({ format: "html", client: "c1" });
      await handler(failed.req, failed.res);
      expect(failed.res._getStatusCode()).toBe(500);
    });

    it("reports on the client's sites and brands it with the client's override over the account brand", async () => {
      agency();
      portfolio({ brand_name: "Agency Co", brand_logo_url: "https://agency.test/logo.png" });
      tables.clients = [
        { data: { id: "c1" }, error: null },
        { data: { brand_name: "Client Brand", brand_logo_url: null }, error: null },
      ];
      const { req, res } = get({ format: "html", client: "c1" });
      await handler(req, res);
      expect(res._getStatusCode()).toBe(200);
      const html = String(res._getData());
      expect(html).toContain("Client Brand");
      expect(html).not.toContain("Agency Co");
      expect(html).toContain("https://agency.test/logo.png"); // logo falls back to the account's
    });

    it("falls back to the account brand when the client has no override", async () => {
      agency();
      portfolio({ brand_name: "Agency Co" });
      tables.clients = [
        { data: { id: "c1" }, error: null },
        { data: null, error: null },
      ];
      const { req, res } = get({ format: "html", client: "c1" });
      await handler(req, res);
      expect(String(res._getData())).toContain("Agency Co");
    });
  });

  it("streams a white-labelled PDF named without our brand", async () => {
    agency();
    portfolio({ brand_name: "Acme Digital" });
    const { req, res } = get();
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect(res._getHeaders()["content-type"]).toBe("application/pdf");
    expect(res._getHeaders()["content-disposition"]).toMatch(/^attachment; filename="security-portfolio-\d{4}-\d{2}-\d{2}\.pdf"$/);
    expect(String(res._getData())).toBe("%PDF-stub");
    const rendered = setContent.mock.calls[0][0] as string;
    expect(rendered).toContain("Acme Digital");
    expect(rendered).not.toMatch(/Hebrides/i);
  });
});
