import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock } = vi.hoisted(() => ({ authenticateApiRequestMock: vi.fn() }));

// Minimal chainable Supabase query-builder stub, matching the pattern used
// in src/lib/freeTier.test.ts — every chain method returns itself, and the
// chain resolves to `result` at .maybeSingle(). Table-keyed so the two
// sequential .from() calls in export.ts (scans, then scan_results) can
// return different canned results.
function makeQueryBuilder(result: unknown) {
  const builder: Record<string, unknown> = {
    select: () => builder,
    eq: () => builder,
    order: () => builder,
    limit: () => builder,
    maybeSingle: () => Promise.resolve(result),
    // finding_triage is read as a list (awaited directly), not .maybeSingle().
    then: (resolve: (v: unknown) => unknown) => Promise.resolve(result ?? { data: [], error: null }).then(resolve),
  };
  return builder;
}

let supabaseTables: Record<string, unknown> = {};

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: {
    from: (table: string) => makeQueryBuilder(supabaseTables[table]),
  },
}));

import handler from "@/pages/api/v1/scans/[id]/export";

function mockReqRes(query: Record<string, string>) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "GET",
    query,
    headers: { authorization: "Bearer test-token" },
  });
}

describe("GET /api/v1/scans/[id]/export", () => {
  beforeEach(() => {
    authenticateApiRequestMock.mockReset();
    supabaseTables = {};
  });

  it("rejects non-GET methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "POST" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 401 when the caller is not authenticated", async () => {
    authenticateApiRequestMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(401);
  });

  it("returns 404 when the scan does not exist", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: null };
    const { req, res } = mockReqRes({ id: "missing-scan" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(404);
    expect(res._getJSONData()).toEqual({ error: "Scan not found" });
  });

  it("returns 403 when the caller does not own the scan", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "someone-else", target_url: "https://example.com" } };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 404 when the scan has no results yet", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = { data: null };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(404);
    expect(res._getJSONData()).toEqual({ error: "No results for this scan yet" });
  });

  it("exports findings as CSV by default, with a header row and escaped fields", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = {
      data: {
        results: {
          findings: [
            {
              severity: "high",
              title: 'Finding with a "quote", and a comma',
              detail: "detail",
              checkId: "tls.grade",
              cveIds: ["CVE-2024-1", "CVE-2024-2"],
              complianceRefs: [{ framework: "owasp-top-10", control: "A03:2021 – Injection" }],
              corroboratedBy: [{ tool: "ZAP", checkId: "zap.alert:x", title: "[ZAP] x" }, { tool: "nuclei", checkId: "nuclei.finding:y", title: "[Nuclei] y" }],
            },
          ],
        },
      },
    };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("text/csv; charset=utf-8");
    expect(res.getHeader("Content-Disposition")).toContain("example.com-findings.csv");

    const body = res._getData() as string;
    const lines = body.split("\r\n");
    expect(lines[0]).toBe("severity,title,detail,check_id,cve_ids,cvss_score,cvss_vector,known_exploited,epss,compliance_refs,triage_state,triage_reason,triage_expires_at,corroborated_by");
    // Embedded quote/comma must be CSV-escaped (doubled quotes, wrapped in quotes).
    expect(lines[1]).toContain('"Finding with a ""quote"", and a comma"');
    expect(lines[1]).toContain("CVE-2024-1; CVE-2024-2");
    expect(lines[1]).toContain("owasp-top-10: A03:2021 – Injection");
    expect(lines[1]).toContain("ZAP: [ZAP] x; nuclei: [Nuclei] y");
  });

  // Titles quote text from the scanned site — a hostile site must not be able
  // to plant a formula that runs when the customer opens the export.
  it("neutralises spreadsheet formulas in CSV cells", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = {
      data: { results: { findings: [{ severity: "low", title: '=HYPERLINK("http://evil")', detail: "d" }] } },
    };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    const row = (res._getData() as string).split("\r\n")[1];
    expect(row).toContain(`"'=HYPERLINK(""http://evil"")"`);
  });

  it("exports findings as JSON when format=json", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = {
      data: { results: { findings: [{ severity: "low", title: "t", detail: "d" }] } },
    };
    const { req, res } = mockReqRes({ id: "scan-1", format: "json" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Disposition")).toContain("example.com-findings.json");
    expect(res._getJSONData()).toEqual({
      scan_id: "scan-1",
      target_url: "https://example.com",
      findings: [{ severity: "low", title: "t", detail: "d", triage: null }],
    });
  });

  it("adds the owner's current triage as columns (CSV) and a field (JSON)", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://Example.com/shop" } };
    supabaseTables.scan_results = {
      data: {
        results: {
          findings: [
            { severity: "high", title: "Triaged", detail: "d", checkId: "headers.csp-absent" },
            { severity: "low", title: "Expired", detail: "d", checkId: "dns.dmarc-missing" },
            { severity: "low", title: "Untriaged", detail: "d", checkId: "tls.grade" },
          ],
        },
      },
    };
    const future = new Date(Date.now() + 7 * 86_400_000).toISOString();
    const past = new Date(Date.now() - 86_400_000).toISOString();
    const triageRow = (check_id: string, state: string, expires_at: string | null, reason: string) => ({
      id: check_id, owner: "owner-1", target_host: "example.com", check_id, state, reason, expires_at,
      created_by: "owner-1", created_at: past, updated_at: past,
    });
    supabaseTables.finding_triage = {
      data: [
        triageRow("headers.csp-absent", "snoozed", future, "=cmd|' /C calc'!A0 fix in sprint"),
        triageRow("dns.dmarc-missing", "snoozed", past, "old"),
      ],
      error: null,
    };

    const csv = mockReqRes({ id: "scan-1" });
    await handler(csv.req, csv.res);
    const lines = (csv.res._getData() as string).split("\r\n");
    // The reason is the customer's own text — formula-neutralised like titles.
    expect(lines[1]).toContain(`,snoozed,'=cmd|' /C calc'!A0 fix in sprint,${future}`);
    expect(lines[2].endsWith(",,,")).toBe(true);
    expect(lines[3].endsWith(",,,")).toBe(true);

    const json = mockReqRes({ id: "scan-1", format: "json" });
    await handler(json.req, json.res);
    const body = json.res._getJSONData() as { findings: Array<{ triage: unknown }> };
    expect(body.findings.map((f) => f.triage)).toEqual([
      { state: "snoozed", reason: "=cmd|' /C calc'!A0 fix in sprint", expiresAt: future, triagedAt: past },
      null,
      null,
    ]);
  });

  it("still exports, untriaged, before migration 046", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = { data: { results: { findings: [{ severity: "low", title: "t", detail: "d", checkId: "x.y" }] } } };
    supabaseTables.finding_triage = { data: null, error: { code: "42P01", message: "relation does not exist" } };
    const { req, res } = mockReqRes({ id: "scan-1", format: "json" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(200);
    expect((res._getJSONData() as { findings: Array<{ triage: unknown }> }).findings[0].triage).toBeNull();
  });

  it("handles a scan with zero findings without erroring", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://example.com" } };
    supabaseTables.scan_results = { data: { results: {} } };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect((res._getData() as string).split("\r\n")).toEqual(["severity,title,detail,check_id,cve_ids,cvss_score,cvss_vector,known_exploited,epss,compliance_refs,triage_state,triage_reason,triage_expires_at,corroborated_by"]);
  });

  it("sanitises the target URL into a filesystem-safe filename", async () => {
    authenticateApiRequestMock.mockResolvedValue({ ownerId: "owner-1", via: "session" });
    supabaseTables.scans = { data: { id: "scan-1", owner: "owner-1", target_url: "https://sub.example.com:8443/path?x=1" } };
    supabaseTables.scan_results = { data: { results: { findings: [] } } };
    const { req, res } = mockReqRes({ id: "scan-1" });

    await handler(req, res);

    const disposition = res.getHeader("Content-Disposition") as string;
    expect(disposition).not.toMatch(/[:/?]/);
  });
});
