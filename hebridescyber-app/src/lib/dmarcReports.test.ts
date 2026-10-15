import { describe, it, expect, vi } from "vitest";
import { toReportInsert, resolveIngestToken } from "./dmarcReports";
import type { DmarcAggregateReport } from "./dmarcAggregate";

const base: DmarcAggregateReport = {
  orgName: "google.com",
  reportId: "rpt-1",
  domain: "Example.com",
  dateBegin: 1696118400,
  dateEnd: 1696204800,
  rows: [{ sourceIp: "1.2.3.4", count: 10, disposition: "none", dkim: "pass", spf: "pass", headerFrom: "example.com" }],
  totalMessages: 10,
  passingMessages: 10,
  failingMessages: 0,
};

describe("toReportInsert", () => {
  it("maps a parsed report to a row, lowercasing the domain and converting dates to ISO", () => {
    const row = toReportInsert("owner-1", base, "fallback.com");
    expect(row.owner).toBe("owner-1");
    expect(row.domain).toBe("example.com");
    expect(row.report_id).toBe("rpt-1");
    expect(row.date_begin).toBe(new Date(1696118400 * 1000).toISOString());
    expect(row.total_messages).toBe(10);
    expect(row.passing_messages).toBe(10);
    expect(row.rows).toHaveLength(1);
  });

  it("uses the fallback domain when the report omits its policy domain", () => {
    const row = toReportInsert("o", { ...base, domain: null }, "Fallback.CO.UK");
    expect(row.domain).toBe("fallback.co.uk");
  });

  it("synthesises a deterministic report_id when one is missing (idempotent re-POST)", () => {
    const a = toReportInsert("o", { ...base, reportId: null }, "x.com");
    const b = toReportInsert("o", { ...base, reportId: null }, "x.com");
    expect(a.report_id).toBe(b.report_id);
    expect(a.report_id).toHaveLength(32);
  });

  it("null dates map to null, not epoch", () => {
    const row = toReportInsert("o", { ...base, dateBegin: null, dateEnd: null }, "x.com");
    expect(row.date_begin).toBeNull();
    expect(row.date_end).toBeNull();
  });
});

describe("resolveIngestToken", () => {
  function stub(owner: string | null) {
    return {
      from: () => ({ select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: owner ? { owner } : null }) }) }) }),
    } as unknown as import("@supabase/supabase-js").SupabaseClient;
  }

  it("resolves a known token to its owner", async () => {
    expect(await resolveIngestToken(stub("owner-9"), "a-sufficiently-long-token")).toBe("owner-9");
  });
  it("returns null for an unknown token", async () => {
    expect(await resolveIngestToken(stub(null), "another-long-token-value")).toBeNull();
  });
  it("rejects an empty or too-short token without querying", async () => {
    const db = { from: vi.fn() } as unknown as import("@supabase/supabase-js").SupabaseClient;
    expect(await resolveIngestToken(db, "")).toBeNull();
    expect(await resolveIngestToken(db, "short")).toBeNull();
    expect(db.from).not.toHaveBeenCalled();
  });
});
