import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const m = vi.hoisted(() => ({ view: vi.fn(), targets: vi.fn() }));
vi.mock("./findingsView", async (o) => ({ ...(await o<typeof import("./findingsView")>()), loadFindingsView: m.view }));
vi.mock("./estatePriority", async (o) => ({ ...(await o<typeof import("./estatePriority")>()), loadTargetContexts: m.targets }));

import { loadEstateMap } from "./estateMap";
import { loadEvidencePack } from "./evidencePack";

type R = { data: unknown; error: unknown };
function client(tables: Record<string, R>) {
  return {
    from: (t: string) => {
      const r = tables[t] ?? { data: [], error: null };
      const q: Record<string, unknown> = {
        select: () => q, eq: () => q, order: () => q, limit: () => q,
        maybeSingle: async () => r,
        then: (res: (v: unknown) => void) => res(r),
      };
      return q;
    },
  } as unknown as SupabaseClient;
}

const row = (over: Record<string, unknown>) => ({ key: "k", host: "www.example.com", checkId: "tls.expiring", checkBase: "tls.expiring", category: "tls", severity: "high", title: "t", triage: null, ...over });

beforeEach(() => {
  m.view.mockReset().mockResolvedValue({ ok: true, data: { rows: [row({})], detailByHost: new Map() } });
  m.targets.mockReset().mockResolvedValue({ contexts: new Map() });
});

describe("loadEstateMap", () => {
  it("builds the map from inventory, the latest scans and open findings", async () => {
    const out = await loadEstateMap(
      client({
        asset_inventory: { data: [{ hostname: "www.example.com", kind: "domain", first_seen_at: "2026-10-01T00:00:00Z", last_seen_at: "2026-11-19T00:00:00Z" }], error: null },
        scans: { data: [{ id: "s1", target_url: "https://www.example.com", created_at: "2026-11-19T00:00:00Z", scan_results: [{ httpx: [{ url: "https://www.example.com", host: "www.example.com", status_code: 200, title: "Shop" }], tls: { status: "checked", certificateExpiresAt: "2026-12-01T00:00:00Z", daysUntilExpiry: 11, issuer: "LE" } }] }], error: null },
      }),
      "o"
    );
    expect(out.ok).toBe(true);
    if (out.ok) {
      expect(out.map.totals.hosts).toBe(1);
      expect(out.map.domains[0].hosts[0]).toMatchObject({ host: "www.example.com", scanId: "s1" });
    }
  });

  it("copes with scan results as an object, or missing", async () => {
    const out = await loadEstateMap(
      client({
        asset_inventory: { data: [], error: null },
        scans: { data: [{ id: "s1", target_url: "https://a.example.com", created_at: "t", scan_results: { httpx: "not a list", tls: null } }, { id: "s2", target_url: "https://b.example.com", created_at: "t", scan_results: null }], error: null },
      }),
      "o"
    );
    expect(out.ok).toBe(true);
  });

  it("fails when any read fails", async () => {
    expect(await loadEstateMap(client({ asset_inventory: { data: null, error: { message: "inv" } } }), "o")).toEqual({ ok: false, error: "inv" });
    expect(await loadEstateMap(client({ scans: { data: null, error: { message: "scans" } } }), "o")).toEqual({ ok: false, error: "scans" });
    m.view.mockResolvedValue({ ok: false, error: "view" });
    expect(await loadEstateMap(client({}), "o")).toEqual({ ok: false, error: "view" });
  });
});

describe("loadEvidencePack", () => {
  it("gathers sites, self-assessment answers and M365/Workspace checks, dropping false positives", async () => {
    m.view.mockResolvedValue({ ok: true, data: { rows: [row({}), row({ key: "fp", triage: { state: "false_positive", reason: "r", expiresAt: null } })], detailByHost: new Map() } });
    const pack = await loadEvidencePack(
      client({
        ce_self_assessment: { data: [{ question_key: "fw-default-passwords", answer: "yes", note: null }], error: null },
        users: { data: { company_name: "Acme Ltd" }, error: null },
        scans: { data: [{ target_url: "https://www.example.com", created_at: "2026-11-19T00:00:00Z" }, { target_url: "https://www.example.com", created_at: "2026-11-01T00:00:00Z" }, { target_url: "not a url", created_at: "x" }], error: null },
        m365_tenants: { data: { last_checked_at: "2026-11-18T00:00:00Z" }, error: null },
        workspace_connections: { data: null, error: null },
      }),
      "o",
      new Date("2026-11-20T00:00:00Z")
    );
    expect(pack.company).toBe("Acme Ltd");
    expect(pack.generatedAt).toBe("2026-11-20T00:00:00.000Z");
    expect(JSON.stringify(pack)).toContain("www.example.com");
  });

  it("throws when the findings can't be read", async () => {
    m.view.mockResolvedValue({ ok: false, error: "view" });
    await expect(loadEvidencePack(client({}), "o")).rejects.toThrow("view");
  });
});
