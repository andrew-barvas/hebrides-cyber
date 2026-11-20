import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const m = vi.hoisted(() => ({
  view: vi.fn(),
  targets: vi.fn(),
  drift: vi.fn(),
  lookalikes: vi.fn(),
  breaches: vi.fn(),
}));
vi.mock("./findingsView", async (o) => ({ ...(await o<typeof import("./findingsView")>()), loadFindingsView: m.view }));
vi.mock("./estatePriority", async (o) => ({ ...(await o<typeof import("./estatePriority")>()), loadTargetContexts: m.targets }));
vi.mock("./estateDrift", async (o) => ({ ...(await o<typeof import("./estateDrift")>()), loadEstateDrift: m.drift }));
vi.mock("./lookoutLookalikes", async (o) => ({ ...(await o<typeof import("./lookoutLookalikes")>()), loadReportLookalikes: m.lookalikes }));
vi.mock("./lookoutBreaches", async (o) => ({ ...(await o<typeof import("./lookoutBreaches")>()), loadReportBreaches: m.breaches }));

import { loadDraftInputs } from "./lookoutReports";

const db = {} as SupabaseClient;

describe("loadDraftInputs", () => {
  beforeEach(() => {
    m.view.mockReset().mockResolvedValue({ ok: true, data: { rows: [], detailByHost: new Map() } });
    m.targets.mockReset().mockResolvedValue({ contexts: new Map() });
    m.drift.mockReset().mockResolvedValue({ ok: true, available: true, drift: { opened: { total: 1 }, fixed: { total: 2 }, openNow: { total: 3 }, newHosts: [] } });
    m.lookalikes.mockReset().mockResolvedValue({ available: true, newInPeriod: [{ domain: "exmple.com" }], totalKnown: 1 });
    m.breaches.mockReset().mockResolvedValue({ available: false, sites: [] });
  });

  it("joins the drift and lookalike sentences into the draft summary for the period", async () => {
    const out = await loadDraftInputs(db, "c1", 30);
    expect(out.items).toEqual([]);
    expect(out.summary).toContain("1 new issue appeared and 2 were fixed; 3 remain open.");
    expect(out.summary).toContain("exmple.com");
    const [, , start, end] = m.lookalikes.mock.calls[0];
    expect((Date.parse(end) - Date.parse(start)) / 86_400_000).toBe(30);
  });

  it("still drafts when the findings view or drift can't be read", async () => {
    m.view.mockResolvedValue({ ok: false, error: "x" });
    m.drift.mockResolvedValue({ ok: false });
    m.lookalikes.mockResolvedValue({ available: true, newInPeriod: [], totalKnown: 0 });
    expect(await loadDraftInputs(db, "c1", 7)).toEqual({ items: [], summary: "" });
  });
});
