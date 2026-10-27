import { describe, it, expect } from "vitest";
import {
  clientName,
  filterByScope,
  groupByClient,
  groupBySite,
  inScope,
  parseScope,
  rollupScore,
  SCOPE_ALL,
  SCOPE_UNASSIGNED,
  type SiteRow,
} from "./clientRollup";

const clients = [
  { id: "c1", name: "Acme" },
  { id: "c2", name: "Beta" },
  { id: "c3", name: "Empty" },
];

function site(id: string, clientId: string | null, over: Partial<SiteRow> = {}): SiteRow {
  return { targetId: id, targetUrl: `https://${id}.test`, clientId, latestScore: null, lastScannedAt: null, openFindingsCount: null, ...over };
}

describe("parseScope", () => {
  it("defaults empty and unknown values to all", () => {
    expect(parseScope(null, clients)).toBe(SCOPE_ALL);
    expect(parseScope(undefined, clients)).toBe(SCOPE_ALL);
    expect(parseScope("all", clients)).toBe(SCOPE_ALL);
    expect(parseScope("deleted-client", clients)).toBe(SCOPE_ALL);
  });
  it("accepts unassigned and a known client id", () => {
    expect(parseScope("unassigned", clients)).toBe(SCOPE_UNASSIGNED);
    expect(parseScope("c2", clients)).toBe("c2");
  });
});

describe("inScope / filterByScope", () => {
  const rows = [site("a", "c1"), site("b", "c2"), site("c", null)];
  it("all keeps everything", () => {
    expect(filterByScope(rows, SCOPE_ALL)).toHaveLength(3);
    expect(inScope(undefined, SCOPE_ALL)).toBe(true);
  });
  it("unassigned keeps rows without a client", () => {
    expect(filterByScope(rows, SCOPE_UNASSIGNED).map((r) => r.targetId)).toEqual(["c"]);
    expect(inScope(undefined, SCOPE_UNASSIGNED)).toBe(true);
  });
  it("a client id keeps only that client", () => {
    expect(filterByScope(rows, "c1").map((r) => r.targetId)).toEqual(["a"]);
    expect(inScope(null, "c1")).toBe(false);
  });
});

describe("rollupScore", () => {
  it("averages real scores, rounded, ignoring nulls", () => {
    expect(rollupScore([80, 61, null])).toBe(71);
  });
  it("is null with nothing scanned", () => {
    expect(rollupScore([])).toBeNull();
    expect(rollupScore([null, null])).toBeNull();
  });
  it("counts a zero score", () => {
    expect(rollupScore([0, 100])).toBe(50);
  });
});

describe("groupByClient", () => {
  const sites = [
    site("a1", "c1", { latestScore: 90, openFindingsCount: 1, openCriticalCount: 0, lastScannedAt: "2026-10-01T00:00:00Z" }),
    site("a2", "c1", { latestScore: 50, openFindingsCount: 4, openCriticalCount: 2, lastScannedAt: "2026-10-05T00:00:00Z" }),
    site("b1", "c2", { latestScore: 40, openFindingsCount: 2 }),
    site("u1", null, { latestScore: 100, openFindingsCount: 0 }),
    site("orphan", "deleted", {}),
  ];
  const groups = groupByClient(sites, clients);

  it("rolls up score, findings, criticals and last scan per client", () => {
    const acme = groups.find((g) => g.clientId === "c1")!;
    expect(acme.rollupScore).toBe(70);
    expect(acme.openFindings).toBe(5);
    expect(acme.openCriticals).toBe(2);
    expect(acme.lastScannedAt).toBe("2026-10-05T00:00:00Z");
    expect(acme.sites).toHaveLength(2);
  });

  it("orders worst roll-up first, unscanned clients next, Unassigned last", () => {
    expect(groups.map((g) => g.name)).toEqual(["Beta", "Acme", "Empty", "Unassigned"]);
  });

  it("keeps clients with no sites, unscanned", () => {
    const empty = groups.find((g) => g.clientId === "c3")!;
    expect(empty.sites).toEqual([]);
    expect(empty.rollupScore).toBeNull();
    expect(empty.lastScannedAt).toBeNull();
  });

  it("treats sites pointing at a deleted client as unassigned", () => {
    const loose = groups.find((g) => g.clientId === null)!;
    expect(loose.sites.map((s) => s.targetId).sort()).toEqual(["orphan", "u1"]);
  });

  it("omits Unassigned when every site has a client", () => {
    expect(groupByClient([site("a", "c1")], clients).some((g) => g.clientId === null)).toBe(false);
  });

  it("breaks score ties and unscanned ties by name", () => {
    const g = groupByClient(
      [site("x", "c1", { latestScore: 60 }), site("y", "c2", { latestScore: 60 })],
      clients,
    );
    expect(g.map((x) => x.name)).toEqual(["Acme", "Beta", "Empty"]);
    const none = groupByClient([], [clients[1], clients[0]]);
    expect(none.map((x) => x.name)).toEqual(["Acme", "Beta"]);
  });

  it("handles no clients at all", () => {
    const g = groupByClient([site("a", null)], []);
    expect(g).toHaveLength(1);
    expect(g[0].name).toBe("Unassigned");
  });

  it("ignores null last-scanned dates and picks the newest otherwise", () => {
    const g = groupByClient(
      [site("a", "c1", { lastScannedAt: null }), site("b", "c1", { lastScannedAt: "2026-01-01T00:00:00Z" }), site("c", "c1", { lastScannedAt: "2025-01-01T00:00:00Z" })],
      clients,
    );
    expect(g.find((x) => x.clientId === "c1")!.lastScannedAt).toBe("2026-01-01T00:00:00Z");
  });
});

describe("clientName", () => {
  it("resolves a name, falling back to Unassigned", () => {
    expect(clientName("c1", clients)).toBe("Acme");
    expect(clientName(null, clients)).toBe("Unassigned");
    expect(clientName("gone", clients)).toBe("Unassigned");
  });
});

describe("groupBySite", () => {
  it("groups by host, sorted, with unknown for unparseable rows", () => {
    const rows = [{ h: "b.test" }, { h: "a.test" }, { h: "b.test" }, { h: null as string | null }];
    const g = groupBySite(rows, (r) => r.h);
    expect(g.map((x) => [x.host, x.rows.length])).toEqual([["a.test", 1], ["b.test", 2], ["unknown", 1]]);
  });
});

describe("groupByClient ordering with an unscanned client listed first", () => {
  it("sinks unscanned clients below scanned ones regardless of input order", () => {
    const g = groupByClient([site("a", "c2", { latestScore: 70 })], [clients[2], clients[1], clients[0]]);
    expect(g.map((x) => x.name)).toEqual(["Beta", "Acme", "Empty"]);
  });
});
