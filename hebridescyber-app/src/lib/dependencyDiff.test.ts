import { describe, it, expect, vi, beforeEach } from "vitest";

const { queryMock, detailsMock } = vi.hoisted(() => ({ queryMock: vi.fn(), detailsMock: vi.fn() }));
vi.mock("./scanners/osv", async (orig) => ({
  ...(await orig<typeof import("./scanners/osv")>()),
  queryOsvBatch: queryMock,
  fetchOsvVulnDetails: detailsMock,
}));

import { computeDependencyDiff, diffLockfiles, MAX_INTRODUCED_QUERIED, type DiffFileInput } from "./dependencyDiff";

const npmLock = (pkgs: Record<string, string>, direct: string[] = Object.keys(pkgs)) =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: Object.fromEntries(direct.map((d) => [d, "*"])) },
      ...Object.fromEntries(Object.entries(pkgs).map(([n, v]) => [`node_modules/${n}`, { version: v }])),
    },
  });
const manifest = (direct: string[]) => JSON.stringify({ dependencies: Object.fromEntries(direct.map((d) => [d, "*"])) });

const file = (over: Partial<DiffFileInput> = {}): DiffFileInput => ({ name: "package-lock.json", base: npmLock({ a: "1.0.0" }), head: npmLock({ a: "1.0.0", lodash: "4.17.0" }), ...over });

const advisory = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  aliases: ["CVE-2021-1234"],
  summary: "Prototype pollution",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
  ...over,
});

beforeEach(() => {
  queryMock.mockReset();
  detailsMock.mockReset();
});

describe("diffLockfiles", () => {
  it("reports only packages head adds, counting removals", () => {
    const { introduced, results } = diffLockfiles([file({ base: npmLock({ a: "1.0.0", gone: "1.0.0" }) })]);
    expect(introduced.map((i) => `${i.pkg.name}@${i.pkg.version}`)).toEqual(["lodash@4.17.0"]);
    expect(results[0]).toMatchObject({ status: "ok", ecosystem: "npm", packages_added: 1, packages_removed: 1 });
  });

  it("treats a changed version as introduced and ignores unchanged ones", () => {
    const { introduced } = diffLockfiles([file({ base: npmLock({ a: "1.0.0", lodash: "4.17.0" }), head: npmLock({ a: "1.0.0", lodash: "4.17.5" }) })]);
    expect(introduced.map((i) => i.pkg.version)).toEqual(["4.17.5"]);
  });

  it("counts every package as introduced when the lockfile is new, and none when it is deleted", () => {
    const added = diffLockfiles([file({ base: null })]);
    expect(added.results[0].base_missing).toBe(true);
    expect(added.introduced).toHaveLength(2);
    const deleted = diffLockfiles([file({ head: null })]);
    expect(deleted.introduced).toEqual([]);
    expect(deleted.results[0]).toMatchObject({ status: "ok", packages_removed: 1 });
  });

  it("marks direct and transitive packages", () => {
    const direct = diffLockfiles([file({ head: npmLock({ a: "1.0.0", lodash: "4.17.0" }, ["a", "lodash"]), head_companion: manifest(["a", "lodash"]) })]);
    expect(direct.introduced[0].pkg.direct).toBe(true);
    const transitive = diffLockfiles([file({ head: npmLock({ a: "1.0.0", lodash: "4.17.0" }, ["a"]), head_companion: manifest(["a"]) })]);
    expect(transitive.introduced[0].pkg.direct).toBe(false);
  });

  it("reports unsupported and unparseable lockfiles as errors, never as unchanged", () => {
    const { results, introduced } = diffLockfiles([
      file({ name: "README.md" }),
      file({ head: "{not json" }),
      file({ base: "{not json" }),
    ]);
    expect(results.map((r) => r.status)).toEqual(["error", "error", "error"]);
    expect(results[0].error).toContain("not a supported lockfile");
    expect(introduced).toEqual([]);
  });

  it("de-duplicates the same package from two lockfiles and accepts nested paths", () => {
    const { introduced, results } = diffLockfiles([file({ name: "web/package-lock.json" }), file({ name: "admin/package-lock.json" })]);
    expect(introduced).toHaveLength(2 - 1 + 0 + 1 - 1 + 0); // lodash from the first file only
    expect(results).toHaveLength(2);
    expect(results[1].packages_added).toBe(1);
  });
});

describe("computeDependencyDiff", () => {
  it("returns introduced vulnerabilities with severity, advisories and fixed version", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [["GHSA-1"]] });
    detailsMock.mockResolvedValue({ details: new Map([["GHSA-1", advisory("GHSA-1")]]), failed: [] });
    const result = await computeDependencyDiff([file({ head_companion: manifest(["lodash"]) })]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(queryMock).toHaveBeenCalledWith([{ ecosystem: "npm", name: "lodash", version: "4.17.0" }]);
    expect(result.complete).toBe(true);
    expect(result.packages_added).toBe(1);
    expect(result.counts).toEqual({ critical: 0, high: 1, medium: 0, low: 0 });
    expect(result.vulnerabilities[0]).toMatchObject({ name: "lodash", version: "4.17.0", severity: "high", fixed_version: "4.17.21", direct: true });
    expect(result.vulnerabilities[0].advisories[0].cve_ids[0]).toMatch(/^CVE-/);
  });

  it("does not query when nothing is introduced", async () => {
    const result = await computeDependencyDiff([file({ head: file().base })]);
    expect(queryMock).not.toHaveBeenCalled();
    expect(result).toMatchObject({ status: "completed", complete: true, vulnerabilities: [] });
  });

  it("is an error, not a clean result, when OSV.dev fails", async () => {
    queryMock.mockResolvedValue({ ok: false, error: "OSV.dev querybatch returned HTTP 503" });
    expect(await computeDependencyDiff([file()])).toEqual({ status: "error", error: "OSV.dev querybatch returned HTTP 503" });
  });

  it("is incomplete when a lockfile can't be read, but still checks the rest", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [[]] });
    const result = await computeDependencyDiff([file(), file({ name: "yarn.lock", head: "garbage \u0000" , base: "garbage \u0000" })]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.complete).toBe(false);
    expect(result.notes.join(" ")).toContain("couldn't be read");
  });

  it("drops withdrawn advisories, keeps unrated ones as medium and reports missing details", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [["GHSA-w"], ["GHSA-u", "GHSA-gone"]] });
    detailsMock.mockResolvedValue({
      details: new Map<string, unknown>([
        ["GHSA-w", advisory("GHSA-w", { withdrawn: "2026-01-01T00:00:00Z" })],
        ["GHSA-u", advisory("GHSA-u", { database_specific: {}, severity: undefined, summary: undefined })],
      ]),
      failed: ["GHSA-gone"],
    });
    const result = await computeDependencyDiff([file({ head: npmLock({ a: "1.0.0", lodash: "4.17.0", other: "1.0.0" }) })]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0]).toMatchObject({ name: "other", severity: "medium", fixed_version: null });
    expect(result.vulnerabilities[0].advisories.find((a) => a.id === "GHSA-gone")).toMatchObject({ severity: null, summary: null });
    expect(result.notes.join(" ")).toContain("GHSA-gone");
  });

  it("sorts by severity and caps what it queries, flagging the result incomplete", async () => {
    const many: Record<string, string> = {};
    for (let i = 0; i < MAX_INTRODUCED_QUERIED + 5; i++) many[`p${i}`] = "1.0.0";
    queryMock.mockImplementation(async (queries: unknown[]) => ({ ok: true, vulnIds: queries.map((_, i) => (i < 2 ? [`G${i}`] : [])) }));
    detailsMock.mockResolvedValue({
      details: new Map([["G0", advisory("G0", { database_specific: { severity: "LOW" } })], ["G1", advisory("G1", { database_specific: { severity: "CRITICAL" } })]]),
      failed: [],
    });
    const result = await computeDependencyDiff([file({ base: npmLock({}), head: npmLock(many) })]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(queryMock.mock.calls[0][0]).toHaveLength(MAX_INTRODUCED_QUERIED);
    expect(result.complete).toBe(false);
    expect(result.packages_added).toBe(MAX_INTRODUCED_QUERIED + 5);
    expect(result.vulnerabilities.map((v) => v.severity)).toEqual(["critical", "low"]);
  });

  it("takes the highest rating across advisories, orders ties by name, and reports dev and transitive context", async () => {
    const graphLock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: { a: "*" } },
        "node_modules/a": { version: "1.0.0", dependencies: { b: "*", c: "*" } },
        "node_modules/b": { version: "1.0.0", dev: true },
        "node_modules/c": { version: "1.0.0" },
      },
    });
    queryMock.mockImplementation(async (q: unknown[]) => ({ ok: true, vulnIds: q.map((_, i) => (i === 0 ? ["G-1-low", "G-2-high"] : ["G-1-low"])) }));
    detailsMock.mockResolvedValue({
      details: new Map([["G-1-low", advisory("G-1-low", { database_specific: { severity: "LOW" } })], ["G-2-high", advisory("G-2-high", { database_specific: { severity: "HIGH" } })]]),
      failed: [],
    });
    const result = await computeDependencyDiff([file({ base: npmLock({}), head: graphLock })]);
    if (result.status !== "completed") throw new Error("unexpected");
    const names = result.vulnerabilities.map((v) => `${v.severity}:${v.name}`);
    expect(names).toEqual(["high:a", "low:b", "low:c"]);
    const b = result.vulnerabilities.find((v) => v.name === "b");
    expect(b?.dev).toBe(true);
    expect(b?.introduced_via).toEqual(["a@1.0.0"]);
  });

  it("notes missing advisory details even when no id is named as failed", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [["G-1"]] });
    detailsMock.mockResolvedValue({ details: new Map(), failed: [] });
    const result = await computeDependencyDiff([file()]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.notes.join(" ")).toContain("1 advisories couldn't be fetched");
  });

  it("handles lockfiles that record no dev scope or dependency graph", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [["G-1"]] });
    detailsMock.mockResolvedValue({ details: new Map([["G-1", advisory("G-1")]]), failed: [] });
    const cargo = (pkgs: string[]) => pkgs.map((p) => `[[package]]\nname = "${p}"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`).join("\n");
    const result = await computeDependencyDiff([{ name: "Cargo.lock", base: cargo(["old"]), head: cargo(["old", "new"]) }]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.vulnerabilities[0]).toMatchObject({ ecosystem: "crates.io", name: "new", dev: null, introduced_via: null });
  });

  it("keeps the higher rating when a lower one follows it", async () => {
    queryMock.mockResolvedValue({ ok: true, vulnIds: [["G-1-high", "G-2-low"]] });
    detailsMock.mockResolvedValue({
      details: new Map([["G-1-high", advisory("G-1-high", { database_specific: { severity: "HIGH" } })], ["G-2-low", advisory("G-2-low", { database_specific: { severity: "LOW" } })]]),
      failed: [],
    });
    const result = await computeDependencyDiff([file()]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.vulnerabilities[0].severity).toBe("high");
  });
});

describe("parse budget", () => {
  it("skips files left over once the time budget is used up, reporting them as not checked", async () => {
    const { introduced, results } = diffLockfiles([file(), file({ name: "yarn.lock" })], -1);
    expect(introduced).toEqual([]);
    expect(results.map((r) => r.status)).toEqual(["error", "error"]);
    expect(results[0].error).toContain("time budget");
    queryMock.mockResolvedValue({ ok: true, vulnIds: [[]] });
    const result = await computeDependencyDiff([file()]);
    if (result.status !== "completed") throw new Error("unexpected");
    expect(result.complete).toBe(true);
  });

  it("survives pathological input (deep nesting) as a per-file error", () => {
    const deep = "[".repeat(100_000);
    const { results } = diffLockfiles([{ name: "Cargo.lock", base: null, head: deep }]);
    expect(results[0].status).toBe("error");
  });
});
