import { describe, it, expect, vi, afterEach } from "vitest";
import {
  cvss3BaseScore,
  extractCveIdsFromText,
  fetchOsvVulnDetails,
  lookupCveIds,
  lookupOsvFixInfo,
  npmPackageNameFor,
  osvSeverity,
  queryOsvBatch,
} from "./osv";

afterEach(() => vi.unstubAllGlobals());

let n = 0;
/** A unique package per test, so the module-level caches never cross tests. */
const pkg = () => `pkg-${++n}`;

function osvReturns(body: unknown, status = 200) {
  const fetchMock = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const range = (...events: Array<Record<string, string>>) => ({ type: "SEMVER", events });

describe("helpers", () => {
  it("maps display names to npm package names", () => {
    expect(npmPackageNameFor("jQuery")).toBe("jquery");
    expect(npmPackageNameFor("Unknown Lib")).toBeNull();
  });

  it("extracts de-duplicated, upper-cased CVE ids from text", () => {
    expect(extractCveIdsFromText("see cve-2020-11022 and CVE-2020-11022, also CVE-2019-11358")).toEqual(["CVE-2020-11022", "CVE-2019-11358"]);
  });
});

describe("lookupCveIds", () => {
  // OSV ids are often GHSA-…; the CVE is frequently only in aliases.
  it("collects CVEs from both id and aliases", async () => {
    osvReturns({ vulns: [{ id: "GHSA-aaaa", aliases: ["CVE-2020-1111"] }, { id: "CVE-2021-2222" }, { id: "OSV-3" }] });
    expect(await lookupCveIds("npm", pkg(), "1.0.0")).toEqual(["CVE-2020-1111", "CVE-2021-2222"]);
  });

  it("caches per package@version", async () => {
    const name = pkg();
    const fetchMock = osvReturns({ vulns: [{ id: "CVE-2020-1" }] });
    await lookupCveIds("npm", name, "1.0.0");
    await lookupCveIds("npm", name, "1.0.0");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns [] for an unknown version, a non-OK response or a network error", async () => {
    const fetchMock = osvReturns({ vulns: [{ id: "CVE-2020-1" }] });
    expect(await lookupCveIds("npm", pkg(), "unknown")).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
    osvReturns({}, 500);
    expect(await lookupCveIds("npm", pkg(), "1.0.0")).toEqual([]);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect(await lookupCveIds("npm", pkg(), "1.0.0")).toEqual([]);
  });
});

describe("lookupOsvFixInfo", () => {
  const affected = (name: string, ...ranges: unknown[]) => [{ package: { name, ecosystem: "npm" }, ranges }];

  it("returns the fixed version for a single vulnerability", async () => {
    const name = pkg();
    osvReturns({ vulns: [{ id: "GHSA-1", aliases: ["CVE-2020-8203"], affected: affected(name, range({ introduced: "0" }, { fixed: "4.17.21" })) }] });
    expect(await lookupOsvFixInfo("npm", name, "4.17.15")).toEqual({ cveIds: ["CVE-2020-8203"], osvIds: ["GHSA-1"], fixedVersion: "4.17.21" });
  });

  it("takes the highest fix across vulnerabilities, so every one is resolved", async () => {
    const name = pkg();
    osvReturns({
      vulns: [
        { id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "1.2.0" })) },
        { id: "GHSA-2", affected: affected(name, range({ introduced: "0" }, { fixed: "1.4.1" })) },
      ],
    });
    expect((await lookupOsvFixInfo("npm", name, "1.1.0")).fixedVersion).toBe("1.4.1");
  });

  // Regression: a 3.x package was told to jump to the 4.x fix.
  it("prefers the fix on the release branch the package is actually on", async () => {
    const name = pkg();
    osvReturns({
      vulns: [
        {
          id: "GHSA-1",
          affected: affected(name, range({ introduced: "0" }, { fixed: "3.10.2" }), range({ introduced: "4.0.0" }, { fixed: "4.17.21" })),
        },
      ],
    });
    expect((await lookupOsvFixInfo("npm", name, "3.10.0")).fixedVersion).toBe("3.10.2");
  });

  it("falls back to the highest fix when the current version can't be read", async () => {
    const name = pkg();
    osvReturns({ vulns: [{ id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "2.0.0" }), range({ introduced: "3.0.0" }, { fixed: "3.1.0" })) }] });
    expect((await lookupOsvFixInfo("npm", name, "nightly-build")).fixedVersion).toBe("3.1.0");
  });

  // Prereleases used to be unreadable, so they always got the highest fix.
  it("places a prerelease in its own branch", async () => {
    const name = pkg();
    osvReturns({ vulns: [{ id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "2.0.0" }), range({ introduced: "3.0.0" }, { fixed: "3.1.0" })) }] });
    expect((await lookupOsvFixInfo("npm", name, "1.0.0-beta.1")).fixedVersion).toBe("2.0.0");
  });

  it("never names a 'fix' at or below the installed version", async () => {
    const name = pkg();
    osvReturns({ vulns: [{ id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "1.5.0" }), range({ introduced: "2.0.0" }, { last_affected: "2.3.0" })) }] });
    expect((await lookupOsvFixInfo("npm", name, "2.1.0")).fixedVersion).toBeNull();
  });

  // Regression: only SEMVER ranges were read, so PyPI/Maven fix versions were lost.
  it("reads ECOSYSTEM ranges with the ecosystem's own ordering", async () => {
    const name = pkg();
    osvReturns({
      vulns: [
        {
          id: "PYSEC-1",
          affected: [{ package: { name: name.toUpperCase().replace("-", "_"), ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0rc1" }] }] }],
        },
        { id: "PYSEC-2", affected: [{ package: { name, ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0" }, { fixed: "1.9.post1" }] }] }] },
      ],
    });
    expect((await lookupOsvFixInfo("PyPI", name, "1.9")).fixedVersion).toBe("2.0rc1");
  });

  it("reads Maven ECOSYSTEM ranges", async () => {
    const name = `org.example:${pkg()}`;
    osvReturns({ vulns: [{ id: "GHSA-m", affected: [{ package: { name, ecosystem: "Maven" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "32.0.0-android" }] }] }] }] });
    expect((await lookupOsvFixInfo("Maven", name, "31.1-jre")).fixedVersion).toBe("32.0.0-android");
  });

  it("follows next_page_token so a long advisory list isn't cut off", async () => {
    const name = pkg();
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      const page = body.page_token
        ? { vulns: [{ id: "GHSA-2", aliases: ["CVE-2020-0002"], affected: affected(name, range({ introduced: "0" }, { fixed: "1.3.0" })) }] }
        : { vulns: [{ id: "GHSA-1", aliases: ["CVE-2020-0001"], affected: affected(name, range({ introduced: "0" }, { fixed: "1.1.0" })) }], next_page_token: "p2" };
      return new Response(JSON.stringify(page));
    });
    vi.stubGlobal("fetch", fetchMock);
    expect(await lookupOsvFixInfo("npm", name, "1.0.0")).toEqual({ cveIds: ["CVE-2020-0001", "CVE-2020-0002"], osvIds: ["GHSA-1", "GHSA-2"], fixedVersion: "1.3.0" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("returns empty when a later page fails, rather than a partial answer", async () => {
    const name = pkg();
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => (++call === 1 ? new Response(JSON.stringify({ vulns: [{ id: "GHSA-1" }], next_page_token: "p2" })) : new Response("{}", { status: 500 })))
    );
    expect(await lookupOsvFixInfo("npm", name, "1.0.0")).toEqual({ cveIds: [], osvIds: [], fixedVersion: null });
  });

  it("refuses to name a target when any vulnerability has no fixed version", async () => {
    const name = pkg();
    osvReturns({
      vulns: [
        { id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "1.2.0" })) },
        { id: "GHSA-2", affected: affected(name, range({ introduced: "0" }, { last_affected: "1.9.9" })) },
      ],
    });
    expect((await lookupOsvFixInfo("npm", name, "1.0.0")).fixedVersion).toBeNull();
  });

  it("ignores ranges for other packages in the same advisory", async () => {
    const name = pkg();
    osvReturns({
      vulns: [
        {
          id: "GHSA-1",
          affected: [
            { package: { name: `${name}-es`, ecosystem: "npm" }, ranges: [range({ introduced: "0" }, { fixed: "9.9.9" })] },
            ...affected(name, range({ introduced: "0" }, { fixed: "1.0.5" })),
          ],
        },
      ],
    });
    expect((await lookupOsvFixInfo("npm", name, "1.0.0")).fixedVersion).toBe("1.0.5");
  });

  it("returns an empty result when nothing is known or the lookup fails", async () => {
    osvReturns({ vulns: [] });
    expect(await lookupOsvFixInfo("npm", pkg(), "1.0.0")).toEqual({ cveIds: [], osvIds: [], fixedVersion: null });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect(await lookupOsvFixInfo("npm", pkg(), "1.0.0")).toEqual({ cveIds: [], osvIds: [], fixedVersion: null });
  });
});

describe("queryOsvBatch", () => {
  type Q = { package: { name: string }; version: string; page_token?: string };

  it("returns advisory ids per query, in order", async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("https://api.osv.dev/v1/querybatch");
      const { queries } = JSON.parse(String(init?.body)) as { queries: Q[] };
      return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "bad" ? { vulns: [{ id: "GHSA-x" }] } : {})) }));
    });
    vi.stubGlobal("fetch", fetchMock);
    const r = await queryOsvBatch([
      { ecosystem: "npm", name: "good", version: "1.0.0" },
      { ecosystem: "npm", name: "bad", version: "1.0.0" },
    ]);
    expect(r).toEqual({ ok: true, vulnIds: [[], ["GHSA-x"]] });
  });

  it("splits more than 1000 queries across requests", async () => {
    const sizes: number[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Q[] };
        sizes.push(queries.length);
        return new Response(JSON.stringify({ results: queries.map(() => ({})) }));
      })
    );
    const r = await queryOsvBatch(Array.from({ length: 1500 }, (_, i) => ({ ecosystem: "npm", name: `p${i}`, version: "1.0.0" })));
    expect(r.ok).toBe(true);
    expect(sizes).toEqual([1000, 500]);
  });

  it("follows each query's next_page_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        const { queries } = JSON.parse(String(init?.body)) as { queries: Q[] };
        return new Response(
          JSON.stringify({
            results: queries.map((q) =>
              q.page_token === "t2" ? { vulns: [{ id: "GHSA-2" }] } : q.package.name === "many" ? { vulns: [{ id: "GHSA-1" }], next_page_token: "t2" } : {}
            ),
          })
        );
      })
    );
    const r = await queryOsvBatch([
      { ecosystem: "npm", name: "few", version: "1.0.0" },
      { ecosystem: "npm", name: "many", version: "1.0.0" },
    ]);
    expect(r).toEqual({ ok: true, vulnIds: [[], ["GHSA-1", "GHSA-2"]] });
  });

  it("retries a 5xx once, then reports failure — never an empty result", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
    const r = await queryOsvBatch([{ ecosystem: "npm", name: "x", version: "1.0.0" }]);
    expect(r).toEqual({ ok: false, error: "OSV.dev querybatch returned HTTP 503" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("fails on a network error or a mismatched result count", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect((await queryOsvBatch([{ ecosystem: "npm", name: "x", version: "1.0.0" }])).ok).toBe(false);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ results: [] }))));
    expect(await queryOsvBatch([{ ecosystem: "npm", name: "x", version: "1.0.0" }])).toEqual({ ok: false, error: "OSV.dev querybatch returned 0 results for 1 queries" });
  });

  it("does not retry a 4xx", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 400 }));
    vi.stubGlobal("fetch", fetchMock);
    expect((await queryOsvBatch([{ ecosystem: "npm", name: "x", version: "1.0.0" }])).ok).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("fetchOsvVulnDetails", () => {
  it("fetches each id once, caches successes, and reports failures", async () => {
    const a = `GHSA-${pkg()}`;
    const b = `GHSA-${pkg()}`;
    const fetchMock = vi.fn(async (url: string) =>
      url.endsWith(a) ? new Response(JSON.stringify({ id: a, aliases: ["CVE-2020-1"] })) : new Response("{}", { status: 404 })
    );
    vi.stubGlobal("fetch", fetchMock);
    const first = await fetchOsvVulnDetails([a, b, a]);
    expect([...first.details.keys()]).toEqual([a]);
    expect(first.failed).toEqual([b]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await fetchOsvVulnDetails([a]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("treats a network error as a failure", async () => {
    const id = `GHSA-${pkg()}`;
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    expect((await fetchOsvVulnDetails([id])).failed).toEqual([id]);
  });
});

describe("severity", () => {
  it("computes CVSS v3 base scores", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBe(10);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3BaseScore("CVSS:4.0/AV:N")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L")).toBeNull();
  });

  it("prefers the advisory's own rating, then its CVSS band, else null", () => {
    expect(osvSeverity({ id: "a", database_specific: { severity: "MODERATE" } })).toBe("medium");
    expect(osvSeverity({ id: "a", database_specific: { severity: "CRITICAL" } })).toBe("critical");
    expect(osvSeverity({ id: "a", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }] })).toBe("high");
    expect(osvSeverity({ id: "a", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }] })).toBe("low");
    expect(osvSeverity({ id: "a" })).toBeNull();
  });
});
