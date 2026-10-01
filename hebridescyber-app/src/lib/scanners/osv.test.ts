import { describe, it, expect, vi, afterEach } from "vitest";
import { extractCveIdsFromText, lookupCveIds, lookupOsvFixInfo, npmPackageNameFor } from "./osv";

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

  it("falls back to the highest fix when the current version can't be placed in a range", async () => {
    const name = pkg();
    osvReturns({ vulns: [{ id: "GHSA-1", affected: affected(name, range({ introduced: "0" }, { fixed: "2.0.0" }), range({ introduced: "3.0.0" }, { fixed: "3.1.0" })) }] });
    expect((await lookupOsvFixInfo("npm", name, "1.0.0-beta.1")).fixedVersion).toBe("3.1.0");
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
