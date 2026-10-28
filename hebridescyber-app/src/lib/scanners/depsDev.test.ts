import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { licensesFromRecord, versionPath, lookupLicenses, SYSTEM_FOR_ECOSYSTEM } from "./depsDev";

describe("versionPath", () => {
  it("builds the deps.dev v3 version URL, URL-encoding the name and version", () => {
    expect(versionPath("npm", "lodash", "4.17.21")).toBe(
      "https://api.deps.dev/v3/systems/npm/packages/lodash/versions/4.17.21"
    );
  });
  it("encodes a scoped npm name and a Maven coordinate", () => {
    expect(versionPath("npm", "@colors/colors", "1.5.0")).toContain("%40colors%2Fcolors");
    expect(versionPath("maven", "com.google.guava:guava", "32.0.0")).toContain("com.google.guava%3Aguava");
  });
});

describe("licensesFromRecord", () => {
  it("extracts the SPDX string list, de-duplicated", () => {
    expect(licensesFromRecord({ licenses: ["MIT", "Apache-2.0", "MIT"] })).toEqual(["MIT", "Apache-2.0"]);
  });
  it("returns [] for a record with no/invalid licenses", () => {
    expect(licensesFromRecord({ licenses: undefined })).toEqual([]);
    expect(licensesFromRecord({ licenses: [1, null] as unknown as string[] })).toEqual([]);
    expect(licensesFromRecord(null)).toEqual([]);
  });
});

describe("SYSTEM_FOR_ECOSYSTEM", () => {
  it("covers the deps.dev ecosystems and omits Packagist (PHP, unsupported)", () => {
    expect(SYSTEM_FOR_ECOSYSTEM.npm).toBe("npm");
    expect(SYSTEM_FOR_ECOSYSTEM.PyPI).toBe("pypi");
    expect(SYSTEM_FOR_ECOSYSTEM.Packagist).toBeUndefined();
  });
});

describe("lookupLicenses", () => {
  const fetchMock = vi.fn();
  const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body });

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("maps resolved packages to their licences, keyed ecosystem:name@version", async () => {
    fetchMock.mockImplementation((url: string) =>
      Promise.resolve(ok({ licenses: url.includes("lodash") ? ["MIT"] : ["GPL-3.0-only"] }))
    );
    const { licenses, failed } = await lookupLicenses([
      { ecosystem: "npm", name: "lodash", version: "4.17.21" },
      { ecosystem: "npm", name: "readline-sync", version: "1.4.10" },
    ]);
    expect(failed).toBe(0);
    expect(licenses.get("npm:lodash@4.17.21")).toEqual(["MIT"]);
    expect(licenses.get("npm:readline-sync@1.4.10")).toEqual(["GPL-3.0-only"]);
  });

  it("de-duplicates identical queries into one request", async () => {
    fetchMock.mockResolvedValue(ok({ licenses: ["MIT"] }));
    // A name unique to this test so the module-level cache (shared across tests
    // in this file, by design) doesn't serve it from an earlier lookup.
    await lookupLicenses([
      { ecosystem: "npm", name: "dedupe-fixture-pkg", version: "4.17.21" },
      { ecosystem: "npm", name: "dedupe-fixture-pkg", version: "4.17.21" },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("skips an ecosystem deps.dev doesn't cover without a request or an error", async () => {
    const { licenses, failed } = await lookupLicenses([{ ecosystem: "Packagist", name: "monolog/monolog", version: "3.0.0" }]);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(failed).toBe(0);
    expect(licenses.size).toBe(0);
  });

  it("treats a 404 as 'no data' (ok, no licence), never a failure", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 404, json: async () => ({}) });
    const { licenses, failed } = await lookupLicenses([{ ecosystem: "npm", name: "ghost-pkg", version: "9.9.9" }]);
    expect(failed).toBe(0);
    expect(licenses.size).toBe(0);
  });

  it("retries once on a 5xx, then counts a persistent failure", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503, json: async () => ({}) });
    const { licenses, failed } = await lookupLicenses([{ ecosystem: "npm", name: "flaky", version: "1.0.0" }]);
    expect(fetchMock).toHaveBeenCalledTimes(2); // one retry
    expect(failed).toBe(1);
    expect(licenses.size).toBe(0); // never a false "unlicensed"
  });

  it("counts a network exception as a failure, not a licence", async () => {
    fetchMock.mockRejectedValue(new Error("network"));
    const { failed } = await lookupLicenses([{ ecosystem: "npm", name: "x", version: "1.0.0" }]);
    expect(failed).toBe(1);
  });
});
