import { describe, it, expect, vi } from "vitest";
import { createCveIndex, memoryCveIndexStore, type CveMatchRow, type CveRecordRow } from "@/lib/cveIndex";
import type { OsvBatchQuery, OsvVulnDetail } from "@/lib/scanners/osv";
import type { EolEntry } from "@/lib/scanners/endOfLife";
import {
  asDeviceMatch,
  carryMatchForward,
  cpeProductFor,
  fixedVersionFromRange,
  matchInventory,
  osEolProduct,
  osvEcosystemFor,
  osvFixFor,
  osvQueriesFor,
  osvRating,
  placeOsCycle,
  MAX_OSV_DETAILS,
  type MatchDeps,
} from "./matching";
import { ubuntuInventory, windowsInventory } from "./testFixtures";

const NOW = new Date("2026-11-20T09:00:00Z");

const state = { backfill_completed_at: "2026-11-01T00:00:00Z", last_success_at: "2026-11-19T00:00:00Z", last_modified_through: "2026-11-19T00:00:00Z", cve_count: 2 };
function cpeRow(overrides: Partial<CveMatchRow>): CveMatchRow {
  return {
    cve_id: "CVE-2026-1000",
    part: "a",
    vendor: "google",
    product: "chrome",
    criteria: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    exact_version: null,
    start_including: null,
    start_excluding: null,
    end_including: null,
    end_excluding: "124.0.6367.60",
    any_update: false,
    conditional: false,
    ...overrides,
  } as CveMatchRow;
}
const records: CveRecordRow[] = [
  { cve_id: "CVE-2026-1000", cvss_score: 8.8, cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N", summary: "Use after free in Chrome", published_at: "2026-10-01T10:00:00Z" } as CveRecordRow,
  { cve_id: "CVE-2026-2000", cvss_score: 6.5, cvss_version: "3.1", cvss_vector: null, summary: "Chrome on a particular OS", published_at: "2026-10-02T10:00:00Z" } as CveRecordRow,
  { cve_id: "CVE-2026-3000", cvss_score: 7.8, cvss_version: "3.1", cvss_vector: null, summary: "7-Zip", published_at: "2026-09-02T10:00:00Z" } as CveRecordRow,
];

function cveIndex() {
  return createCveIndex(
    memoryCveIndexStore({
      state,
      matches: [
        cpeRow({}),
        cpeRow({ cve_id: "CVE-2026-2000", conditional: true }),
        cpeRow({ cve_id: "CVE-2026-3000", vendor: "7-zip", product: "7-zip", end_excluding: null, end_including: "23.01" }),
      ],
      records,
    }),
    { now: NOW }
  );
}

const ubuntuAdvisory: OsvVulnDetail & { published: string } = {
  id: "UBUNTU-CVE-2026-5000",
  aliases: ["CVE-2026-5000"],
  summary: "openssl: buffer overread",
  published: "2026-10-20T00:00:00Z",
  severity: [{ type: "Ubuntu", score: "high" }],
  affected: [{ package: { name: "openssl", ecosystem: "Ubuntu:22.04:LTS" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "3.0.2-0ubuntu1.15" }] }] }],
};

const eolEntries: Record<string, EolEntry[]> = {
  ubuntu: [{ cycle: "22.04", eol: "2027-04-01" }, { cycle: "18.04", eol: "2023-05-31" }],
  windows: [
    { cycle: "11-23h2-w", eol: "2025-11-11" },
    { cycle: "11-24h2-w", eol: "2026-10-13" },
    { cycle: "11-24h2-e", eol: "2027-10-12" },
    { cycle: "10-22h2", eol: "2025-10-14" },
  ],
  "windows-server": [{ cycle: "2022", eol: "2031-10-14" }, { cycle: "2012-r2", eol: "2023-10-10" }],
  macos: [{ cycle: "14", eol: false }, { cycle: "11", eol: "2023-09-26" }],
};

function deps(overrides: Partial<MatchDeps> = {}): MatchDeps {
  return {
    cveIndex: cveIndex(),
    queryOsvBatch: vi.fn(async (qs: OsvBatchQuery[]) => ({ ok: true as const, vulnIds: qs.map((q) => (q.name === "openssl" ? ["UBUNTU-CVE-2026-5000"] : [])) })),
    fetchOsvVulnDetails: vi.fn(async (ids: string[]) => ({ details: new Map(ids.map((id) => [id, ubuntuAdvisory] as const)), failed: [] })),
    fetchEolProduct: vi.fn(async (p: string) => eolEntries[p] ?? null),
    now: NOW,
    ...overrides,
  };
}

describe("osvEcosystemFor", () => {
  it("names OSV ecosystems for the distros we use and nothing else", () => {
    const os = ubuntuInventory().os;
    expect(osvEcosystemFor(os)).toBe("Ubuntu:22.04:LTS");
    expect(osvEcosystemFor({ ...os, distro_version_id: "23.10" })).toBe("Ubuntu:23.10");
    expect(osvEcosystemFor({ ...os, distro_id: "debian", distro_version_id: "12" })).toBe("Debian:12");
    expect(osvEcosystemFor({ ...os, distro_id: "almalinux", distro_version_id: "9.3" })).toBe("AlmaLinux:9");
    expect(osvEcosystemFor({ ...os, distro_id: "rocky", distro_version_id: "9.3" })).toBe("Rocky Linux:9");
    expect(osvEcosystemFor({ ...os, distro_id: "arch", distro_version_id: "" })).toBeNull();
    expect(osvEcosystemFor({ ...os, distro_id: "ubuntu", distro_version_id: "jammy" })).toBeNull();
    expect(osvEcosystemFor(windowsInventory().os)).toBeNull();
  });
});

describe("osvQueriesFor", () => {
  it("queries Debian/Ubuntu by source package, once per source version", () => {
    const qs = osvQueriesFor(ubuntuInventory(), "Ubuntu:22.04:LTS");
    expect(qs.map((q) => `${q.name}@${q.version}`)).toEqual(["openssl@3.0.2-0ubuntu1.10", "glibc@2.35-0ubuntu3.6"]);
  });
  it("queries rpm packages by binary name and skips anything without a version", () => {
    const inv = ubuntuInventory({
      software: [
        { name: "openssl-libs", version: "1:3.0.7-24.el9", publisher: "", source: "rpm", installed_at: "", arch: "", source_name: "openssl", source_version: "" },
        { name: "nover", version: "", publisher: "", source: "rpm", installed_at: "", arch: "", source_name: "", source_version: "" },
        { name: "Google Chrome", version: "1", publisher: "", source: "registry", installed_at: "", arch: "", source_name: "", source_version: "" },
      ],
    });
    expect(osvQueriesFor(inv, "AlmaLinux:9").map((q) => q.name)).toEqual(["openssl-libs"]);
  });
});

describe("cpeProductFor", () => {
  it("maps only curated programs, respecting where they were read from", () => {
    expect(cpeProductFor("Google Chrome", "registry")).toEqual({ vendor: "google", product: "chrome" });
    expect(cpeProductFor("Mozilla Firefox ESR (x64 en-GB)", "registry")).toEqual({ vendor: "mozilla", product: "firefox_esr" });
    expect(cpeProductFor("Mozilla Firefox (x64 en-GB)", "registry")).toEqual({ vendor: "mozilla", product: "firefox" });
    expect(cpeProductFor("7-Zip 23.01 (x64)", "registry")).toEqual({ vendor: "7-zip", product: "7-zip" });
    expect(cpeProductFor("Safari", "app")).toEqual({ vendor: "apple", product: "safari" });
    expect(cpeProductFor("Safari", "registry")).toBeNull();
    expect(cpeProductFor("Contoso Line-of-Business App", "registry")).toBeNull();
  });
});

describe("OS end of life", () => {
  it("picks the endoflife.date product", () => {
    expect(osEolProduct(ubuntuInventory().os)).toBe("ubuntu");
    expect(osEolProduct(windowsInventory().os)).toBe("windows");
    expect(osEolProduct({ ...windowsInventory().os, name: "Microsoft Windows Server 2022 Standard" })).toBe("windows-server");
    expect(osEolProduct({ ...ubuntuInventory().os, family: "macos" })).toBe("macos");
    expect(osEolProduct({ ...ubuntuInventory().os, distro_id: "gentoo" })).toBeNull();
  });

  it("places Windows clients by major, release and servicing edition", () => {
    const os = windowsInventory().os;
    expect(placeOsCycle(os, eolEntries.windows, NOW)).toMatchObject({ state: "unsupported", cycle: "11-23h2-w" });
    expect(placeOsCycle({ ...os, release: "24H2", name: "Microsoft Windows 11 Enterprise" }, eolEntries.windows, NOW)).toMatchObject({ state: "supported", cycle: "11-24h2-e" });
    // No edition-specific cycle: fall back to the plain one; build number says 10.
    expect(placeOsCycle({ ...os, name: "Windows", build: "19045", release: "22H2" }, eolEntries.windows, NOW)).toMatchObject({ cycle: "10-22h2", state: "unsupported" });
    expect(placeOsCycle({ ...os, name: "Microsoft Windows 10 Enterprise LTSC 2021" }, eolEntries.windows, NOW)).toBeNull();
    expect(placeOsCycle({ ...os, release: "" }, eolEntries.windows, NOW)).toBeNull();
    expect(placeOsCycle({ ...os, release: "21H2" }, eolEntries.windows, NOW)).toBeNull();
    expect(placeOsCycle({ ...os, name: "Windows", build: "" }, eolEntries.windows, NOW)).toBeNull();
  });

  it("places Windows Server by year, including R2", () => {
    const os = { ...windowsInventory().os, name: "Microsoft Windows Server 2012 R2 Standard" };
    expect(placeOsCycle(os, eolEntries["windows-server"], NOW)).toMatchObject({ cycle: "2012-r2", state: "unsupported" });
    expect(placeOsCycle({ ...os, name: "Microsoft Windows Server 2022 Datacenter" }, eolEntries["windows-server"], NOW)).toMatchObject({ cycle: "2022", state: "supported" });
    expect(placeOsCycle({ ...os, name: "Microsoft Windows Server 2025 Standard" }, eolEntries["windows-server"], NOW)).toBeNull();
  });

  it("places macOS and Linux by version", () => {
    expect(placeOsCycle({ ...ubuntuInventory().os, family: "macos", version: "11.7.10" }, eolEntries.macos, NOW)).toMatchObject({ state: "unsupported", cycle: "11" });
    expect(placeOsCycle(ubuntuInventory().os, eolEntries.ubuntu, NOW)).toMatchObject({ state: "supported", cycle: "22.04" });
    expect(placeOsCycle({ ...ubuntuInventory().os, family: "macos", version: "" }, eolEntries.macos, NOW)).toBeNull();
  });
});

describe("helpers", () => {
  it("reads the first fixed version from an NVD range, never from <=", () => {
    expect(fixedVersionFromRange(">= 1.0, < 1.2.3")).toBe("1.2.3");
    expect(fixedVersionFromRange("< 2.0")).toBe("2.0");
    expect(fixedVersionFromRange("<= 1.2.3")).toBeNull();
    expect(fixedVersionFromRange("")).toBeNull();
  });

  it("rates OSV advisories from CVSS, GitHub ratings or a distro priority", () => {
    expect(osvRating(ubuntuAdvisory)).toBe("high");
    expect(osvRating({ id: "X", database_specific: { severity: "CRITICAL" } })).toBe("critical");
    expect(osvRating({ id: "X", severity: [{ type: "Ubuntu", score: "negligible" }] })).toBeNull();
  });

  it("finds a fix only in the advisory's entry for this package and release", () => {
    expect(osvFixFor(ubuntuAdvisory, "Ubuntu:22.04:LTS", "openssl")).toEqual({ fixAvailable: true, fixedVersion: "3.0.2-0ubuntu1.15" });
    expect(osvFixFor(ubuntuAdvisory, "Ubuntu:24.04:LTS", "openssl")).toEqual({ fixAvailable: null, fixedVersion: null });
    const unfixed = { ...ubuntuAdvisory, affected: [{ package: { name: "openssl", ecosystem: "Ubuntu:22.04:LTS" }, ranges: [{ events: [{ introduced: "0" }] }] }] };
    expect(osvFixFor(unfixed, "Ubuntu:22.04:LTS", "openssl")).toEqual({ fixAvailable: false, fixedVersion: null });
  });

  it("reads a stored match back only when it has the right shape", () => {
    expect(asDeviceMatch(null)).toBeNull();
    expect(asDeviceMatch({ status: "weird", cves: [], notes: [] })).toBeNull();
    expect(asDeviceMatch({ status: "checked", cves: "no", notes: [] })).toBeNull();
    expect(asDeviceMatch({ status: "partial", cves: [], notes: [] })).not.toBeNull();
  });
});

describe("matchInventory", () => {
  it("matches Ubuntu packages through OSV, with severity, fix and dates", async () => {
    const d = deps();
    const m = await matchInventory(ubuntuInventory(), d);
    expect(m.status).toBe("checked");
    expect(m.cves).toEqual([
      {
        id: "CVE-2026-5000",
        advisoryId: "UBUNTU-CVE-2026-5000",
        source: "osv",
        software: "openssl",
        version: "3.0.2-0ubuntu1.10",
        cvssScore: null,
        severity: "high",
        fixAvailable: true,
        fixedVersion: "3.0.2-0ubuntu1.15",
        publishedAt: "2026-10-20T00:00:00Z",
        summary: "openssl: buffer overread",
      },
    ]);
    expect(m.osEol).toEqual({ product: "ubuntu", cycle: "22.04", state: "supported", eolDate: null });
    expect(m.coverage).toEqual({ softwareTotal: 3, softwareChecked: 2 });
    expect(d.queryOsvBatch).toHaveBeenCalledWith([
      { ecosystem: "Ubuntu:22.04:LTS", name: "openssl", version: "3.0.2-0ubuntu1.10" },
      { ecosystem: "Ubuntu:22.04:LTS", name: "glibc", version: "2.35-0ubuntu3.6" },
    ]);
  });

  it("a failed OSV lookup makes the match partial, never clean", async () => {
    const m = await matchInventory(ubuntuInventory(), deps({ queryOsvBatch: async () => ({ ok: false, error: "HTTP 503" }) }));
    expect(m.status).toBe("partial");
    expect(m.cves).toEqual([]);
    expect(m.notes[0]).toMatch(/OSV\.dev lookup failed \(HTTP 503\)/);
  });

  it("keeps an advisory whose detail couldn't be read, without inventing a severity", async () => {
    const m = await matchInventory(ubuntuInventory(), deps({ fetchOsvVulnDetails: async (ids) => ({ details: new Map(), failed: ids }) }));
    expect(m.status).toBe("partial");
    expect(m.cves[0]).toMatchObject({ id: "UBUNTU-CVE-2026-5000", severity: null, fixAvailable: null, publishedAt: null, summary: null });
  });

  it("skips withdrawn advisories and caps how many details are read", async () => {
    const many = Array.from({ length: MAX_OSV_DETAILS + 5 }, (_, i) => `ADV-${i}`);
    const fetchOsvVulnDetails = vi.fn(async (ids: string[]) => ({ details: new Map(ids.map((id) => [id, { ...ubuntuAdvisory, id, withdrawn: "2026-11-01" }] as const)), failed: [] }));
    const m = await matchInventory(ubuntuInventory(), deps({ queryOsvBatch: async (qs) => ({ ok: true, vulnIds: qs.map(() => many) }), fetchOsvVulnDetails }));
    expect(fetchOsvVulnDetails.mock.calls[0][0]).toHaveLength(MAX_OSV_DETAILS);
    expect(m.notes.join(" ")).toMatch(/5 advisories weren't read/);
    // The capped-out ids have no detail and aren't withdrawn as far as we
    // know: kept, for both packages that reported them.
    expect(m.cves).toHaveLength(10);
  });

  it("matches curated Windows programs through the CPE index, dropping conditional criteria", async () => {
    const m = await matchInventory(windowsInventory(), deps());
    expect(m.status).toBe("checked");
    expect(m.cves.map((c) => [c.id, c.software, c.fixAvailable, c.fixedVersion])).toEqual([
      ["CVE-2026-1000", "Google Chrome", true, "124.0.6367.60"],
      ["CVE-2026-3000", "7-Zip 23.01 (x64)", null, null],
    ]);
    expect(m.cves[0]).toMatchObject({ source: "nvd", cvssScore: 8.8, severity: "high", publishedAt: "2026-10-01T10:00:00Z" });
    expect(m.coverage).toEqual({ softwareTotal: 3, softwareChecked: 2 });
    expect(m.osEol).toMatchObject({ cycle: "11-23h2-w", state: "unsupported", eolDate: "2025-11-11" });
  });

  it("reports a missing or stale CVE index as partial", async () => {
    const noIndex = await matchInventory(windowsInventory(), deps({ cveIndex: null }));
    expect(noIndex.status).toBe("partial");
    expect(noIndex.notes[0]).toMatch(/CVE index couldn't be opened/);

    const stale = createCveIndex(memoryCveIndexStore({ state: { ...state, last_success_at: "2026-10-01T00:00:00Z" }, matches: [], records }), { now: NOW });
    const m = await matchInventory(windowsInventory(), deps({ cveIndex: stale }));
    expect(m.status).toBe("partial");
    expect(m.notes.join(" ")).toMatch(/CVE index unavailable \(CVE index is stale/);
  });

  it("an unreachable endoflife.date is a note, not a verdict", async () => {
    const m = await matchInventory(windowsInventory({ software: [] }), deps({ fetchEolProduct: async () => null }));
    expect(m.osEol).toBeNull();
    expect(m.notes).toEqual(["endoflife.date couldn't be reached, so OS support status is unknown."]);
  });

  it("does no OSV or CPE work for an OS and software list it can't match", async () => {
    const d = deps();
    const inv = ubuntuInventory({ software: [], os: { ...ubuntuInventory().os, distro_id: "gentoo" } });
    const m = await matchInventory(inv, d);
    expect(m).toMatchObject({ status: "checked", cves: [], osEol: null });
    expect(d.queryOsvBatch).not.toHaveBeenCalled();
    const empty = await matchInventory(ubuntuInventory({ software: [] }), d);
    expect(empty.cves).toEqual([]);
    expect(d.queryOsvBatch).not.toHaveBeenCalled();
  });
});

describe("carryMatchForward", () => {
  it("keeps only CVEs whose software and version are still installed", async () => {
    const m = await matchInventory(windowsInventory(), deps());
    const upgraded = windowsInventory();
    upgraded.software[0] = { ...upgraded.software[0], version: "124.0.6367.60" };
    expect(carryMatchForward(m, upgraded)!.cves.map((c) => c.id)).toEqual(["CVE-2026-3000"]);
    expect(carryMatchForward(null, upgraded)).toBeNull();

    const osv = await matchInventory(ubuntuInventory(), deps());
    expect(carryMatchForward(osv, ubuntuInventory())!.cves).toHaveLength(1);
  });
});
