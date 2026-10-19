import { describe, it, expect } from "vitest";
import {
  assessObservation,
  buildCveTechRanges,
  compareToBound,
  latestScanPerHost,
  matchHost,
  nvdRangesByTech,
  osvRangesForPackage,
  parseVersion,
  recentKevAdditions,
  splitCpe,
  versionInRange,
  type NvdCveRecord,
  type OsvVulnRecord,
  type VersionRange,
} from "./emergingThreats";
import type { KevIndex } from "./scanners/threatIntel";
import type { TechObservation } from "./scanners/techInventory";

const v = (s: string) => parseVersion(s)!;
const obs = (tech: string, version: string | null, packagedBy: string | null = null): TechObservation => ({
  tech, version, packagedBy, source: "fingerprint", reportedVulnerable: false,
});
const cpe = (vendorProduct: string, version = "*", update = "*", edition = "*") =>
  `cpe:2.3:a:${vendorProduct}:${version}:${update}:*:*:${edition}:*:*:*`;

// Shapes copied from real NVD records (trimmed): CVE-2021-41773 lists Apache
// 2.4.49 exactly; CVE-2024-4577 lists PHP ranges AND Windows.
const NVD_APACHE: NvdCveRecord = {
  id: "CVE-2021-41773",
  configurations: [
    { nodes: [{ operator: "OR", negate: false, cpeMatch: [{ vulnerable: true, criteria: cpe("apache:http_server", "2.4.49") }] }] },
    { nodes: [{ operator: "OR", cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*" }] }] },
  ],
};
const NVD_PHP_WINDOWS: NvdCveRecord = {
  id: "CVE-2024-4577",
  configurations: [
    {
      operator: "AND",
      nodes: [
        {
          operator: "OR",
          cpeMatch: [
            { vulnerable: true, criteria: cpe("php:php"), versionStartIncluding: "8.1.0", versionEndExcluding: "8.1.29" },
            { vulnerable: true, criteria: cpe("php:php"), versionStartIncluding: "8.3.0", versionEndExcluding: "8.3.8" },
          ],
        },
        { operator: "OR", cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" }] },
      ],
    },
  ],
};

describe("parseVersion / compareToBound", () => {
  it("parses dotted versions and prereleases, and refuses other schemes", () => {
    expect(parseVersion("2.4.49")).toEqual({ nums: [2, 4, 49], pre: null });
    expect(parseVersion("11.1.0-next.0")).toEqual({ nums: [11, 1, 0], pre: "next.0" });
    expect(parseVersion("r22")).toBeNull();
    expect(parseVersion("1.0.2k")).toBeNull();
  });

  it("compares full versions, padding the shorter bound with zeros", () => {
    expect(compareToBound(v("2.4.49"), v("2.4.50"))).toBe("lt");
    expect(compareToBound(v("2.4.49"), v("2.4.49"))).toBe("eq");
    expect(compareToBound(v("2.4.49"), v("2.4"))).toBe("gt");
    expect(compareToBound(v("6.4.0"), v("6.4"))).toBe("eq");
  });

  it("treats a release as after its own prereleases", () => {
    expect(compareToBound(v("3.0.0"), v("3.0.0-beta.1"))).toBe("gt");
    expect(compareToBound(v("11.1"), v("11.1.0-next.3"))).toBe("gt");
  });

  it("is honest about a partial version", () => {
    expect(compareToBound(v("6.4"), v("6.4.3"))).toBe("unknown");
    expect(compareToBound(v("6.4"), v("6.4.0"))).toBe("ge");
    expect(compareToBound(v("6.4"), v("6.5.1"))).toBe("lt");
  });
});

describe("versionInRange (boundaries)", () => {
  const range = (r: Omit<VersionRange, "source">): VersionRange => ({ source: "nvd", ...r });

  it("includes the start and excludes the fix", () => {
    const r = range({ startIncluding: "8.1.0", endExcluding: "8.1.29" });
    expect(versionInRange("8.1.0", r)).toBe("in");
    expect(versionInRange("8.1.28", r)).toBe("in");
    expect(versionInRange("8.1.29", r)).toBe("out");
    expect(versionInRange("8.0.30", r)).toBe("out");
  });

  it("handles exclusive starts and inclusive ends", () => {
    const r = range({ startExcluding: "1.3.9", endIncluding: "1.4.0" });
    expect(versionInRange("1.3.9", r)).toBe("out");
    expect(versionInRange("1.3.10", r)).toBe("in");
    expect(versionInRange("1.4.0", r)).toBe("in");
    expect(versionInRange("1.4.1", r)).toBe("out");
  });

  it("matches an exact version only exactly", () => {
    expect(versionInRange("2.4.49", range({ exact: "2.4.49" }))).toBe("in");
    expect(versionInRange("2.4.48", range({ exact: "2.4.49" }))).toBe("out");
    expect(versionInRange("2.4", range({ exact: "2.4.49" }))).toBe("unknown");
  });

  it("treats a range with no bounds as every version", () => {
    expect(versionInRange("1.2.3", range({}))).toBe("in");
  });

  it("can't place a partial version that straddles the fix", () => {
    expect(versionInRange("6.4", range({ startIncluding: "6.4", endExcluding: "6.4.3" }))).toBe("unknown");
    expect(versionInRange("6.4", range({ endExcluding: "6.4.0" }))).toBe("out");
  });

  it("gives no verdict when a bound uses another version scheme", () => {
    expect(versionInRange("1.18.0", range({ startIncluding: "r22", endIncluding: "r27" }))).toBeNull();
  });
});

describe("NVD configurations", () => {
  it("splits CPEs on unescaped colons only", () => {
    expect(splitCpe(cpe("joomla:joomla\\!"))?.[4]).toBe("joomla\\!");
    expect(splitCpe("cpe:2.3:a:x")).toBeNull();
  });

  it("maps vulnerable CPEs to our technologies and ignores everything else", () => {
    const ranges = nvdRangesByTech(NVD_APACHE);
    expect([...ranges.keys()]).toEqual(["Apache"]);
    expect(ranges.get("Apache")).toEqual([{ source: "nvd", exact: "2.4.49" }]);
  });

  it("marks ranges that only apply together with another component (AND)", () => {
    const php = nvdRangesByTech(NVD_PHP_WINDOWS).get("PHP")!;
    expect(php).toHaveLength(2);
    expect(php.every((r) => r.conditional)).toBe(true);
  });

  it("skips pre-release-specific entries, N/A versions, negated nodes and non-vulnerable matches", () => {
    const ranges = nvdRangesByTech({
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: true, criteria: cpe("angular:angular", "11.1.0", "next0") },
                { vulnerable: true, criteria: cpe("wordpress:wordpress", "-") },
                { vulnerable: false, criteria: cpe("jquery:jquery") },
              ],
            },
            { negate: true, cpeMatch: [{ vulnerable: true, criteria: cpe("drupal:drupal") }] },
          ],
        },
      ],
    });
    expect(ranges.size).toBe(0);
  });

  it("reads Joomla's escaped CPE product name", () => {
    const ranges = nvdRangesByTech({
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: cpe("joomla:joomla\\!"), versionStartIncluding: "4.0.0", versionEndExcluding: "4.2.8" }] }] }],
    });
    expect(ranges.get("Joomla")).toEqual([{ source: "nvd", startIncluding: "4.0.0", endExcluding: "4.2.8" }]);
  });

  it("maps the newer CMS platforms from NVD's CPE names", () => {
    const ranges = nvdRangesByTech({
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: true, criteria: cpe("typo3:typo3"), versionEndExcluding: "12.4.11" },
                { vulnerable: true, criteria: cpe("umbraco:umbraco_cms"), versionEndExcluding: "13.5.2" },
                { vulnerable: true, criteria: cpe("craftcms:craft_cms"), versionEndExcluding: "4.8.1" },
                { vulnerable: true, criteria: cpe("moodle:moodle"), versionEndExcluding: "4.1.9" },
                { vulnerable: true, criteria: cpe("prestashop:prestashop"), versionEndExcluding: "8.1.3" },
                { vulnerable: true, criteria: cpe("opencart:opencart"), versionEndExcluding: "4.0.2.3" },
              ],
            },
          ],
        },
      ],
    });
    expect([...ranges.keys()].sort()).toEqual(["Craft CMS", "Moodle", "OpenCart", "PrestaShop", "TYPO3", "Umbraco"]);
    expect(ranges.get("TYPO3")).toEqual([{ source: "nvd", endExcluding: "12.4.11" }]);
  });

  it("tolerates a record with no configurations", () => {
    expect(nvdRangesByTech(null).size).toBe(0);
    expect(nvdRangesByTech({}).size).toBe(0);
  });
});

describe("OSV npm ranges", () => {
  const GHSA: OsvVulnRecord = {
    id: "GHSA-gxr4-xjj5-5px2",
    affected: [
      { package: { name: "jquery", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.12.0" }, { fixed: "3.5.0" }] }] },
      { package: { name: "jquery", ecosystem: "NuGet" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
    ],
  };

  it("reads introduced/fixed for the named npm package only", () => {
    expect(osvRangesForPackage([GHSA], "jquery")).toEqual([{ source: "osv", startIncluding: "1.12.0", endExcluding: "3.5.0" }]);
  });

  it("handles introduced 0, last_affected, open-ended ranges and explicit versions", () => {
    const rec: OsvVulnRecord = {
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "4.17.20" }, { introduced: "5.0.0" }] }],
        },
        { package: { name: "moment", ecosystem: "npm" }, versions: ["2.29.1"] },
      ],
    };
    expect(osvRangesForPackage([rec], "lodash")).toEqual([
      { source: "osv", endIncluding: "4.17.20" },
      { source: "osv", startIncluding: "5.0.0" },
    ]);
    expect(osvRangesForPackage([rec], "moment")).toEqual([{ source: "osv", exact: "2.29.1" }]);
  });
});

describe("buildCveTechRanges", () => {
  it("prefers OSV's npm data for npm libraries — a package OSV doesn't list is not affected", () => {
    // Real case: NVD files Angular's CVE-2021-4231 under angularjs:angularjs;
    // the GitHub advisory lists only @angular/core.
    const nvd: NvdCveRecord = {
      configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: cpe("angularjs:angularjs"), versionEndExcluding: "11.0.5" }] }] }],
    };
    const osv: OsvVulnRecord[] = [
      { affected: [{ package: { name: "@angular/core", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "11.0.0" }, { fixed: "11.0.5" }] }] }] },
    ];
    const ranges = buildCveTechRanges("CVE-2021-4231", nvd, osv);
    expect(ranges.byTech.has("AngularJS")).toBe(false);
    expect(ranges.byTech.get("Angular")).toEqual([{ source: "osv", startIncluding: "11.0.0", endExcluding: "11.0.5" }]);
  });

  it("falls back to NVD for npm libraries when OSV has no npm data, and always uses NVD for servers", () => {
    const nvd: NvdCveRecord = {
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: true, criteria: cpe("jquery:jquery"), versionStartIncluding: "1.0.3", versionEndExcluding: "3.5.0" },
                { vulnerable: true, criteria: cpe("drupal:drupal"), versionStartIncluding: "7.0", versionEndExcluding: "7.70" },
              ],
            },
          ],
        },
      ],
    };
    const ranges = buildCveTechRanges("CVE-2020-11023", nvd, []);
    expect(ranges.byTech.get("jQuery")?.[0]).toMatchObject({ source: "nvd", endExcluding: "3.5.0" });
    expect(ranges.byTech.get("Drupal")?.[0]).toMatchObject({ source: "nvd", endExcluding: "7.70" });
  });
});

describe("evidence tiers", () => {
  const ranges: VersionRange[] = [{ source: "nvd", startIncluding: "8.1.0", endExcluding: "8.1.29" }];

  it("affected: a detected version inside the range", () => {
    expect(assessObservation(obs("PHP", "8.1.2"), ranges)).toEqual({ tier: "affected", reason: "version_in_range" });
  });

  it("nothing: a detected version outside every range", () => {
    expect(assessObservation(obs("PHP", "8.1.29"), ranges)).toBeNull();
    expect(assessObservation(obs("PHP", "8.1.2"), [])).toBeNull();
  });

  it("possibly affected: product seen but no version", () => {
    expect(assessObservation(obs("PHP", null), ranges)).toEqual({ tier: "possibly_affected", reason: "version_unknown" });
  });

  it("possibly affected: a partial version that straddles the fix", () => {
    expect(assessObservation(obs("PHP", "8.1"), ranges)).toEqual({ tier: "possibly_affected", reason: "partial_version" });
  });

  it("possibly affected: distribution packages, since vendors backport fixes", () => {
    expect(assessObservation(obs("PHP", "8.1.2", "Ubuntu"), ranges)).toEqual({ tier: "possibly_affected", reason: "distro_packaged" });
    // ...but a distro version outside the range is still not a match.
    expect(assessObservation(obs("PHP", "8.2.0", "Ubuntu"), ranges)).toBeNull();
  });

  it("possibly affected: in range, but only on a platform we can't see", () => {
    expect(assessObservation(obs("PHP", "8.1.2"), [{ ...ranges[0], conditional: true }])).toEqual({
      tier: "possibly_affected",
      reason: "platform_specific",
    });
  });

  it("no evidence from a range in another version scheme", () => {
    expect(assessObservation(obs("Nginx", "1.18.0"), [{ source: "nvd", startIncluding: "r22", endIncluding: "r27" }])).toBeNull();
  });
});

describe("matchHost", () => {
  it("never matches on a name alone — the tech must be mapped and covered", () => {
    const cve = buildCveTechRanges("CVE-2021-41773", NVD_APACHE, []);
    expect(matchHost([obs("Nginx", "1.18.0"), obs("Apache Tomcat", "9.0.0")], [cve])).toEqual([]);
  });

  it("returns one match per CVE, preferring the strongest evidence", () => {
    const nvd: NvdCveRecord = {
      configurations: [
        {
          nodes: [
            {
              cpeMatch: [
                { vulnerable: true, criteria: cpe("drupal:drupal"), versionStartIncluding: "7.0", versionEndExcluding: "7.70" },
                { vulnerable: true, criteria: cpe("jquery:jquery"), versionEndExcluding: "3.5.0" },
              ],
            },
          ],
        },
      ],
    };
    const cve = buildCveTechRanges("CVE-2020-11023", nvd, []);
    const matches = matchHost([obs("Drupal", null), obs("jQuery", "1.12.4")], [cve]);
    expect(matches).toEqual([
      { cveId: "CVE-2020-11023", tech: "jQuery", product: "jQuery", detectedVersion: "1.12.4", packagedBy: null, tier: "affected", reason: "version_in_range" },
    ]);
  });

  it("labels server products for humans", () => {
    const cve = buildCveTechRanges("CVE-2021-41773", NVD_APACHE, []);
    expect(matchHost([obs("Apache", "2.4.49")], [cve])[0].product).toBe("Apache HTTP Server");
  });
});

describe("recentKevAdditions", () => {
  const kev: KevIndex = new Map([
    ["CVE-2026-1000", { ransomware: true, vendorProject: "PHP Group", product: "PHP", vulnerabilityName: "PHP Thing", dateAdded: "2026-09-29" }],
    ["CVE-2026-1001", { ransomware: false, dateAdded: "2026-09-28" }],
    ["CVE-2026-0999", { ransomware: false, dateAdded: "2026-09-27" }],
    ["CVE-2026-0998", { ransomware: false }],
  ]);

  it("keeps entries added in the last 3 days, newest first", () => {
    const out = recentKevAdditions(kev, new Date("2026-10-01T12:00:00Z"));
    expect(out.map((a) => a.cveId)).toEqual(["CVE-2026-1000", "CVE-2026-1001"]);
    expect(out[0]).toEqual({
      cveId: "CVE-2026-1000", vendorProject: "PHP Group", product: "PHP", vulnerabilityName: "PHP Thing", dateAdded: "2026-09-29", ransomware: true,
    });
    expect(out[1].vulnerabilityName).toBeNull();
  });
});

describe("latestScanPerHost", () => {
  it("groups by hostname, ignoring path and case, and keeps the newest", () => {
    const latest = latestScanPerHost([
      { id: "a", target_url: "https://Shop.example/", created_at: "2026-09-01T00:00:00Z" },
      { id: "b", target_url: "https://shop.example/cart", created_at: "2026-09-20T00:00:00Z" },
      { id: "c", target_url: "https://blog.example", created_at: "2026-09-10T00:00:00Z" },
      { id: "d", target_url: "not a url", created_at: "2026-09-30T00:00:00Z" },
    ]);
    expect(Object.fromEntries([...latest].map(([h, s]) => [h, s.id]))).toEqual({ "shop.example": "b", "blog.example": "c" });
  });
});
