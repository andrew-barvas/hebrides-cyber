import { describe, it, expect, vi, afterEach } from "vitest";
import { createHash } from "node:crypto";
import { compareRetireVersions, displayName, loadRetireRepository, matchRetire, setRetireRepositoryForTests, type RetireRepository } from "./retireJs";
import { jsLibrariesFromRetire } from "./webapp";

afterEach(() => {
  vi.unstubAllGlobals();
  setRetireRepositoryForTests(null);
});

const hashedBody = "/* custom build of widget */ var w = 1;";

// Shapes copied from the real repository/jsrepository.json.
const REPO: RetireRepository = {
  "retire-example": { extractors: { filename: ["retire-example-(§§version§§)(.min)?\\.js"] } },
  jquery: {
    vulnerabilities: [
      { below: "1.6.3", severity: "medium", identifiers: { summary: "XSS with location.hash", CVE: ["CVE-2011-4969"] } },
      { atOrAbove: "1.2.0", below: "3.5.0", severity: "medium", identifiers: { summary: "Regex in htmlPrefilter", CVE: ["CVE-2020-11022"] } },
    ],
    extractors: {
      uri: ["/(§§version§§)/jquery(\\.min)?\\.js"],
      filename: ["jquery-(§§version§§)(\\.min)?\\.js"],
      filecontent: ["/\\*!? jQuery v(§§version§§)"],
    },
  },
  "jquery-ui": {
    vulnerabilities: [{ below: "1.13.2", severity: "high", identifiers: { summary: "XSS in checkboxradio", CVE: ["CVE-2022-31160"] } }],
    extractors: { filecontent: ["/\\*! jQuery UI - v(§§version§§)"] },
  },
  widget: {
    vulnerabilities: [{ below: "2.0.0", severity: "critical", identifiers: { summary: "Prototype pollution" } }],
    extractors: { hashes: { [createHash("sha1").update(hashedBody).digest("hex")]: "1.4.0" } },
  },
};

describe("compareRetireVersions", () => {
  it("orders numerically, with pre-releases before the release", () => {
    expect(compareRetireVersions("1.10.0", "1.9.9")).toBeGreaterThan(0);
    expect(compareRetireVersions("1.2", "1.2.1")).toBeLessThan(0);
    expect(compareRetireVersions("1.2", "1.2.0")).toBe(0);
    expect(compareRetireVersions("1.0.0-beta.2", "1.0.0")).toBeLessThan(0);
    expect(compareRetireVersions("trunk", "1.0.0")).toBeNull();
  });
});

describe("matchRetire", () => {
  it("detects from a CDN path, a filename, a file banner and a file hash", () => {
    const matches = matchRetire(
      REPO,
      ["https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js", "https://example.com/js/app.js"],
      ["/*! jQuery UI - v1.12.1 - 2016-09-14 */ ...", hashedBody]
    );
    expect(matches.map((m) => [m.component, m.version, m.vulnerabilities.map((v) => v.severity)])).toEqual([
      ["jquery", "3.4.1", ["medium"]],
      ["jquery-ui", "1.12.1", ["high"]],
      ["widget", "1.4.0", ["critical"]],
    ]);
    expect(matches[0].vulnerabilities[0].cveIds).toEqual(["CVE-2020-11022"]);
  });

  it("respects atOrAbove and below, and reports a current version as clean", () => {
    const old = matchRetire(REPO, ["https://example.com/jquery-1.4.2.min.js"]);
    expect(old[0].vulnerabilities.map((v) => v.summary)).toEqual(["XSS with location.hash", "Regex in htmlPrefilter"]);
    const current = matchRetire(REPO, ["https://example.com/jquery-3.7.1.min.js"]);
    expect(current).toEqual([{ component: "jquery", version: "3.7.1", vulnerabilities: [] }]);
  });

  it("never reports the repository's example component or an unrecognised script", () => {
    expect(matchRetire(REPO, ["https://example.com/retire-example-0.0.1.js", "https://example.com/app.js"], ["var x;"])).toEqual([]);
  });
});

describe("displayName", () => {
  it("keeps the names existing checkIds use", () => {
    expect(displayName("jquery")).toBe("jQuery");
    expect(displayName("moment.js")).toBe("Moment.js");
    expect(displayName("jquery-ui")).toBe("jquery-ui");
  });
});

describe("loadRetireRepository", () => {
  it("returns null, not an empty repository, when the data can't be fetched", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 503 })));
    expect(await loadRetireRepository()).toBeNull();
  });

  it("fetches from a pinned commit, not a moving branch", async () => {
    const fetchMock = vi.fn<(url: string) => Promise<Response>>(async () => new Response(JSON.stringify(REPO)));
    vi.stubGlobal("fetch", fetchMock);
    await loadRetireRepository();
    expect(fetchMock.mock.calls[0][0]).toMatch(/RetireJS\/retire\.js\/[0-9a-f]{40}\/repository\/jsrepository\.json$/);
  });
});

describe("jsLibrariesFromRetire", () => {
  it("turns matches into findings with published severity, CVEs and the fix version", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
    const libs = await jsLibrariesFromRetire(REPO, '<script src="/js/jquery-1.4.2.min.js"></script>', "https://example.com/");
    expect(libs).toEqual([
      {
        name: "jQuery",
        version: "1.4.2",
        isVulnerable: true,
        severity: "medium",
        cveIds: ["CVE-2011-4969", "CVE-2020-11022"],
        reason: "jQuery 1.4.2 has 2 published vulnerabilities: XSS with location.hash; Regex in htmlPrefilter. Fixed in 3.5.0 or later.",
      },
    ]);
  });

  it("reads script bodies for banner and hash matches, and reports a current version as clean", async () => {
    const bodies: Record<string, string> = {
      "https://example.com/vendor/ui.js": "/*! jQuery UI - v1.13.2 - 2022-07-14 */",
      "https://cdn.example.net/w.js": hashedBody,
    };
    vi.stubGlobal("fetch", vi.fn(async (url: string) => (bodies[url] ? new Response(bodies[url]) : new Response("", { status: 404 }))));
    const html = '<script src="/vendor/ui.js"></script><script src="https://cdn.example.net/w.js"></script><script src="javascript:void(0)"></script>';
    const libs = await jsLibrariesFromRetire(REPO, html, "https://example.com/");
    expect(libs).toEqual([
      { name: "jquery-ui", version: "1.13.2", isVulnerable: false, reason: "jquery-ui 1.13.2: no published vulnerabilities for this version" },
      {
        name: "widget",
        version: "1.4.0",
        isVulnerable: true,
        severity: "critical",
        cveIds: [],
        reason: "widget 1.4.0 has 1 published vulnerability: Prototype pollution. Fixed in 2.0.0 or later.",
      },
    ]);
  });
});
