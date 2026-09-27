import { describe, it, expect, vi, afterEach } from "vitest";
import {
  EPSS_API_URL,
  KEV_FEED_URL,
  applyThreatIntel,
  enrichFindingsWithThreatIntel,
  parseEpss,
  parseKev,
  resetThreatIntelCache,
} from "./threatIntel";
import type { Finding } from "./index";

afterEach(() => {
  vi.unstubAllGlobals();
  resetThreatIntelCache();
});

const finding = (cveIds?: string[]): Finding => ({ severity: "high", title: "Outdated jQuery", detail: "d", checkId: "webapp.lib", cveIds });

const KEV_BODY = {
  vulnerabilities: [
    { cveID: "CVE-2020-11022", knownRansomwareCampaignUse: "Unknown" },
    { cveID: "CVE-2021-44228", knownRansomwareCampaignUse: "Known" },
    { cveID: "not-a-cve" },
  ],
};
const EPSS_BODY = {
  data: [
    { cve: "CVE-2020-11022", epss: "0.02100", percentile: "0.88000" },
    { cve: "CVE-2020-11023", epss: "0.45000", percentile: "0.97000" },
    { cve: "CVE-2021-44228", epss: "0.97500", percentile: "0.99990" },
  ],
};

describe("parsers", () => {
  it("indexes KEV by CVE id, flagging ransomware use and skipping junk", () => {
    const kev = parseKev(KEV_BODY);
    expect([...kev.keys()]).toEqual(["CVE-2020-11022", "CVE-2021-44228"]);
    expect(kev.get("CVE-2021-44228")).toEqual({ ransomware: true });
    expect(parseKev({ unexpected: true }).size).toBe(0);
  });

  it("indexes EPSS rows, parsing its string numbers", () => {
    expect(parseEpss(EPSS_BODY).get("CVE-2020-11023")).toEqual({ epss: 0.45, percentile: 0.97 });
    expect(parseEpss(null).size).toBe(0);
  });
});

describe("applyThreatIntel", () => {
  const kev = parseKev(KEV_BODY);
  const epss = parseEpss(EPSS_BODY);

  it("marks known-exploited CVEs and takes the highest EPSS across a finding's CVEs", () => {
    const f = finding(["CVE-2020-11022", "cve-2020-11023"]);
    applyThreatIntel([f], kev, epss);
    expect(f.threatIntel).toEqual({ knownExploited: true, kevCveIds: ["CVE-2020-11022"], epss: 0.45, epssPercentile: 0.97 });
  });

  it("flags ransomware use", () => {
    const f = finding(["CVE-2021-44228"]);
    applyThreatIntel([f], kev, epss);
    expect(f.threatIntel).toMatchObject({ knownExploited: true, ransomware: true, epss: 0.975 });
  });

  it("records 'not in KEV' only when KEV was actually checked", () => {
    const f = finding(["CVE-2019-0001"]);
    applyThreatIntel([f], kev, epss);
    expect(f.threatIntel).toEqual({ knownExploited: false });
  });

  // An unreachable feed is not evidence that nothing is exploited.
  it("leaves findings alone when KEV was unreachable and EPSS had no score", () => {
    const f = finding(["CVE-2019-0001"]);
    applyThreatIntel([f], null, epss);
    expect(f.threatIntel).toBeUndefined();
  });

  it("still reports EPSS when only KEV was unreachable", () => {
    const f = finding(["CVE-2020-11023"]);
    applyThreatIntel([f], null, epss);
    expect(f.threatIntel).toEqual({ knownExploited: false, epss: 0.45, epssPercentile: 0.97 });
  });

  it("ignores findings without CVEs and never touches severity", () => {
    const noCve = finding();
    const withCve = finding(["CVE-2021-44228"]);
    applyThreatIntel([noCve, withCve], kev, epss);
    expect(noCve.threatIntel).toBeUndefined();
    expect(withCve.severity).toBe("high");
  });
});

describe("enrichFindingsWithThreatIntel", () => {
  function stubFeeds(kevOk = true) {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === KEV_FEED_URL) return kevOk ? new Response(JSON.stringify(KEV_BODY)) : new Response("down", { status: 503 });
      if (url.startsWith(EPSS_API_URL)) return new Response(JSON.stringify(EPSS_BODY));
      throw new Error(`unexpected ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("makes no requests when no finding carries a CVE", async () => {
    const fetchMock = stubFeeds();
    await enrichFindingsWithThreatIntel([finding()]);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("queries EPSS once for the de-duplicated CVE set and caches KEV between scans", async () => {
    const fetchMock = stubFeeds();
    const a = finding(["CVE-2020-11022"]);
    const b = finding(["cve-2020-11022", "CVE-2021-44228"]);
    await enrichFindingsWithThreatIntel([a, b], 1_000);
    const epssCalls = fetchMock.mock.calls.filter(([u]) => String(u).startsWith(EPSS_API_URL));
    expect(epssCalls).toHaveLength(1);
    expect(String(epssCalls[0][0])).toBe(`${EPSS_API_URL}?cve=CVE-2020-11022,CVE-2021-44228`);
    expect(b.threatIntel?.ransomware).toBe(true);

    await enrichFindingsWithThreatIntel([finding(["CVE-2021-44228"])], 2_000);
    expect(fetchMock.mock.calls.filter(([u]) => u === KEV_FEED_URL)).toHaveLength(1);
  });

  it("degrades to EPSS-only when the KEV feed is down", async () => {
    stubFeeds(false);
    const f = finding(["CVE-2020-11022"]);
    await enrichFindingsWithThreatIntel([f]);
    expect(f.threatIntel).toEqual({ knownExploited: false, epss: 0.021, epssPercentile: 0.88 });
  });

  it("never throws when both sources fail", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
    const f = finding(["CVE-2020-11022"]);
    await expect(enrichFindingsWithThreatIntel([f])).resolves.toBeUndefined();
    expect(f.threatIntel).toBeUndefined();
  });
});
