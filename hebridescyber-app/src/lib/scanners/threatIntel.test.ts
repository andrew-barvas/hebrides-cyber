import { describe, it, expect, vi, afterEach } from "vitest";
import {
  EPSS_API_URL,
  EXPLOITDB_INDEX_URL,
  KEV_FEED_URL,
  applyThreatIntel,
  enrichFindingsWithThreatIntel,
  parseEpss,
  parseExploitDbIndex,
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

  it("keeps the descriptive fields emerging-threat alerts need, and drops malformed dates", () => {
    const kev = parseKev({
      vulnerabilities: [
        { cveID: "cve-2024-4577", vendorProject: "PHP Group", product: "PHP", vulnerabilityName: "PHP-CGI OS Command Injection", dateAdded: "2024-06-12" },
        { cveID: "CVE-2024-0001", dateAdded: "June 2024", product: "  " },
      ],
    });
    expect(kev.get("CVE-2024-4577")).toEqual({
      ransomware: false, vendorProject: "PHP Group", product: "PHP", vulnerabilityName: "PHP-CGI OS Command Injection", dateAdded: "2024-06-12",
    });
    expect(kev.get("CVE-2024-0001")).toEqual({ ransomware: false });
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

const EDB_CSV = [
  "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags",
  '16929,exploits/a.rb,"Thing, with a comma ""and quotes""",2010-11-11,x,dos,aix,,2010-11-11,2011-03-06,1,CVE-2009-3699;OSVDB-58726,',
  "50000,exploits/b.py,Other,2024-01-01,y,remote,linux,22,2024-01-01,2024-01-02,0,CVE-2024-6387,",
  "50001,exploits/c.py,Same CVE,2024-01-03,y,remote,linux,22,2024-01-03,2024-01-03,0,cve-2024-6387;CVE-2024-6387,",
  "bad,exploits/d.py,No id,2024-01-03,y,remote,linux,,2024-01-03,2024-01-03,0,CVE-2099-0001,",
].join("\r\n");

describe("Exploit-DB public-exploit signal", () => {
  it("parses CVE ids out of the index's codes column, quote-aware, de-duplicated", () => {
    const index = parseExploitDbIndex(EDB_CSV);
    expect(index.get("CVE-2009-3699")).toEqual(["16929"]);
    expect(index.get("CVE-2024-6387")).toEqual(["50000", "50001"]);
    expect(index.has("CVE-2099-0001")).toBe(false);
    expect(parseExploitDbIndex("not,a,known,header\n1,2,3,4").size).toBe(0);
  });

  it("marks checked-and-listed, checked-and-none, and leaves it absent when the index didn't load", () => {
    const index = parseExploitDbIndex(EDB_CSV);
    const listed = finding(["CVE-2024-6387"]);
    const none = finding(["CVE-2020-11022"]);
    applyThreatIntel([listed, none], null, null, index);
    expect(listed.threatIntel?.publicExploit).toEqual({ exploitDbIds: ["50000", "50001"] });
    expect(none.threatIntel?.publicExploit).toEqual({ exploitDbIds: [] });

    const unknown = finding(["CVE-2024-6387"]);
    applyThreatIntel([unknown], parseKev(KEV_BODY), null, null);
    expect(unknown.threatIntel?.publicExploit).toBeUndefined();
  });

  it("loads the index once per day and never throws when it can't", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === EXPLOITDB_INDEX_URL) return new Response(EDB_CSV);
      throw new Error("offline");
    });
    vi.stubGlobal("fetch", fetchMock);
    const f = finding(["CVE-2024-6387"]);
    await enrichFindingsWithThreatIntel([f], 1_000);
    expect(f.threatIntel?.publicExploit?.exploitDbIds).toEqual(["50000", "50001"]);
    await enrichFindingsWithThreatIntel([finding(["CVE-2024-6387"])], 2_000);
    expect(fetchMock.mock.calls.filter(([u]) => u === EXPLOITDB_INDEX_URL)).toHaveLength(1);

    resetThreatIntelCache();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("down", { status: 503 })));
    const g = finding(["CVE-2024-6387"]);
    await expect(enrichFindingsWithThreatIntel([g])).resolves.toBeUndefined();
    expect(g.threatIntel).toBeUndefined();
  });
});
