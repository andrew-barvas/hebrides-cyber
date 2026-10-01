import { describe, it, expect, vi, afterEach } from "vitest";
import { checkSafeBrowsing, parseThreatMatchesResponse } from "./safeBrowsing";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("parseThreatMatchesResponse", () => {
  it("treats an empty body as clean — that is Google's normal answer", () => {
    expect(parseThreatMatchesResponse({})).toEqual({ flagged: false, matches: [], threatTypes: [] });
  });

  it("collects matches and de-duplicates threat types", () => {
    const parsed = parseThreatMatchesResponse({
      matches: [
        { threatType: "MALWARE", platformType: "WINDOWS", threatEntryType: "URL" },
        { threatType: "MALWARE", platformType: "ANY_PLATFORM" },
        { threatType: "SOCIAL_ENGINEERING" },
      ],
    });
    expect(parsed.flagged).toBe(true);
    expect(parsed.threatTypes).toEqual(["MALWARE", "SOCIAL_ENGINEERING"]);
    expect(parsed.matches[2]).toEqual({ threatType: "SOCIAL_ENGINEERING", platformType: "UNKNOWN", threatEntryType: "URL" });
  });
});

describe("checkSafeBrowsing", () => {
  it("is not_configured without a key, and makes no request", async () => {
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect((await checkSafeBrowsing("https://example.com")).status).toBe("not_configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("asks about exactly the target URL and reports a match", async () => {
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key");
    const fetchMock = vi.fn<(url: string, init: RequestInit) => Promise<Response>>(async () => new Response(JSON.stringify({ matches: [{ threatType: "MALWARE" }] })));
    vi.stubGlobal("fetch", fetchMock);

    const result = await checkSafeBrowsing("https://example.com/shop");
    expect(result).toMatchObject({ status: "checked", flagged: true, threatTypes: ["MALWARE"] });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toMatch(/^https:\/\/safebrowsing\.googleapis\.com\/v4\/threatMatches:find\?key=/);
    const body = JSON.parse(String(init.body));
    expect(body.threatInfo.threatEntries).toEqual([{ url: "https://example.com/shop" }]);
    expect(body.threatInfo.threatTypes).toEqual(["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]);
  });

  // An API failure must never read as "clean".
  it("reports an error, not a clean result, when the API fails", async () => {
    vi.stubEnv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("quota", { status: 429 })));
    expect(await checkSafeBrowsing("https://example.com")).toEqual({ status: "error", note: "Safe Browsing API returned HTTP 429" });

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
    expect((await checkSafeBrowsing("https://example.com")).status).toBe("error");
  });
});
