import { describe, it, expect, vi, afterEach } from "vitest";
import { checkHibp, hibpBreachSeverity, parseBreachDetail, summariseBreachedDomainResponse, type HibpBreach } from "./hibp";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

const breach = (dataClasses: string[]): HibpBreach => ({
  name: "X",
  title: "X",
  breachDate: null,
  dataClasses,
  description: "",
  isSensitive: false,
  isVerified: true,
  affectedAliasCount: 1,
});

describe("pure helpers", () => {
  it("counts affected aliases per breach", () => {
    const counts = summariseBreachedDomainResponse({ alice: ["Adobe", "LinkedIn"], bob: ["Adobe"], carol: [] });
    expect([...counts]).toEqual([
      ["Adobe", 2],
      ["LinkedIn", 1],
    ]);
  });

  it("strips HIBP's HTML from the description", () => {
    const parsed = parseBreachDetail({ Name: "Adobe", Description: 'In 2013, <a href="https://x">Adobe</a> was breached.' }, 3);
    expect(parsed).toMatchObject({ name: "Adobe", title: "Adobe", description: "In 2013, Adobe was breached.", affectedAliasCount: 3, isVerified: true });
  });

  it("grades severity by the data actually exposed", () => {
    expect(hibpBreachSeverity(breach(["Email addresses", "Passwords"]))).toBe("high");
    expect(hibpBreachSeverity(breach(["Email addresses", "Credit cards"]))).toBe("high");
    expect(hibpBreachSeverity(breach(["Email addresses", "Names"]))).toBe("medium");
    expect(hibpBreachSeverity(breach([]))).toBe("low");
  });
});

describe("checkHibp", () => {
  function hibp(routes: Record<string, Response | (() => Response)>) {
    const fetchMock = vi.fn(async (url: string) => {
      const path = url.replace("https://haveibeenpwned.com/api/v3", "");
      const r = routes[path];
      if (!r) return new Response("", { status: 404 });
      return typeof r === "function" ? r() : r;
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("is not_configured without a key", async () => {
    vi.stubEnv("HIBP_API_KEY", "");
    expect((await checkHibp("https://example.com")).status).toBe("not_configured");
  });

  it("searches the registered domain, not the scanned subdomain", async () => {
    vi.stubEnv("HIBP_API_KEY", "k");
    const fetchMock = hibp({});
    const result = await checkHibp("https://shop.example.co.uk/basket");
    expect(result).toEqual({ status: "checked", domain: "example.co.uk", breaches: [], affectedAliasCount: 0 });
    expect(fetchMock.mock.calls[0][0]).toBe("https://haveibeenpwned.com/api/v3/breacheddomain/example.co.uk");
  });

  // 403 is HIBP's own domain verification, unrelated to ours — not "no breaches".
  it("reports not_verified on 403", async () => {
    vi.stubEnv("HIBP_API_KEY", "k");
    hibp({ "/breacheddomain/example.com": new Response("", { status: 403 }) });
    expect(await checkHibp("https://www.example.com")).toMatchObject({ status: "not_verified", domain: "example.com" });
  });

  it.each([
    [401, /rejected the API key/],
    [429, /rate-limited/],
    [500, /HTTP 500/],
  ])("reports HTTP %i as an error", async (status, note) => {
    vi.stubEnv("HIBP_API_KEY", "k");
    hibp({ "/breacheddomain/example.com": new Response("", { status }) });
    const result = await checkHibp("https://example.com");
    expect(result.status).toBe("error");
    expect(result.status === "error" && result.note).toMatch(note);
  });

  it("enriches each breach, newest first, and keeps a breach whose detail lookup failed", async () => {
    vi.stubEnv("HIBP_API_KEY", "k");
    hibp({
      "/breacheddomain/example.com": () => new Response(JSON.stringify({ alice: ["Adobe", "Canva"], bob: ["Adobe"] })),
      "/breach/Canva": () => new Response(JSON.stringify({ Name: "Canva", BreachDate: "2019-05-24", DataClasses: ["Passwords"] })),
      "/breach/Adobe": () => new Response("", { status: 503 }),
    });
    const result = await checkHibp("https://example.com");
    if (result.status !== "checked") throw new Error(JSON.stringify(result));
    expect(result.affectedAliasCount).toBe(2);
    expect(result.breaches.map((b) => [b.name, b.breachDate, b.affectedAliasCount])).toEqual([
      ["Canva", "2019-05-24", 1],
      ["Adobe", null, 2],
    ]);
  });
});
