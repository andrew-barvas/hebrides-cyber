import { describe, it, expect, vi, afterEach } from "vitest";
import { checkRecon } from "./recon";

afterEach(() => vi.unstubAllGlobals());

type Reply = { status: number; body?: unknown };
type Routes = { dns?: unknown; shodan?: Reply; crt?: Reply | Reply[] };

function serve(routes: Routes) {
  let crtCalls = 0;
  const fetchMock = vi.fn(async (url: string) => {
    if (url.startsWith("https://cloudflare-dns.com/")) return new Response(JSON.stringify(routes.dns ?? { Answer: [] }));
    if (url.startsWith("https://internetdb.shodan.io/")) {
      const r = routes.shodan ?? { status: 404 };
      return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
    }
    if (url.startsWith("https://crt.sh/")) {
      // An array is a sequence of replies, one per request.
      const replies = Array.isArray(routes.crt) ? routes.crt : [routes.crt ?? { status: 200, body: [] }];
      const r = replies[Math.min(crtCalls++, replies.length - 1)];
      return new Response(JSON.stringify(r.body ?? []), { status: r.status });
    }
    throw new Error(`unexpected ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

const A = { Answer: [{ type: 1, data: "203.0.113.7" }] };

describe("checkRecon", () => {
  it("resolves the IP and returns Shodan data for it", async () => {
    serve({ dns: A, shodan: { status: 200, body: { cves: ["CVE-2021-44228"], ports: [80, 443], tags: ["cdn"] } } });
    const result = await checkRecon("https://www.example.com");
    expect(result).toMatchObject({
      status: "checked",
      ip: "203.0.113.7",
      shodan: { cves: ["CVE-2021-44228"], ports: [80, 443], tags: ["cdn"], cpes: [], hostnames: [] },
    });
  });

  it("treats Shodan's 404 as 'no data', and skips Shodan with no IP", async () => {
    serve({ dns: A, shodan: { status: 404 } });
    expect((await checkRecon("https://example.com")) as { shodan: unknown }).toMatchObject({ shodan: null });

    const fetchMock = serve({ dns: { Answer: [] } });
    expect(await checkRecon("https://example.com")).toMatchObject({ ip: null, shodan: null });
    expect(fetchMock.mock.calls.some(([u]) => String(u).includes("internetdb"))).toBe(false);
  });

  it("de-duplicates CT names, splits multi-name certs and folds wildcards into their base", async () => {
    serve({
      crt: {
        status: 200,
        body: [
          { name_value: "shop.example.com\nwww.example.com", issuer_name: "R3", not_before: "2026-01-01" },
          { name_value: "*.api.example.com", issuer_name: "R3" },
          { name_value: "api.example.com", issuer_name: "R3" },
          { name_value: "SHOP.example.com", issuer_name: "R3" },
        ],
      },
    });
    const result = await checkRecon("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.subdomains.map((s) => s.name)).toEqual(["api.example.com", "shop.example.com", "www.example.com"]);
  });

  // Regression: "*.example.com" stripped to "example.com" was listed as a
  // subdomain of itself.
  it("never lists the domain itself, including via a wildcard certificate", async () => {
    serve({ crt: { status: 200, body: [{ name_value: "*.example.com" }, { name_value: "example.com" }, { name_value: "a.example.com" }] } });
    const result = await checkRecon("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.subdomains.map((s) => s.name)).toEqual(["a.example.com"]);
  });

  // Regression: scanning a subdomain only searched beneath it.
  it("enumerates the whole registered domain when scanning a subdomain", async () => {
    const fetchMock = serve({});
    await checkRecon("https://shop.example.co.uk/basket");
    const crtUrl = String(fetchMock.mock.calls.find(([u]) => String(u).startsWith("https://crt.sh/"))![0]);
    expect(crtUrl).toBe("https://crt.sh/?q=%25.example.co.uk&output=json");
  });

  // Regression: a site on a platform's shared domain searched every site on it.
  it("enumerates only the site's own names on a shared hosting domain", async () => {
    for (const [target, query] of [
      ["https://mysite.github.io/", "%25.mysite.github.io"],
      ["https://www.stmarys.herts.sch.uk/", "%25.stmarys.herts.sch.uk"],
    ]) {
      const fetchMock = serve({});
      await checkRecon(target);
      const crtUrl = String(fetchMock.mock.calls.find(([u]) => String(u).startsWith("https://crt.sh/"))![0]);
      expect(crtUrl).toBe(`https://crt.sh/?q=${query}&output=json`);
    }
  });

  // Regression: an outage used to read as "no subdomains", which let
  // takeover and subdomain-cert findings be marked fixed.
  it("says the lookup failed when crt.sh is down, without failing the scan", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = serve({ dns: A, crt: { status: 503 } });
      const pending = checkRecon("https://example.com");
      await vi.advanceTimersByTimeAsync(2_000);
      expect(await pending).toMatchObject({ status: "checked", subdomains: [], ctLookupFailed: true });
      expect(fetchMock.mock.calls.filter(([u]) => String(u).startsWith("https://crt.sh/"))).toHaveLength(2); // one retry
    } finally {
      vi.useRealTimers();
    }
  });

  it("recovers from a momentary crt.sh error with one retry", async () => {
    vi.useFakeTimers();
    try {
      serve({ crt: [{ status: 502 }, { status: 200, body: [{ name_value: "shop.example.com" }] }] });
      const pending = checkRecon("https://example.com");
      await vi.advanceTimersByTimeAsync(2_000);
      const result = await pending;
      expect(result).toMatchObject({ status: "checked", subdomains: [{ name: "shop.example.com" }] });
      expect(result).not.toHaveProperty("ctLookupFailed");
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the most recently certified hosts when capping, listed alphabetically", async () => {
    const body = Array.from({ length: 60 }, (_, i) => ({ name_value: `h${String(i).padStart(2, "0")}.example.com`, not_before: `2026-01-01T00:00:${String(i).padStart(2, "0")}` }));
    body.push({ name_value: "h00.example.com", not_before: "2026-09-01T00:00:00" }); // h00 renewed recently
    serve({ crt: { status: 200, body } });
    const result = await checkRecon("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    const names = result.subdomains.map((s) => s.name);
    expect(names).toContain("h00.example.com");
    expect(names).not.toContain("h01.example.com"); // among the oldest
    expect(names).toEqual([...names].sort());
    expect(result.subdomains.find((s) => s.name === "h00.example.com")?.notBefore).toBe("2026-09-01T00:00:00");
  });

  it("records when each name first appeared in CT, whatever order crt.sh lists its certificates in", async () => {
    serve({
      crt: {
        status: 200,
        body: [
          { name_value: "shop.example.com", not_before: "2026-09-01T00:00:00", issuer_name: "R11" },
          { name_value: "shop.example.com\n*.api.example.com", not_before: "2023-02-01T00:00:00", issuer_name: "R3" },
          { name_value: "api.example.com", not_before: "2026-10-01T00:00:00", issuer_name: "R10" },
          { name_value: "undated.example.com" },
        ],
      },
    });
    const result = await checkRecon("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.subdomains).toEqual([
      { name: "api.example.com", issuer: "R10", notBefore: "2026-10-01T00:00:00", firstNotBefore: "2023-02-01T00:00:00" },
      { name: "shop.example.com", issuer: "R11", notBefore: "2026-09-01T00:00:00", firstNotBefore: "2023-02-01T00:00:00" },
      { name: "undated.example.com", issuer: "", notBefore: "" },
    ]);
  });

  it("caps the list at 50", async () => {
    serve({ crt: { status: 200, body: Array.from({ length: 80 }, (_, i) => ({ name_value: `h${String(i).padStart(2, "0")}.example.com` })) } });
    const result = await checkRecon("https://example.com");
    if (result.status !== "checked") throw new Error("expected checked");
    expect(result.subdomains).toHaveLength(50);
  });

  it("returns an error result for an unparseable target", async () => {
    expect((await checkRecon("not a url")).status).toBe("error");
  });
});
