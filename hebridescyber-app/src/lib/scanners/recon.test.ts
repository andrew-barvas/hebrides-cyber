import { describe, it, expect, vi, afterEach } from "vitest";
import { checkRecon } from "./recon";

afterEach(() => vi.unstubAllGlobals());

type Routes = { dns?: unknown; shodan?: { status: number; body?: unknown }; crt?: { status: number; body?: unknown } };

function serve(routes: Routes) {
  const fetchMock = vi.fn(async (url: string) => {
    if (url.startsWith("https://cloudflare-dns.com/")) return new Response(JSON.stringify(routes.dns ?? { Answer: [] }));
    if (url.startsWith("https://internetdb.shodan.io/")) {
      const r = routes.shodan ?? { status: 404 };
      return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
    }
    if (url.startsWith("https://crt.sh/")) {
      const r = routes.crt ?? { status: 200, body: [] };
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

  it("returns an empty list when crt.sh is down, never a failed scan", async () => {
    serve({ dns: A, crt: { status: 503 } });
    expect(await checkRecon("https://example.com")).toMatchObject({ status: "checked", subdomains: [] });
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
