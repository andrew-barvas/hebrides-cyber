import { describe, it, expect, vi, beforeEach } from "vitest";
import { runEasmDiscovery } from "./easmDiscovery";

type Row = Record<string, unknown>;

function fakeSupabase(existingHostnames: string[] = []) {
  const upserts: Row[] = [];
  const client = {
    from: (table: string) => {
      if (table !== "asset_inventory") throw new Error(`unexpected table: ${table}`);
      return {
        select: () => ({
          eq: () => ({
            like: () => Promise.resolve({ data: existingHostnames.map((hostname) => ({ hostname })), error: null }),
          }),
        }),
        upsert: (row: Row) => {
          upserts.push(row);
          return Promise.resolve({ data: null, error: null });
        },
      };
    },
  };
  return { client: client as never, upserts };
}

function fetchMockFor(opts: {
  crtShEntries?: Array<{ name_value: string; not_before?: string }>;
  crtShOk?: boolean;
  /** crt.sh answers 200 but with something that is not a certificate list (it sometimes serves an HTML error page). */
  crtShBody?: string;
  resolvingHosts?: string[]; // hosts that answer an A record on the DNS-over-HTTPS brute-force lookup
  httpOkHosts?: string[]; // hosts that answer the HEAD probe with 200
}) {
  return vi.fn(async (url: string) => {
    if (url.startsWith("https://crt.sh/")) {
      if (opts.crtShOk === false) return new Response(null, { status: 500 });
      if (opts.crtShBody !== undefined) return new Response(opts.crtShBody, { status: 200 });
      return new Response(JSON.stringify(opts.crtShEntries ?? []), { status: 200 });
    }
    if (url.startsWith("https://cloudflare-dns.com/")) {
      const name = new URL(url).searchParams.get("name") ?? "";
      const resolves = (opts.resolvingHosts ?? []).includes(name);
      return new Response(JSON.stringify({ Answer: resolves ? [{ type: 1, data: "1.2.3.4" }] : [] }), { status: 200 });
    }
    // HTTP(S) HEAD probe of a discovered host.
    const host = new URL(url).hostname;
    const ok = (opts.httpOkHosts ?? []).includes(host);
    return new Response(null, { status: ok ? 200 : 404 });
  });
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("runEasmDiscovery", () => {
  it("discovers new subdomains via crt.sh, probes them, and saves them to asset_inventory", async () => {
    vi.stubGlobal(
      "fetch",
      fetchMockFor({
        crtShEntries: [{ name_value: "api.example.com\n*.dev.example.com" }],
        httpOkHosts: ["api.example.com"],
      })
    );
    const { client, upserts } = fakeSupabase([]);

    const result = await runEasmDiscovery(client, "owner-1", "example.com");

    expect(result.domain).toBe("example.com");
    expect(result.newAssets).toBe(2);
    const hostnames = upserts.map((u) => u.hostname);
    expect(hostnames).toEqual(expect.arrayContaining(["api.example.com", "dev.example.com"]));
    expect(upserts.every((u) => u.owner === "owner-1")).toBe(true);
    const apiAsset = result.assets.find((a) => a.hostname === "api.example.com");
    expect(apiAsset).toMatchObject({ source: "crt.sh", httpStatus: 200 });
  });

  it("does not re-probe or re-save a hostname already in asset_inventory", async () => {
    vi.stubGlobal("fetch", fetchMockFor({ crtShEntries: [{ name_value: "api.example.com" }] }));
    const { client, upserts } = fakeSupabase(["api.example.com"]);

    const result = await runEasmDiscovery(client, "owner-1", "example.com");

    expect(result.newAssets).toBe(0);
    expect(upserts).toHaveLength(0);
  });

  it("never runs DNS brute-force unless bruteForce: true is explicitly passed", async () => {
    const fetchMock = fetchMockFor({ crtShEntries: [], resolvingHosts: ["admin.example.com"] });
    vi.stubGlobal("fetch", fetchMock);
    const { client } = fakeSupabase([]);

    await runEasmDiscovery(client, "owner-1", "example.com");
    expect(fetchMock.mock.calls.some((c) => (c[0] as string).includes("cloudflare-dns.com"))).toBe(false);

    await runEasmDiscovery(client, "owner-1", "example.com", { bruteForce: true });
    expect(fetchMock.mock.calls.some((c) => (c[0] as string).includes("cloudflare-dns.com"))).toBe(true);
  });

  it("finds hosts the brute-force prefix list resolves, when bruteForce: true", async () => {
    vi.stubGlobal(
      "fetch",
      fetchMockFor({ crtShEntries: [], resolvingHosts: ["admin.example.com"], httpOkHosts: ["admin.example.com"] })
    );
    const { client } = fakeSupabase([]);

    const result = await runEasmDiscovery(client, "owner-1", "example.com", { bruteForce: true });

    expect(result.assets.some((a) => a.hostname === "admin.example.com" && a.source === "dns-brute")).toBe(true);
  });

  it("is never confirmed/overridden by brute-force when crt.sh already found the same host", async () => {
    vi.stubGlobal(
      "fetch",
      fetchMockFor({ crtShEntries: [{ name_value: "admin.example.com" }], resolvingHosts: ["admin.example.com"] })
    );
    const { client } = fakeSupabase([]);

    const result = await runEasmDiscovery(client, "owner-1", "example.com", { bruteForce: true });

    const admin = result.assets.filter((a) => a.hostname === "admin.example.com");
    expect(admin).toHaveLength(1);
    expect(admin[0].source).toBe("crt.sh");
  });

  it("never throws — a crt.sh failure or a database error just returns an empty result", async () => {
    vi.stubGlobal("fetch", fetchMockFor({ crtShOk: false }));
    const brokenClient = {
      from: () => {
        throw new Error("supabase down");
      },
    } as never;

    const result = await runEasmDiscovery(brokenClient, "owner-1", "example.com");
    // `ctRead: false` is the point: the empty result is "could not look", not "nothing there".
    expect(result).toEqual({ domain: "example.com", assetsDiscovered: 0, newAssets: 0, assets: [], firstCertificates: new Map(), ctRead: false });
  });

  describe("certificate evidence", () => {
    beforeEach(() => {
      vi.spyOn(console, "warn").mockImplementation(() => {});
    });

    it("returns each hostname's earliest certificate date and says crt.sh was read", async () => {
      vi.stubGlobal(
        "fetch",
        fetchMockFor({
          crtShEntries: [
            // api has two certificates; the earliest date is the evidence it is new, not the renewal.
            { name_value: "api.example.com", not_before: "2026-10-01T09:00:00" },
            { name_value: "api.example.com\n*.dev.example.com", not_before: "2026-08-01T09:00:00" },
            { name_value: "elsewhere.other.net", not_before: "2026-10-02T09:00:00" },
          ],
        })
      );
      const { client } = fakeSupabase([]);

      const result = await runEasmDiscovery(client, "owner-1", "example.com");

      expect(result.ctRead).toBe(true);
      expect(result.firstCertificates.get("api.example.com")).toBe("2026-08-01T09:00:00");
      expect(result.firstCertificates.get("dev.example.com")).toBe("2026-08-01T09:00:00"); // wildcard base, lowercased
      expect(result.firstCertificates.has("elsewhere.other.net")).toBe(false); // outside the domain
    });

    it("reports a failed lookup as ctRead false, not as an empty success", async () => {
      vi.stubGlobal("fetch", fetchMockFor({ crtShOk: false }));
      const { client, upserts } = fakeSupabase([]);

      const result = await runEasmDiscovery(client, "owner-1", "example.com");

      expect(result.ctRead).toBe(false);
      expect(result.firstCertificates.size).toBe(0);
      expect(upserts).toHaveLength(0);
    }, 10_000);

    it("treats a 200 reply that is not a certificate list as a failure (crt.sh serves HTML error pages)", async () => {
      vi.stubGlobal("fetch", fetchMockFor({ crtShBody: "<html><body>Bad gateway</body></html>" }));
      const { client } = fakeSupabase([]);

      const result = await runEasmDiscovery(client, "owner-1", "example.com");

      expect(result.ctRead).toBe(false);
    });

    it("treats a JSON reply that is not an array as a failure too", async () => {
      vi.stubGlobal("fetch", fetchMockFor({ crtShBody: JSON.stringify({ error: "rate limited" }) }));
      const { client } = fakeSupabase([]);

      expect((await runEasmDiscovery(client, "owner-1", "example.com")).ctRead).toBe(false);
    });

    it("keeps the most recently certified hostnames when there are more than the cap, so a new one is never the one cut", async () => {
      // 250 old hostnames and one brand-new one listed LAST, where a plain slice(0, 200) would drop it.
      const old = Array.from({ length: 250 }, (_, i) => ({ name_value: `old${String(i).padStart(3, "0")}.example.com`, not_before: "2020-01-01T00:00:00" }));
      const fresh = { name_value: "brand-new.example.com", not_before: "2026-10-05T00:00:00" };
      vi.stubGlobal("fetch", fetchMockFor({ crtShEntries: [...old, fresh], httpOkHosts: ["brand-new.example.com"] }));
      const { client, upserts } = fakeSupabase([]);

      const result = await runEasmDiscovery(client, "owner-1", "example.com");

      expect(result.assetsDiscovered).toBe(200);
      expect(result.assets.some((a) => a.hostname === "brand-new.example.com")).toBe(true);
      expect(upserts.some((u) => u.hostname === "brand-new.example.com")).toBe(true);
    });
  });

  describe("which URL new rows are stored under", () => {
    it("stores the monitored site's URL, so a scan of that site's alert can find the rows", async () => {
      vi.stubGlobal("fetch", fetchMockFor({ crtShEntries: [{ name_value: "api.example.com" }], httpOkHosts: ["api.example.com"] }));
      const { client, upserts } = fakeSupabase([]);

      await runEasmDiscovery(client, "owner-1", "example.com", { targetUrl: "https://www.example.com" });

      expect(upserts).toHaveLength(1);
      expect(upserts[0].target_url).toBe("https://www.example.com");
    });

    it("falls back to https://<domain> for a caller that only knows the domain", async () => {
      vi.stubGlobal("fetch", fetchMockFor({ crtShEntries: [{ name_value: "api.example.com" }], httpOkHosts: ["api.example.com"] }));
      const { client, upserts } = fakeSupabase([]);

      await runEasmDiscovery(client, "owner-1", "example.com");

      expect(upserts[0].target_url).toBe("https://example.com");
    });
  });

  it("caps how many newly-discovered hosts get probed and saved in one run", async () => {
    const many = Array.from({ length: 40 }, (_, i) => `h${i}.example.com`);
    vi.stubGlobal(
      "fetch",
      fetchMockFor({ crtShEntries: [{ name_value: many.join("\n") }], httpOkHosts: many })
    );
    const { client, upserts } = fakeSupabase([]);

    const result = await runEasmDiscovery(client, "owner-1", "example.com");

    expect(result.newAssets).toBe(40); // the true count...
    expect(upserts.length).toBeLessThan(40); // ...but only a bounded number get saved this run
    expect(upserts.length).toBeGreaterThan(0);
  });
});
