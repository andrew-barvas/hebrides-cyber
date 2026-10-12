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
  crtShEntries?: Array<{ name_value: string }>;
  crtShOk?: boolean;
  resolvingHosts?: string[]; // hosts that answer an A record on the DNS-over-HTTPS brute-force lookup
  httpOkHosts?: string[]; // hosts that answer the HEAD probe with 200
}) {
  return vi.fn(async (url: string) => {
    if (url.startsWith("https://crt.sh/")) {
      if (opts.crtShOk === false) return new Response(null, { status: 500 });
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
    expect(result).toEqual({ domain: "example.com", assetsDiscovered: 0, newAssets: 0, assets: [] });
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
