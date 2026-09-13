import { describe, it, expect, vi } from "vitest";
import { syncAssetInventory } from "./assetInventory";
import type { ScanResults } from "./scanners";

function baseResults(overrides: Partial<ScanResults> = {}): ScanResults {
  return {
    tls: { status: "checked", isHttps: true, protocol: "TLSv1.3", weakProtocol: false, weakCipher: false, selfSigned: false, certificateExpiresAt: null, daysUntilExpiry: null, hsts: { present: true, adequate: true, maxAge: 31536000 } },
    headers: { status: "checked", owasp: { headers: [], score: 100 }, csp: { present: true, grade: "A", issues: [] }, cookies: [], cors: { wildcardOrigin: false }, infoDisclosure: { issues: [] } },
    dns: { status: "checked" },
    exposure: { status: "checked", exposed: [], securityTxtPresent: true },
    directoryListing: { status: "checked", open: [] },
    cloudMisconfig: { status: "checked", buckets: [] },
    fingerprint: { status: "checked", technologies: [], riskySoftware: [] },
    ports: { status: "checked", ports: [] },
    recon: { status: "checked", ip: "1.2.3.4", shodan: null, subdomains: [] },
    safeBrowsing: { status: "not_configured" },
    waybackDiscovery: { status: "checked", livePaths: [] },
    hibp: { status: "not_configured" },
    wpvdb: { status: "not_applicable" },
    playwright: { status: "checked" },
    webapp: { status: "checked" },
    zap: { status: "not_configured" },
    target_url: "https://example.com",
    ...overrides,
  } as unknown as ScanResults;
}

function fakeSupabase() {
  const upsertCalls: { table: string; rows: unknown[] }[] = [];
  return {
    client: {
      from: (table: string) => ({
        upsert: vi.fn((rows: unknown[]) => {
          upsertCalls.push({ table, rows });
          return Promise.resolve({ error: null });
        }),
      }),
    },
    upsertCalls,
  };
}

describe("syncAssetInventory", () => {
  it("upserts the root domain with its CMS type and cloud hints", async () => {
    const { client, upsertCalls } = fakeSupabase();
    const results = baseResults({
      fingerprint: {
        status: "checked",
        technologies: [
          { name: "WordPress", category: "CMS", version: null, confidence: "high", source: "html" },
          { name: "Cloudflare", category: "CDN", version: null, confidence: "high", source: "header" },
        ],
        riskySoftware: [],
      },
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await syncAssetInventory(client as any, "owner-1", "https://example.com", results, undefined);

    expect(upsertCalls).toHaveLength(1);
    expect(upsertCalls[0].table).toBe("asset_inventory");
    const rootRow = upsertCalls[0].rows[0] as Record<string, unknown>;
    expect(rootRow.hostname).toBe("example.com");
    expect(rootRow.kind).toBe("domain");
    expect(rootRow.cms_type).toBe("wordpress");
    expect(rootRow.cloud_hints).toEqual(["Cloudflare"]);
    expect(rootRow).not.toHaveProperty("first_seen_at");
  });

  it("includes Subfinder-discovered subdomains when the extended tool ran", async () => {
    const { client, upsertCalls } = fakeSupabase();
    const results = baseResults();
    const extended = {
      subdomains: {
        status: "completed",
        subdomains: [
          { host: "api.example.com" },
          { host: "example.com" }, // root hostname — must be de-duplicated, not double-inserted
        ],
      },
    };

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await syncAssetInventory(client as any, "owner-1", "https://example.com", results, extended);

    const rows = upsertCalls[0].rows as Record<string, unknown>[];
    expect(rows).toHaveLength(2); // root + api.example.com, not the duplicated root
    expect(rows.map((r) => r.hostname)).toEqual(["example.com", "api.example.com"]);
    expect(rows[1].kind).toBe("subdomain");
  });

  it("falls back to recon.ts's crt.sh subdomains when Subfinder didn't run", async () => {
    const { client, upsertCalls } = fakeSupabase();
    const results = baseResults({
      recon: { status: "checked", ip: "1.2.3.4", shodan: null, subdomains: [{ name: "mail.example.com", issuer: "Let's Encrypt", notBefore: "2026-01-01" }] },
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await syncAssetInventory(client as any, "owner-1", "https://example.com", results, undefined);

    const rows = upsertCalls[0].rows as Record<string, unknown>[];
    expect(rows.map((r) => r.hostname)).toEqual(["example.com", "mail.example.com"]);
  });

  it("never throws when the upsert itself fails — best-effort, must not fail the scan", async () => {
    const client = { from: () => ({ upsert: () => Promise.resolve({ error: { message: "boom" } }) }) };
    const results = baseResults();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(syncAssetInventory(client as any, "owner-1", "https://example.com", results, undefined)).resolves.toBeUndefined();
  });

  it("never throws when the target_url itself is unparseable", async () => {
    const client = { from: () => ({ upsert: () => Promise.resolve({ error: null }) }) };
    const results = baseResults();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await expect(syncAssetInventory(client as any, "owner-1", "not-a-url", results, undefined)).resolves.toBeUndefined();
  });
});
