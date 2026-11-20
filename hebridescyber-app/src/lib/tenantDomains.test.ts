import { describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { isCoveredBy, loadTenantDomains, suggestTenantDomains } from "./tenantDomains";

describe("suggestTenantDomains", () => {
  it("keeps verified customer domains, unmonitored first, and drops Microsoft's own and unverified ones", () => {
    const out = suggestTenantDomains(
      [
        { id: "contoso.onmicrosoft.com", isVerified: true },
        { id: "Example.co.uk", isVerified: true },
        { id: "shop-example.com", isVerified: true },
        { id: "pending.com", isVerified: false },
        { id: "not a domain", isVerified: true },
        { id: "example.co.uk", isVerified: true },
        {},
      ],
      ["https://www.example.co.uk", "not a url ::"]
    );
    expect(out).toEqual([
      { domain: "shop-example.com", monitored: false },
      { domain: "example.co.uk", monitored: true },
    ]);
  });
});

describe("isCoveredBy", () => {
  it("counts the domain itself or a host under it, never a lookalike suffix", () => {
    expect(isCoveredBy("example.com", ["example.com"])).toBe(true);
    expect(isCoveredBy("example.com", ["shop.example.com"])).toBe(true);
    expect(isCoveredBy("example.com", ["badexample.com"])).toBe(false);
  });
});

describe("loadTenantDomains", () => {
  const TENANT = "11111111-2222-3333-4444-555555555555";
  const config = { clientId: "c", clientSecret: "s" };
  const db = (tenant: unknown, targets: unknown[] = []) =>
    ({
      from: (table: string) => ({
        select: () => ({
          eq: () =>
            table === "m365_tenants"
              ? { maybeSingle: async () => ({ data: tenant, error: null }) }
              : Promise.resolve({ data: targets, error: null }),
        }),
      }),
    }) as unknown as SupabaseClient;

  const token = `x.${Buffer.from(JSON.stringify({ roles: [], tid: TENANT })).toString("base64url")}.y`;
  const fetchOk = vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    if (u.includes("/oauth2/")) return new Response(JSON.stringify({ access_token: token }), { status: 200 });
    return new Response(JSON.stringify({ value: [{ id: "example.com", isVerified: true }, { id: "other.org", isVerified: true }] }), { status: 200 });
  }) as unknown as typeof fetch;

  it("is not_configured without the app credential and not_connected without a tenant", async () => {
    expect(await loadTenantDomains(db(null), "o", { config: null })).toEqual({ status: "not_configured" });
    expect(await loadTenantDomains(db(null), "o", { config })).toEqual({ status: "not_connected" });
  });

  it("reads the domains live and marks the ones already monitored", async () => {
    const r = await loadTenantDomains(db({ tenant_id: TENANT }, [{ target_url: "https://www.example.com" }]), "o", { config, fetchImpl: fetchOk });
    expect(r).toEqual({ status: "ok", source: "m365", truncated: false, domains: [{ domain: "other.org", monitored: false }, { domain: "example.com", monitored: true }] });
  });

  it("answers a fixed message when Microsoft refuses, never its error text", async () => {
    const refuse = vi.fn(async () => new Response(JSON.stringify({ error: "invalid_client", error_description: "AADSTS700016 secret detail" }), { status: 400 })) as unknown as typeof fetch;
    const r = await loadTenantDomains(db({ tenant_id: TENANT }), "o", { config, fetchImpl: refuse });
    expect(r.status).toBe("error");
    expect(JSON.stringify(r)).not.toContain("AADSTS");
  });
});
