import { describe, it, expect, vi } from "vitest";

const { exchange } = vi.hoisted(() => ({ exchange: vi.fn(async () => ({ error: null })) }));
vi.mock("@/lib/supabase/server", () => ({ createServerSupabaseClient: async () => ({ auth: { exchangeCodeForSession: exchange } }) }));

import { GET } from "./route";

const go = async (query: string) => (await GET(new Request(`https://www.hebridescyber.co.uk/auth/callback?${query}`))).headers.get("location");

describe("GET /auth/callback", () => {
  it("lands on the requested path on this site", async () => {
    expect(await go(`code=abc&next=${encodeURIComponent("/pricing?checkout=pro")}`)).toBe("https://www.hebridescyber.co.uk/pricing?checkout=pro");
  });

  it("never redirects off the site, whatever next says", async () => {
    for (const next of ["@evil.example", "//evil.example", "/\\evil.example", "https://evil.example"]) {
      const location = await go(`code=abc&next=${encodeURIComponent(next)}`);
      expect(new URL(location!).host, next).toBe("www.hebridescyber.co.uk");
      expect(location).toBe("https://www.hebridescyber.co.uk/dashboard");
    }
  });
});
