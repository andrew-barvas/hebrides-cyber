import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

const { replies } = vi.hoisted(() => ({
  replies: {
    verifications: { data: [] as unknown, error: null as unknown },
    users: { data: null as unknown, error: null as unknown },
  },
}));

vi.mock("@/lib/supabaseClient", () => ({
  supabase: {
    from: (table: "verifications" | "users") => ({
      select: () => ({
        not: async () => replies.verifications,
        maybeSingle: async () => replies[table],
      }),
    }),
  },
}));

import { scanTargetHint, useVerifiedDomains } from "./verifiedDomains";

describe("useVerifiedDomains", () => {
  beforeEach(() => {
    replies.verifications = { data: [{ domain: "Example.com" }, { domain: "shop.test" }], error: null };
    replies.users = { data: { is_admin: false }, error: null };
  });

  it("loads the user's verified hostnames, lower-cased, and whether they are an admin", async () => {
    const { result } = renderHook(() => useVerifiedDomains());
    expect(result.current.loaded).toBe(false);
    await waitFor(() => expect(result.current.loaded).toBe(true));
    expect([...result.current.domains].sort()).toEqual(["example.com", "shop.test"]);
    expect(result.current.isAdmin).toBe(false);
  });

  it("stays unloaded when the read fails, so no wrong hint is shown", async () => {
    replies.verifications = { data: null, error: { message: "down" } };
    replies.users = { data: { is_admin: true }, error: null };
    const { result } = renderHook(() => useVerifiedDomains());
    await waitFor(() => expect(result.current.isAdmin).toBe(true));
    expect(result.current.loaded).toBe(false);
    expect(scanTargetHint("https://x.test", result.current)).toBeNull();
  });
});

describe("scanTargetHint", () => {
  const verified = { domains: new Set(["www.example.com"]), isAdmin: false, loaded: true };

  it("finds the apex/www twin in either direction", () => {
    expect(scanTargetHint("https://example.com", verified)).toEqual({ host: "example.com", verifiedAlternative: "www.example.com" });
    expect(scanTargetHint("https://www.other.test", { ...verified, domains: new Set(["other.test"]) })).toEqual({ host: "www.other.test", verifiedAlternative: "other.test" });
    expect(scanTargetHint("https://WWW.Example.com/x", verified)).toBeNull();
  });
});
