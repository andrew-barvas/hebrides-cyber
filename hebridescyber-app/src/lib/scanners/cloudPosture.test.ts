import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runCloudPostureChecks } from "./cloudPosture";

function mockSupabase(creds: Array<{ provider: string; credentials_encrypted: Record<string, string> }> | null) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({ data: creds }),
      }),
    }),
  } as unknown as import("@supabase/supabase-js").SupabaseClient;
}

describe("runCloudPostureChecks", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns not_configured when no credentials exist", async () => {
    const result = await runCloudPostureChecks(mockSupabase([]), "owner-1");
    expect(result.status).toBe("not_configured");
  });

  it("returns not_configured when query returns null", async () => {
    const result = await runCloudPostureChecks(mockSupabase(null), "owner-1");
    expect(result.status).toBe("not_configured");
  });

  it("returns checked with empty findings for aws stub", async () => {
    const supabase = mockSupabase([
      { provider: "aws", credentials_encrypted: { accessKeyId: "AKID", secretAccessKey: "secret" } },
    ]);
    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toEqual([]);
      expect(result.provider).toBe("aws");
    }
  });

  it("returns findings for azure storage with public blob access", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: "test-token" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [
            { name: "publicaccount", properties: { allowBlobPublicAccess: true } },
            { name: "privateaccount", properties: { allowBlobPublicAccess: false } },
          ],
        }),
      });
    vi.stubGlobal("fetch", mockFetch);

    const supabase = mockSupabase([
      {
        provider: "azure",
        credentials_encrypted: {
          tenantId: "t1",
          clientId: "c1",
          clientSecret: "s1",
          subscriptionId: "sub1",
        },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].title).toContain("publicaccount");
      expect(result.findings[0].severity).toBe("high");
    }
  });

  it("handles azure token failure gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 401 })
    );

    const supabase = mockSupabase([
      {
        provider: "azure",
        credentials_encrypted: {
          tenantId: "t1",
          clientId: "c1",
          clientSecret: "bad",
          subscriptionId: "sub1",
        },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toEqual([]);
    }
  });

  it("handles multiple providers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 401 })
    );

    const supabase = mockSupabase([
      { provider: "aws", credentials_encrypted: { accessKeyId: "AKID", secretAccessKey: "secret" } },
      {
        provider: "azure",
        credentials_encrypted: { tenantId: "t1", clientId: "c1", clientSecret: "s1", subscriptionId: "sub1" },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.provider).toBe("aws,azure");
    }
  });

  it("returns error on supabase query crash", async () => {
    const supabase = {
      from: () => { throw new Error("db down"); },
    } as unknown as import("@supabase/supabase-js").SupabaseClient;

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("error");
    if (result.status === "error") {
      expect(result.note).toContain("db down");
    }
  });
});
