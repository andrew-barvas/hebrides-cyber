import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { forwardToSiem, validateSiemWebhook, type SiemPayload } from "./siemIntegration";

function mockSupabase(integrations: unknown[] | null) {
  const updateChain = { eq: vi.fn().mockResolvedValue({ error: null }) };
  return {
    from: () => ({
      select: () => ({
        eq: vi.fn().mockReturnThis(),
        data: integrations,
      }),
      update: () => updateChain,
    }),
  } as unknown as import("@supabase/supabase-js").SupabaseClient;
}

describe("siemIntegration", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const basePayload: SiemPayload = {
    eventType: "scan.completed",
    timestamp: "2026-09-14T12:00:00Z",
    actorId: "user-1",
    severity: "high",
  };

  describe("validateSiemWebhook", () => {
    it("returns ok:true on successful webhook test", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true }));
      const result = await validateSiemWebhook("https://siem.example.com/events", null, "json");
      expect(result.ok).toBe(true);
    });

    it("returns ok:false on HTTP error", async () => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));
      const result = await validateSiemWebhook("https://siem.example.com/events", "Bearer bad", "json");
      expect(result.ok).toBe(false);
      expect(result.error).toContain("401");
    });

    it("returns ok:false on network error", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
      const result = await validateSiemWebhook("https://siem.example.com/events", null, "json");
      expect(result.ok).toBe(false);
      expect(result.error).toContain("timeout");
    });

    it("sends CEF format when configured", async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", mockFetch);
      await validateSiemWebhook("https://siem.example.com/events", null, "cef");
      expect(mockFetch.mock.calls[0][1].headers["Content-Type"]).toBe("text/plain");
      expect(mockFetch.mock.calls[0][1].body).toContain("CEF:0");
    });

    it("sends LEEF format when configured", async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", mockFetch);
      await validateSiemWebhook("https://siem.example.com/events", null, "leef");
      expect(mockFetch.mock.calls[0][1].body).toContain("LEEF:2.0");
    });
  });

  describe("forwardToSiem", () => {
    it("does nothing when no integrations exist", async () => {
      const supabase = mockSupabase([]);
      const mockFetch = vi.fn();
      vi.stubGlobal("fetch", mockFetch);
      await forwardToSiem(supabase, "owner-1", basePayload);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("does nothing when no integrations match event type", async () => {
      const supabase = mockSupabase([
        { id: "int-1", type: "webhook", endpoint: "https://siem.example.com", auth_header: null, format: "json", event_types: ["finding.new"] },
      ]);
      const mockFetch = vi.fn();
      vi.stubGlobal("fetch", mockFetch);
      await forwardToSiem(supabase, "owner-1", basePayload);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});
