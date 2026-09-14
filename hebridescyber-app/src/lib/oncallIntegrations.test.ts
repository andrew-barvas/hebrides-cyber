import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  validatePagerDutyKey,
  createPagerDutyIncident,
  resolvePagerDutyIncident,
  validateOpsgenieKey,
  createOpsgenieAlert,
  resolveOpsgenieAlert,
} from "./oncallIntegrations";

describe("oncallIntegrations", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("PagerDuty", () => {
    it("validatePagerDutyKey returns ok:true on successful trigger+resolve", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn()
          .mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({ dedup_key: "dk1" }) })
          .mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) })
      );
      const result = await validatePagerDutyKey("test-routing-key");
      expect(result.ok).toBe(true);
    });

    it("validatePagerDutyKey returns ok:false on non-ok response", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: false, status: 400, text: async () => "bad request" })
      );
      const result = await validatePagerDutyKey("bad-key");
      expect(result.ok).toBe(false);
      expect(result.error).toContain("400");
    });

    it("validatePagerDutyKey returns ok:false on network error", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
      const result = await validatePagerDutyKey("key");
      expect(result.ok).toBe(false);
      expect(result.error).toContain("network");
    });

    it("createPagerDutyIncident sends trigger event", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 202,
        json: async () => ({ dedup_key: "dedup-123" }),
      });
      vi.stubGlobal("fetch", mockFetch);

      const result = await createPagerDutyIncident("routing-key", {
        dedupKey: "scan-finding-1",
        summary: "Critical finding",
        severity: "critical",
        sourceUrl: "https://example.com",
        detailsUrl: "https://app.hebridescyber.co.uk/scan/123",
      });

      expect(result.ok).toBe(true);
      if (result.ok) expect(result.alertId).toBe("dedup-123");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event_action).toBe("trigger");
      expect(body.routing_key).toBe("routing-key");
      expect(body.payload.summary).toBe("Critical finding");
      expect(body.payload.severity).toBe("critical");
    });

    it("createPagerDutyIncident maps high severity to error", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ dedup_key: "dk" }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await createPagerDutyIncident("key", {
        dedupKey: "dk",
        summary: "test",
        severity: "high",
        sourceUrl: "https://example.com",
        detailsUrl: "https://example.com",
      });
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.payload.severity).toBe("error");
    });

    it("createPagerDutyIncident returns failure on error", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: false, status: 400 })
      );
      const result = await createPagerDutyIncident("key", {
        dedupKey: "dk",
        summary: "test",
        severity: "high",
        sourceUrl: "https://example.com",
        detailsUrl: "https://example.com",
      });
      expect(result.ok).toBe(false);
    });

    it("resolvePagerDutyIncident sends resolve event", async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 202 });
      vi.stubGlobal("fetch", mockFetch);

      const result = await resolvePagerDutyIncident("routing-key", "dedup-123");
      expect(result).toBe(true);
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event_action).toBe("resolve");
      expect(body.dedup_key).toBe("dedup-123");
    });

    it("resolvePagerDutyIncident returns false on failure", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
      const result = await resolvePagerDutyIncident("key", "dk");
      expect(result).toBe(false);
    });
  });

  describe("Opsgenie", () => {
    it("validateOpsgenieKey returns ok:true on successful heartbeat check", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ data: [] }) })
      );
      const result = await validateOpsgenieKey("api-key", "us");
      expect(result.ok).toBe(true);
    });

    it("validateOpsgenieKey returns ok:false on 401", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: false, status: 401 })
      );
      const result = await validateOpsgenieKey("bad-key", "us");
      expect(result.ok).toBe(false);
      expect(result.error).toContain("Invalid");
    });

    it("validateOpsgenieKey uses EU endpoint for eu region", async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ data: [] }) });
      vi.stubGlobal("fetch", mockFetch);

      await validateOpsgenieKey("key", "eu");
      expect(mockFetch.mock.calls[0][0]).toContain("api.eu.opsgenie.com");
    });

    it("createOpsgenieAlert sends alert with correct priority mapping", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ requestId: "req-123" }),
      });
      vi.stubGlobal("fetch", mockFetch);

      const result = await createOpsgenieAlert("api-key", "us", {
        alias: "scan-123-finding-456",
        message: "Critical finding",
        description: "SQL injection found",
        priority: "critical",
        sourceUrl: "https://example.com",
      });

      expect(result.ok).toBe(true);
      if (result.ok) expect(result.alertId).toBe("scan-123-finding-456");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.message).toBe("Critical finding");
      expect(body.priority).toBe("P1");
    });

    it("createOpsgenieAlert maps high to P2", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ requestId: "r" }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await createOpsgenieAlert("key", "us", {
        alias: "a",
        message: "m",
        description: "d",
        priority: "high",
        sourceUrl: "https://example.com",
      });
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.priority).toBe("P2");
    });

    it("resolveOpsgenieAlert sends close request with alias", async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
      vi.stubGlobal("fetch", mockFetch);

      const result = await resolveOpsgenieAlert("api-key", "us", "scan-123-finding-456");
      expect(result).toBe(true);
      expect(mockFetch.mock.calls[0][0]).toContain("scan-123-finding-456/close");
    });

    it("resolveOpsgenieAlert returns false on failure", async () => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
      const result = await resolveOpsgenieAlert("key", "us", "alias");
      expect(result).toBe(false);
    });
  });
});
