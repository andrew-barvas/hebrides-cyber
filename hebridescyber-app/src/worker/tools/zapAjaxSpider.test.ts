import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runZapAjaxSpider } from "./zapAjaxSpider";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.ZAP_API_URL;
  delete process.env.ZAP_API_KEY;
});

describe("runZapAjaxSpider", () => {
  it("returns not_configured when ZAP_API_URL is not set", async () => {
    delete process.env.ZAP_API_URL;
    const result = await runZapAjaxSpider("https://example.com");
    expect(result).toEqual({ status: "not_configured" });
  });

  it("completes a scan and returns discovered URLs", async () => {
    process.env.ZAP_API_URL = "http://localhost:8090";
    process.env.ZAP_API_KEY = "testkey";

    fetchMock
      // scan action
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ scan: "1" }),
      })
      // status poll — stopped
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ status: "stopped" }),
      })
      // results
      .mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            results: [
              { url: "https://example.com/app" },
              { url: "https://example.com/api/data" },
              { url: "https://example.com/app" }, // duplicate
            ],
          }),
      });

    const result = await runZapAjaxSpider("https://example.com");
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.urls).toEqual(["https://example.com/app", "https://example.com/api/data"]);
  });

  it("polls until status is stopped", async () => {
    vi.useFakeTimers();
    process.env.ZAP_API_URL = "http://localhost:8090";

    fetchMock
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ scan: "1" }) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ status: "running" }) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ status: "stopped" }) })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ results: [] }) });

    const resultPromise = runZapAjaxSpider("https://example.com");

    // Advance past the poll interval
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.advanceTimersByTimeAsync(10_000);

    const result = await resultPromise;
    expect(result.status).toBe("completed");
    expect(fetchMock).toHaveBeenCalledTimes(4);
    vi.useRealTimers();
  });

  it("returns error when ZAP API fails", async () => {
    process.env.ZAP_API_URL = "http://localhost:8090";

    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: () => Promise.resolve({}),
    });

    const result = await runZapAjaxSpider("https://example.com");
    expect(result.status).toBe("error");
    if (result.status !== "error") return;
    expect(result.note).toContain("ZAP AJAX Spider failed");
  });
});
