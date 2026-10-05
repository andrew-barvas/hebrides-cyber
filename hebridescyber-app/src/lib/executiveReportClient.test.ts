import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchExecutiveReport } from "./executiveReportClient";

afterEach(() => vi.unstubAllGlobals());

describe("fetchExecutiveReport", () => {
  it("sends the scan id and bearer token and returns PDF bytes", async () => {
    const fetchMock = vi.fn(async () => new Response("%PDF-1.7", { status: 200, headers: { "content-type": "application/pdf" } }));
    vi.stubGlobal("fetch", fetchMock);
    const out = await fetchExecutiveReport("a b", "tok");
    expect(out.kind).toBe("pdf");
    expect(fetchMock).toHaveBeenCalledWith("/api/generate-report?scan_id=a%20b", { headers: { Authorization: "Bearer tok" } });
  });

  it("returns the download URL when storage is configured", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ url: "https://blob.test/r.pdf" })));
    expect(await fetchExecutiveReport("s", "t")).toEqual({ kind: "url", url: "https://blob.test/r.pdf" });
  });

  it("rejects a JSON answer with no link", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({})));
    await expect(fetchExecutiveReport("s", "t")).rejects.toThrow(/no download link/);
  });

  it("explains rate limits and other failures", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 429 })));
    await expect(fetchExecutiveReport("s", "t")).rejects.toThrow(/Too many report requests/);
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 500 })));
    await expect(fetchExecutiveReport("s", "t")).rejects.toThrow(/\(500\)/);
  });

  it("treats a response with no content type as PDF bytes", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 200 })));
    expect((await fetchExecutiveReport("s", "t")).kind).toBe("pdf");
  });
});
