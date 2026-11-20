import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { blobs, exists, download } = vi.hoisted(() => ({
  blobs: { list: [] as Array<{ name: string; properties: { contentLength?: number } }> },
  exists: vi.fn(),
  download: vi.fn(),
}));

vi.mock("@azure/storage-blob", () => ({
  BlobServiceClient: {
    fromConnectionString: () => ({
      getContainerClient: () => ({
        exists,
        listBlobsFlat: ({ prefix }: { prefix: string }) =>
          (async function* () {
            for (const b of blobs.list) if (b.name.startsWith(prefix)) yield b;
          })(),
        getBlockBlobClient: (name: string) => ({ downloadToBuffer: () => download(name) }),
      }),
    }),
  },
}));

import { loadEstateGallery, loadReportForPdf } from "./lookoutReportPdf";

type Reply = { data?: unknown; error?: { message: string } | null };
function db(replies: Record<string, Reply[]>) {
  return {
    from: (table: string) => {
      const q: Record<string, unknown> = {};
      for (const m of ["select", "eq", "lte", "order", "limit"]) q[m] = () => q;
      const next = () => Promise.resolve(replies[table]?.shift() ?? { data: null, error: null });
      q.maybeSingle = next;
      q.then = (r: (v: unknown) => void, j: (e: unknown) => void) => next().then(r, j);
      return q;
    },
  } as unknown as SupabaseClient;
}

describe("loadEstateGallery", () => {
  beforeEach(() => {
    vi.stubEnv("AZURE_STORAGE_CONNECTION_STRING", "UseDevelopmentStorage=true");
    exists.mockReset().mockResolvedValue(true);
    download.mockReset().mockImplementation(async (name: string) => Buffer.from(`jpeg:${name}`));
    blobs.list = [];
  });
  afterEach(() => vi.unstubAllEnvs());

  it("is empty without storage configured or without a scan", async () => {
    vi.stubEnv("AZURE_STORAGE_CONNECTION_STRING", "");
    expect(await loadEstateGallery(db({}), "o1", "2026-11-19")).toEqual([]);
    vi.stubEnv("AZURE_STORAGE_CONNECTION_STRING", "UseDevelopmentStorage=true");
    expect(await loadEstateGallery(db({ scans: [{ data: [] }] }), "o1", "2026-11-19")).toEqual([]);
  });

  it("uses the newest scan that has screenshots, skipping oversized and badly named files", async () => {
    blobs.list = [
      { name: "o1/s2/www.example.com.jpg", properties: { contentLength: 1000 } },
      { name: "o1/s2/huge.example.com.jpg", properties: { contentLength: 50_000_000 } },
      { name: "o1/s2/notes.txt", properties: { contentLength: 10 } },
      { name: "o1/s3/old.example.com.jpg", properties: { contentLength: 1000 } },
    ];
    const gallery = await loadEstateGallery(db({ scans: [{ data: [{ id: "s1" }, { id: "s2" }, { id: "s3" }] }] }), "o1", "2026-11-19");
    expect(gallery).toEqual([{ host: "www.example.com", dataUri: `data:image/jpeg;base64,${Buffer.from("jpeg:o1/s2/www.example.com.jpg").toString("base64")}` }]);
  });

  it("is empty when the container doesn't exist or storage fails, never an error", async () => {
    exists.mockResolvedValue(false);
    expect(await loadEstateGallery(db({ scans: [{ data: [{ id: "s1" }] }] }), "o1", "2026-11-19")).toEqual([]);
    exists.mockRejectedValue(new Error("storage down"));
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await loadEstateGallery(db({ scans: [{ data: [{ id: "s1" }] }] }), "o1", "2026-11-19")).toEqual([]);
    spy.mockRestore();
  });
});

describe("loadReportForPdf", () => {
  const report = { customer: "o1", period_start: "2026-10-20", period_end: "2026-11-19", status: "published", summary: "s", published_at: null, acknowledged_at: null };

  it("returns the report without the customer column, and its included items", async () => {
    const out = await loadReportForPdf(db({ lookout_reports: [{ data: report }], lookout_report_items: [{ data: [{ host: "a", priority: 1 }] }] }), "r1");
    expect(out?.customer).toBe("o1");
    expect(out?.report).not.toHaveProperty("customer");
    expect(out?.items).toEqual([{ host: "a", priority: 1 }]);
  });

  it("is null for no report, and throws on a read error", async () => {
    expect(await loadReportForPdf(db({ lookout_reports: [{ data: null }] }), "r1")).toBeNull();
    await expect(loadReportForPdf(db({ lookout_reports: [{ error: { message: "db down" } }] }), "r1")).rejects.toThrow("db down");
    await expect(loadReportForPdf(db({ lookout_reports: [{ data: report }], lookout_report_items: [{ error: { message: "items down" } }] }), "r1")).rejects.toThrow("items down");
  });
});
