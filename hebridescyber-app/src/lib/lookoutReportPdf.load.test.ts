import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";

const { blobs } = vi.hoisted(() => ({ blobs: { exists: true, list: {} as Record<string, Array<{ name: string; size: number }>>, fail: false } }));

vi.mock("@azure/storage-blob", () => ({
  BlobServiceClient: {
    fromConnectionString: () => ({
      getContainerClient: () => ({
        exists: async () => blobs.exists,
        listBlobsFlat: async function* ({ prefix }: { prefix: string }) {
          if (blobs.fail) throw new Error("storage down");
          for (const b of blobs.list[prefix] ?? []) yield { name: prefix + b.name, properties: { contentLength: b.size } };
        },
        getBlockBlobClient: (name: string) => ({ downloadToBuffer: async () => Buffer.from(`jpeg:${name}`) }),
      }),
    }),
  },
}));

import { GALLERY_MAX, loadEstateGallery, loadReportForPdf } from "./lookoutReportPdf";

function client(tables: Record<string, { data: unknown; error: unknown }>) {
  return {
    from: (t: string) => {
      const q: Record<string, unknown> = {
        select: () => q, eq: () => q, lte: () => q, order: () => q, limit: () => q,
        maybeSingle: async () => tables[t],
        then: (r: (v: unknown) => void) => r(tables[t]),
      };
      return q;
    },
  } as unknown as SupabaseClient;
}

describe("loadEstateGallery", () => {
  const scans = { data: [{ id: "s2" }, { id: "s1" }], error: null };
  beforeEach(() => {
    vi.stubEnv("AZURE_STORAGE_CONNECTION_STRING", "conn");
    blobs.exists = true;
    blobs.fail = false;
    blobs.list = {};
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("is empty without storage configured", async () => {
    vi.stubEnv("AZURE_STORAGE_CONNECTION_STRING", "");
    expect(await loadEstateGallery(client({ scans }), "c", "2026-11-20")).toEqual([]);
  });

  it("is empty with no completed scans or no container", async () => {
    expect(await loadEstateGallery(client({ scans: { data: [], error: null } }), "c", "2026-11-20")).toEqual([]);
    blobs.exists = false;
    expect(await loadEstateGallery(client({ scans }), "c", "2026-11-20")).toEqual([]);
  });

  it("takes the newest scan that has screenshots, skipping bad names and oversized files", async () => {
    blobs.list["c/s2/"] = [];
    blobs.list["c/s1/"] = [
      { name: "www.example.com.jpg", size: 1000 },
      { name: "huge.example.com.jpg", size: 999_999 },
      { name: "../escape.jpg", size: 10 },
      { name: "a.example.com.jpg", size: 10 },
    ];
    const gallery = await loadEstateGallery(client({ scans }), "c", "2026-11-20");
    expect(gallery.map((g) => g.host)).toEqual(["a.example.com", "www.example.com"]);
    expect(gallery[0].dataUri).toBe(`data:image/jpeg;base64,${Buffer.from("jpeg:c/s1/a.example.com.jpg").toString("base64")}`);
  });

  it("caps the gallery and swallows a storage failure", async () => {
    blobs.list["c/s2/"] = Array.from({ length: GALLERY_MAX + 5 }, (_, i) => ({ name: `h${String(i).padStart(2, "0")}.example.com.jpg`, size: 10 }));
    expect(await loadEstateGallery(client({ scans }), "c", "2026-11-20")).toHaveLength(GALLERY_MAX);
    blobs.fail = true;
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await loadEstateGallery(client({ scans }), "c", "2026-11-20")).toEqual([]);
    err.mockRestore();
  });
});

describe("loadReportForPdf", () => {
  const report = { customer: "c1", period_start: "2026-10-21", period_end: "2026-11-20", status: "published", summary: "s", published_at: null, acknowledged_at: null };

  it("returns the report without the customer column, and its included items", async () => {
    const out = await loadReportForPdf(client({ lookout_reports: { data: report, error: null }, lookout_report_items: { data: [{ host: "h", priority: 1 }], error: null } }), "id");
    expect(out?.customer).toBe("c1");
    expect(out?.report).not.toHaveProperty("customer");
    expect(out?.items).toEqual([{ host: "h", priority: 1 }]);
  });

  it("is null when there's no such report, and throws on read errors", async () => {
    expect(await loadReportForPdf(client({ lookout_reports: { data: null, error: null } }), "id")).toBeNull();
    await expect(loadReportForPdf(client({ lookout_reports: { data: null, error: { message: "boom" } } }), "id")).rejects.toThrow("boom");
    await expect(loadReportForPdf(client({ lookout_reports: { data: report, error: null }, lookout_report_items: { data: null, error: { message: "items" } } }), "id")).rejects.toThrow("items");
  });
});
