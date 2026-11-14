import { describe, it, expect, vi, beforeEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { authenticateApiRequestMock, state } = vi.hoisted(() => ({
  authenticateApiRequestMock: vi.fn(),
  state: { scan: { id: "scan-1", owner: "owner-1" } as { id: string; owner: string } | null, requested: [] as string[] },
}));

vi.mock("@/lib/apiAuth", () => ({
  authenticateApiRequest: authenticateApiRequestMock,
  supabaseAdmin: { from: () => ({ select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: state.scan, error: null }) }) }) }) },
}));
vi.mock("@azure/storage-blob", () => ({
  BlobServiceClient: {
    fromConnectionString: () => ({
      getContainerClient: () => ({
        getBlockBlobClient: (name: string) => {
          state.requested.push(name);
          return { exists: async () => true, downloadToBuffer: async () => Buffer.from([0xff, 0xd8]) };
        },
      }),
    }),
  },
}));

import handler from "@/pages/api/scans/[id]/screenshots/[file]";

async function get(file: string) {
  const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET", query: { id: "scan-1", file } });
  await handler(req, res);
  return res;
}

describe("GET /api/scans/[id]/screenshots/[file]", () => {
  beforeEach(() => {
    process.env.AZURE_STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true";
    authenticateApiRequestMock.mockReset().mockResolvedValue({ ownerId: "owner-1", via: "session" });
    state.scan = { id: "scan-1", owner: "owner-1" };
    state.requested = [];
  });

  it("serves the owner's image from their own folder", async () => {
    const res = await get("shop.example.com.jpg");
    expect(res._getStatusCode()).toBe(200);
    expect(res.getHeader("Content-Type")).toBe("image/jpeg");
    expect(state.requested).toEqual(["owner-1/scan-1/shop.example.com.jpg"]);
  });

  it("refuses another owner's scan and never touches storage", async () => {
    state.scan = { id: "scan-1", owner: "someone-else" };
    expect((await get("shop.example.com.jpg"))._getStatusCode()).toBe(403);
    expect(state.requested).toEqual([]);
  });

  it("rejects path tricks in the file name", async () => {
    for (const bad of ["../owner-2/scan-9/x.jpg", "x.png", "a/b.jpg"]) expect((await get(bad))._getStatusCode(), bad).toBe(400);
    expect(state.requested).toEqual([]);
  });
});
