import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createMocks } from "node-mocks-http";
import type { NextApiRequest, NextApiResponse } from "next";

const { requireAdminMock, createIfNotExistsMock, uploadDataMock, getBlockBlobClientMock, getContainerClientMock, fromConnectionStringMock } =
  vi.hoisted(() => ({
    requireAdminMock: vi.fn(),
    createIfNotExistsMock: vi.fn(),
    uploadDataMock: vi.fn(),
    getBlockBlobClientMock: vi.fn(),
    getContainerClientMock: vi.fn(),
    fromConnectionStringMock: vi.fn(),
  }));

vi.mock("@/lib/adminAuth", () => ({ requireAdmin: requireAdminMock, supabaseAdmin: {} }));

vi.mock("@azure/storage-blob", () => ({
  BlobServiceClient: { fromConnectionString: fromConnectionStringMock },
}));

import handler from "@/pages/api/admin/blog/upload-image";

const TINY_PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

function mockReqRes(body: Record<string, unknown> = {}) {
  return createMocks<NextApiRequest, NextApiResponse>({
    method: "POST",
    headers: { authorization: "Bearer t" },
    body,
  });
}

describe("POST /api/admin/blog/upload-image", () => {
  beforeEach(() => {
    requireAdminMock.mockReset().mockResolvedValue("admin-1");
    process.env.AZURE_STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true";

    getBlockBlobClientMock.mockReset().mockReturnValue({
      uploadData: uploadDataMock.mockReset().mockResolvedValue(undefined),
      url: "https://storage.example.com/public/blog/generated-id.png",
    });
    getContainerClientMock.mockReset().mockReturnValue({
      createIfNotExists: createIfNotExistsMock.mockReset().mockResolvedValue(undefined),
      getBlockBlobClient: getBlockBlobClientMock,
    });
    fromConnectionStringMock.mockReset().mockReturnValue({ getContainerClient: getContainerClientMock });
  });

  afterEach(() => {
    delete process.env.AZURE_STORAGE_CONNECTION_STRING;
  });

  it("rejects non-POST methods with 405", async () => {
    const { req, res } = createMocks<NextApiRequest, NextApiResponse>({ method: "GET" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(405);
  });

  it("returns 403 when the caller is not an admin", async () => {
    requireAdminMock.mockResolvedValue(null);
    const { req, res } = mockReqRes({ dataUrl: `data:image/png;base64,${TINY_PNG_BASE64}`, filename: "a.png" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(403);
  });

  it("returns 503 when Azure storage isn't configured", async () => {
    delete process.env.AZURE_STORAGE_CONNECTION_STRING;
    const { req, res } = mockReqRes({ dataUrl: `data:image/png;base64,${TINY_PNG_BASE64}`, filename: "a.png" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(503);
  });

  it("returns 400 when dataUrl or filename is missing", async () => {
    const { req, res } = mockReqRes({ filename: "a.png" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("returns 400 for a malformed data URL", async () => {
    const { req, res } = mockReqRes({ dataUrl: "not-a-data-url", filename: "a.png" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects a non-image data URL", async () => {
    const { req, res } = mockReqRes({ dataUrl: "data:text/plain;base64,aGVsbG8=", filename: "a.txt" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("rejects an image over 5 MB", async () => {
    const bigBase64 = Buffer.alloc(6 * 1024 * 1024, "a").toString("base64");
    const { req, res } = mockReqRes({ dataUrl: `data:image/png;base64,${bigBase64}`, filename: "big.png" });
    await handler(req, res);
    expect(res._getStatusCode()).toBe(400);
  });

  it("uploads a valid image and returns its public URL", async () => {
    const { req, res } = mockReqRes({ dataUrl: `data:image/png;base64,${TINY_PNG_BASE64}`, filename: "photo.png" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(200);
    expect(res._getJSONData()).toEqual({ url: "https://storage.example.com/public/blog/generated-id.png" });
    expect(createIfNotExistsMock).toHaveBeenCalledWith({ access: "blob" });
    expect(uploadDataMock).toHaveBeenCalledWith(expect.any(Buffer), { blobHTTPHeaders: { blobContentType: "image/png" } });
  });

  it("returns 500 when the Azure upload throws", async () => {
    uploadDataMock.mockRejectedValue(new Error("blob storage unreachable"));
    const { req, res } = mockReqRes({ dataUrl: `data:image/png;base64,${TINY_PNG_BASE64}`, filename: "photo.png" });

    await handler(req, res);

    expect(res._getStatusCode()).toBe(500);
    expect((res._getJSONData() as { error: string }).error).toContain("blob storage unreachable");
  });
});
