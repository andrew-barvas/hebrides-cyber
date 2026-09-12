import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runMetadataLeakCheck } from "./metadataLeak";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function makeResponse(body: string, contentType = "application/pdf") {
  const buf = Buffer.from(body, "latin1");
  return {
    ok: true,
    headers: new Map([["content-type", contentType]]),
    arrayBuffer: () => Promise.resolve(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)),
  };
}

describe("runMetadataLeakCheck", () => {
  it("returns empty findings when no document URLs are provided", async () => {
    const result = await runMetadataLeakCheck([
      "https://example.com/page.html",
      "https://example.com/style.css",
    ]);
    expect(result).toEqual({ status: "completed", findings: [] });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("extracts email addresses from PDF metadata", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("Some text admin@internal.corp more text")
    );
    const result = await runMetadataLeakCheck(["https://example.com/doc.pdf"]);
    expect(result.status).toBe("completed");
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/doc.pdf",
      type: "email",
      value: "admin@internal.corp",
    });
  });

  it("extracts internal IP addresses", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("Server: 192.168.1.100 responded")
    );
    const result = await runMetadataLeakCheck(["https://example.com/report.docx"]);
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/report.docx",
      type: "internal-ip",
      value: "192.168.1.100",
    });
  });

  it("extracts Windows paths", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("path: C:\\Users\\jsmith\\Documents\\secret-project\\file.txt")
    );
    const result = await runMetadataLeakCheck(["https://example.com/file.xlsx"]);
    if (result.status !== "completed") return;
    expect(result.findings.some((f) => f.type === "path" && f.value.includes("jsmith"))).toBe(true);
  });

  it("extracts PDF /Author metadata", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("/Author (John Smith) /Creator (Microsoft Word)")
    );
    const result = await runMetadataLeakCheck(["https://example.com/internal.pdf"]);
    if (result.status !== "completed") return;
    expect(result.findings).toContainEqual({
      url: "https://example.com/internal.pdf",
      type: "author",
      value: "John Smith",
    });
    expect(result.findings).toContainEqual({
      url: "https://example.com/internal.pdf",
      type: "software",
      value: "Microsoft Word",
    });
  });

  it("deduplicates findings by type+value", async () => {
    fetchMock
      .mockResolvedValueOnce(makeResponse("leak@corp.com another leak@corp.com"))
      .mockResolvedValueOnce(makeResponse("leak@corp.com again"));
    const result = await runMetadataLeakCheck([
      "https://example.com/a.pdf",
      "https://example.com/b.pdf",
    ]);
    if (result.status !== "completed") return;
    const emails = result.findings.filter((f) => f.type === "email" && f.value === "leak@corp.com");
    expect(emails).toHaveLength(1);
  });

  it("skips HTML responses", async () => {
    fetchMock.mockResolvedValueOnce(
      makeResponse("admin@internal.corp", "text/html")
    );
    const result = await runMetadataLeakCheck(["https://example.com/doc.pdf"]);
    if (result.status !== "completed") return;
    expect(result.findings).toEqual([]);
  });

  it("limits to MAX_FILES_TO_CHECK", async () => {
    const urls = Array.from({ length: 25 }, (_, i) => `https://example.com/file${i}.pdf`);
    fetchMock.mockResolvedValue(makeResponse("nothing here"));
    await runMetadataLeakCheck(urls);
    expect(fetchMock).toHaveBeenCalledTimes(20);
  });
});
